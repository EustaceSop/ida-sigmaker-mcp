#!/usr/bin/env python3
"""IDA SigMaker MCP - hardened bridge with per-request timeouts.

This MCP server bridges LLM tool calls to the sigmaker plugin running inside
IDA. It is intentionally paranoid about hangs because a single stuck request
would previously wedge every subsequent invocation:

  * every embedded Python snippet forces `noninteractive=True` + a positive
    `time_budget_seconds`, so the plugin never blocks on `ask_yn` and always
    honors a wall-clock deadline
  * every RPC read is bounded via a worker-thread + Queue timeout; on expiry
    the IDA-side subprocess is killed and the pool re-created so a single
    hung request cannot poison the pool
  * every embedded snippet is wrapped in `try/finally` so partial state is
    always torn down before returning to the caller

Environment knobs (all optional):
    IDA_RPC_URL            HTTP endpoint of the ida_pro_mcp RPC server
    SIGMAKER_PATH          Directory containing sigmaker.py (for sys.path insert)
    SIGMAKER_TIME_BUDGET   Default wall-clock budget passed to sigmaker (seconds)
    SIGMAKER_RPC_TIMEOUT   Hard timeout for a single IDA RPC round-trip
    SIGMAKER_MAX_LENGTH    Absolute cap on max_length regardless of param
"""

import json
import os
import queue
import subprocess
import sys
import threading

IDA_RPC_URL = os.getenv("IDA_RPC_URL", "http://127.0.0.1:13337")
SIGMAKER_PATH = os.getenv("SIGMAKER_PATH", r"D:\ida-sigmaker-mcp")

# Wall-clock budget passed into the sigmaker plugin. This is a soft, in-plugin
# deadline that lets the hot loop bail out cleanly instead of running forever.
DEFAULT_TIME_BUDGET = float(os.getenv("SIGMAKER_TIME_BUDGET", "15.0"))
# Hard timeout on the RPC round-trip. Kept larger than DEFAULT_TIME_BUDGET so
# the plugin can finish its own cleanup before we tear down the subprocess.
DEFAULT_RPC_TIMEOUT = float(os.getenv("SIGMAKER_RPC_TIMEOUT", "60.0"))
# Absolute cap on max_length. Even a caller-supplied 500 would make each
# is_unique() scan very expensive on a large binary.
MAX_LENGTH_CAP = int(os.getenv("SIGMAKER_MAX_LENGTH", "256"))

# Persistent IDA subprocess. Guarded by _ida_lock so requests are serialized
# (the underlying py_eval endpoint is single-threaded on IDA's main thread).
_ida_process: "subprocess.Popen | None" = None
_ida_lock = threading.Lock()
_request_id = 0


class MCPServer:
    def __init__(self, name, version):
        self.name, self.version, self.tools = name, version, {}

    def tool(self, name, description, parameters):
        def decorator(func):
            self.tools[name] = {
                "description": description,
                "parameters": parameters,
                "handler": func,
            }
            return func

        return decorator

    def handle_request(self, request):
        method, req_id = request.get("method"), request.get("id")
        if method == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "serverInfo": {"name": self.name, "version": self.version},
                    "capabilities": {"tools": {}},
                },
            }
        elif method == "tools/list":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "tools": [
                        {
                            "name": n,
                            "description": i["description"],
                            "inputSchema": {
                                "type": "object",
                                "properties": i["parameters"],
                            },
                        }
                        for n, i in self.tools.items()
                    ]
                },
            }
        elif method == "tools/call":
            tool_name = request["params"]["name"]
            args = request["params"].get("arguments", {})
            if tool_name not in self.tools:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32602, "message": f"Unknown tool: {tool_name}"},
                }
            # Handler exceptions must never propagate up to the JSON-RPC loop
            # or the whole MCP server would die on a single bad request.
            try:
                result = self.tools[tool_name]["handler"](**args)
            except Exception as exc:
                result = json.dumps({"error": f"handler crashed: {exc}"})
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"content": [{"type": "text", "text": str(result)}]},
            }
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": -32601, "message": "Method not found"},
        }

    def start(self):
        for line in sys.stdin:
            try:
                request = json.loads(line)
                response = self.handle_request(request)
                print(json.dumps(response), flush=True)
            except Exception as e:
                print(
                    json.dumps(
                        {"jsonrpc": "2.0", "error": {"code": -32603, "message": str(e)}}
                    ),
                    flush=True,
                )


def _spawn_ida_process():
    cmd = [
        sys.executable,
        r"C:\Users\GayBottle\AppData\Local\Programs\Python\Python311\Lib\site-packages\ida_pro_mcp\server.py",
        "--ida-rpc",
        IDA_RPC_URL,
    ]
    return subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,  # line-buffered so readline() returns promptly
    )


def get_ida_process():
    global _ida_process
    if _ida_process is None or _ida_process.poll() is not None:
        _ida_process = _spawn_ida_process()
    return _ida_process


def _kill_ida_process():
    """Tear down the current subprocess. Used after a timeout so the next
    request gets a fresh pool instead of trying to interleave with a hung one.
    """
    global _ida_process
    if _ida_process is None:
        return
    try:
        _ida_process.kill()
    except Exception:
        pass
    try:
        _ida_process.wait(timeout=2)
    except Exception:
        pass
    _ida_process = None


def call_ida_rpc(code, timeout=None):
    """Send Python code to the IDA plugin, return the eval result.

    Timeouts are enforced via a reader thread. If the plugin does not respond
    within `timeout` seconds we kill the entire subprocess pool — otherwise
    a delayed stale response would be dequeued by the next unrelated request
    and cause a response/request-id mismatch.
    """
    global _request_id
    if timeout is None:
        timeout = DEFAULT_RPC_TIMEOUT

    with _ida_lock:
        _request_id += 1
        req_id = _request_id
        proc = get_ida_process()
        payload = {
            "jsonrpc": "2.0",
            "id": req_id,
            "method": "tools/call",
            "params": {"name": "py_eval", "arguments": {"code": code}},
        }
        try:
            proc.stdin.write(json.dumps(payload) + "\n")
            proc.stdin.flush()
        except Exception as exc:
            _kill_ida_process()
            raise Exception(f"Failed to send request to IDA RPC: {exc}")

        # Read the response line with a wall-clock timeout via a worker thread.
        # We do NOT set a stdout deadline directly because Popen streams are
        # blocking on Windows; the thread + Queue pattern is the standard fix.
        result_q: queue.Queue = queue.Queue(maxsize=1)

        def _reader():
            try:
                line = proc.stdout.readline()
                result_q.put(("ok", line))
            except Exception as exc:
                result_q.put(("err", str(exc)))

        reader = threading.Thread(target=_reader, daemon=True)
        reader.start()

        try:
            status, data = result_q.get(timeout=timeout)
        except queue.Empty:
            # Timed out. Kill the whole subprocess — any late response is now
            # garbage relative to future requests, and we want a clean pool.
            _kill_ida_process()
            raise Exception(
                f"IDA RPC timed out after {timeout:.1f}s (request id={req_id})"
            )

        if status == "err":
            _kill_ida_process()
            raise Exception(f"IDA RPC read error: {data}")

        line = data
        if not line:
            _kill_ida_process()
            raise Exception("No response from IDA (EOF)")

        try:
            result = json.loads(line)
        except Exception:
            raise Exception(f"Malformed response from IDA: {line[:200]!r}")

        if "error" in result:
            raise Exception(str(result["error"]))

        # Prefer structuredContent.result
        structured = result.get("result", {}).get("structuredContent", {})
        if structured and "result" in structured:
            result_str = structured["result"]
            try:
                return json.loads(result_str) if result_str else ""
            except Exception:
                return result_str

        content = result.get("result", {}).get("content", [])
        if content and len(content) > 0:
            return content[0].get("text", "")
        return ""


# Common preamble injected into every embedded snippet. Kept as a single
# constant so all tool handlers share the same import + config assumptions.
SIGMAKER_INIT = f"""
import sys
if r'{SIGMAKER_PATH}' not in sys.path:
    sys.path.insert(0, r'{SIGMAKER_PATH}')
from sigmaker import (
    SignatureMaker,
    SigMakerConfig,
    XrefFinder,
    SignatureType,
    invalidate_buffer_cache,
)
"""


def _clamp_max_length(v) -> int:
    """Enforce the module-wide cap so callers can't ask us to scan forever."""
    try:
        v = int(v)
    except Exception:
        v = 100
    if v <= 0:
        v = 100
    return min(v, MAX_LENGTH_CAP)


def _clamp_budget(v) -> float:
    try:
        v = float(v)
    except Exception:
        v = DEFAULT_TIME_BUDGET
    if v <= 0:
        v = DEFAULT_TIME_BUDGET
    # Guard against callers passing an absurd budget that would out-live the
    # RPC-side timeout. Keep budget < RPC timeout by a small margin so the
    # plugin can finish its cleanup + response marshalling.
    return min(v, max(1.0, DEFAULT_RPC_TIMEOUT - 5.0))


server = MCPServer("ida-sigmaker", "1.0.0")


@server.tool(
    "generate_signature",
    "Generate unique signature using original sigmaker",
    {
        "address": {"type": "string"},
        "format": {
            "type": "string",
            "description": "ida/x64dbg/mask/bitmask",
            "default": "ida",
        },
        "max_length": {"type": "integer", "default": 100},
    },
)
def generate_signature(address, format="ida", max_length=100):
    try:
        fmt = format.lower()
        if fmt not in ["ida", "x64dbg", "mask", "bitmask"]:
            return json.dumps(
                {"error": f"Invalid format: {format}. Use ida/x64dbg/mask/bitmask"}
            )
        addr = int(address, 16) if isinstance(address, str) else address
        max_length = _clamp_max_length(max_length)
        budget = _clamp_budget(DEFAULT_TIME_BUDGET)
        code = f"""
{SIGMAKER_INIT}
import idc, json
addr = {addr}
result = None
try:
    if not idc.is_code(idc.get_full_flags(addr)):
        result = {{'error': 'Address is not code', 'address': hex(addr), 'suggestion': 'Use address in code section'}}
    else:
        cfg = SigMakerConfig(
            output_format=SignatureType.IDA,
            wildcard_operands=True,
            continue_outside_of_function=True,
            wildcard_optimized=True,
            enable_continue_prompt=False,
            ask_longer_signature=False,
            noninteractive=True,
            time_budget_seconds={budget},
            max_single_signature_length={max_length},
        )
        maker = SignatureMaker()
        try:
            gen_sig = maker.make_signature(addr, cfg)
            sig_str = format(gen_sig.signature, '{fmt}')
            result = {{'address': hex(addr), 'signature': sig_str, 'format': '{fmt}', 'length': len(gen_sig.signature), 'unique': True, 'source': 'original sigmaker'}}
        except Exception as e:
            result = {{'error': str(e), 'address': hex(addr)}}
finally:
    # Best-effort cleanup: ensure no lingering wait-box if the plugin threw
    # somewhere weird (e.g. Qt widget teardown mid-call).
    try:
        import idaapi as _iaa
        _iaa.hide_wait_box()
    except Exception:
        pass
json.dumps(result)
"""
        return call_ida_rpc(code)
    except Exception as e:
        return json.dumps({"error": str(e)})


@server.tool(
    "generate_xref_signatures",
    "Generate XREF signatures",
    {
        "address": {"type": "string"},
        "format": {"type": "string", "default": "ida"},
        "top_n": {"type": "integer", "default": 5},
        "max_length": {"type": "integer", "default": 100},
    },
)
def generate_xref_signatures(address, format="ida", top_n=5, max_length=100):
    try:
        fmt = format.lower()
        if fmt not in ["ida", "x64dbg", "mask", "bitmask"]:
            return json.dumps({"error": f"Invalid format: {format}"})
        addr = int(address, 16) if isinstance(address, str) else address
        max_length = _clamp_max_length(max_length)
        try:
            top_n = int(top_n)
        except Exception:
            top_n = 5
        top_n = max(1, min(top_n, 50))
        budget = _clamp_budget(DEFAULT_TIME_BUDGET)
        code = f"""
{SIGMAKER_INIT}
import json
addr = {addr}
result = None
try:
    cfg = SigMakerConfig(
        output_format=SignatureType.IDA,
        wildcard_operands=True,
        continue_outside_of_function=True,
        wildcard_optimized=True,
        enable_continue_prompt=False,
        ask_longer_signature=False,
        noninteractive=True,
        time_budget_seconds={budget},
        max_single_signature_length={max_length},
        max_xref_signature_length={max_length},
    )
    finder = XrefFinder()
    try:
        xref_result = finder.find_xrefs(addr, cfg)
        results = []
        for gen_sig in xref_result.signatures[:{top_n}]:
            sig_str = format(gen_sig.signature, '{fmt}')
            caller_addr = hex(gen_sig.match.address) if gen_sig.match else 'unknown'
            results.append({{'signature': sig_str, 'caller': caller_addr, 'length': len(gen_sig.signature)}})
        result = {{'target': hex(addr), 'format': '{fmt}', 'xref_count': len(xref_result.signatures), 'xref_signatures': results, 'source': 'original sigmaker'}}
    except Exception as e:
        result = {{'error': str(e), 'target': hex(addr)}}
finally:
    try:
        import idaapi as _iaa
        _iaa.hide_wait_box()
    except Exception:
        pass
json.dumps(result)
"""
        return call_ida_rpc(code)
    except Exception as e:
        return json.dumps({"error": str(e)})


@server.tool(
    "search_signature",
    "Search for signature pattern",
    {"pattern": {"type": "string"}, "limit": {"type": "integer", "default": 100}},
)
def search_signature(pattern, limit=100):
    try:
        try:
            limit = int(limit)
        except Exception:
            limit = 100
        limit = max(1, min(limit, 10000))
        # Escape single quotes so we can embed the pattern safely
        pattern_escaped = pattern.replace("\\", "\\\\").replace("'", "\\'")
        code = f"""
import ida_bytes, ida_search, ida_idaapi, idaapi, json
# IDA pattern: space-separated hex, ?? for wildcard
pattern_str = '{pattern_escaped}'.replace(' ', '')
results = []
try:
    ea = ida_bytes.get_imagebase()
    for _ in range({limit}):
        ea = ida_search.find_binary(ea, ida_idaapi.BADADDR, pattern_str, 16, ida_search.SEARCH_DOWN)
        if ea == ida_idaapi.BADADDR:
            break
        results.append(hex(ea))
        ea += 1
finally:
    try:
        idaapi.hide_wait_box()
    except Exception:
        pass
json.dumps({{'pattern': '{pattern_escaped}', 'matches': len(results), 'addresses': results}})
"""
        return call_ida_rpc(code)
    except Exception as e:
        return json.dumps({"error": str(e)})


@server.tool(
    "batch_generate_signatures",
    "Generate signatures for multiple addresses",
    {
        "addresses": {"type": "array", "items": {"type": "string"}},
        "format": {"type": "string", "default": "ida"},
        "max_length": {"type": "integer", "default": 100},
    },
)
def batch_generate_signatures(addresses, format="ida", max_length=100):
    try:
        fmt = format.lower()
        if fmt not in ["ida", "x64dbg", "mask", "bitmask"]:
            return json.dumps({"error": f"Invalid format: {format}"})
        addrs = [int(a, 16) if isinstance(a, str) else a for a in addresses]
        max_length = _clamp_max_length(max_length)
        # Total batch budget = per-address budget × number of addresses, capped
        # so a huge batch cannot occupy the RPC pipe forever. RPC timeout is
        # then scaled to be strictly larger than the plugin budget so the
        # plugin can send its response before the client gives up.
        per_addr_budget = _clamp_budget(DEFAULT_TIME_BUDGET)
        # Hard ceiling on batch runtime — 5 min protects against pathological
        # inputs. Callers can raise via SIGMAKER_BATCH_MAX env if needed.
        batch_ceiling = float(os.getenv("SIGMAKER_BATCH_MAX", "300.0"))
        total_budget = min(per_addr_budget * max(1, len(addrs)), batch_ceiling)
        code = f"""
{SIGMAKER_INIT}
import json, time
addrs = {addrs}
deadline = time.time() + {total_budget}
per_addr_budget = {per_addr_budget}
maker = SignatureMaker()
results = []
try:
    for addr in addrs:
        # Global deadline check — bail out early with best-effort partial
        # results rather than block the caller until the RPC timeout.
        remaining = deadline - time.time()
        if remaining <= 0:
            results.append({{'address': hex(addr), 'error': 'batch time budget exhausted', 'success': False}})
            continue
        this_budget = min(per_addr_budget, max(1.0, remaining))
        cfg = SigMakerConfig(
            output_format=SignatureType.IDA,
            wildcard_operands=True,
            continue_outside_of_function=True,
            wildcard_optimized=True,
            enable_continue_prompt=False,
            ask_longer_signature=False,
            noninteractive=True,
            time_budget_seconds=this_budget,
            max_single_signature_length={max_length},
        )
        try:
            gen_sig = maker.make_signature(addr, cfg)
            sig_str = format(gen_sig.signature, '{fmt}')
            results.append({{'address': hex(addr), 'signature': sig_str, 'length': len(gen_sig.signature), 'success': True}})
        except Exception as e:
            results.append({{'address': hex(addr), 'error': str(e), 'success': False}})
finally:
    try:
        import idaapi as _iaa
        _iaa.hide_wait_box()
    except Exception:
        pass
json.dumps({{'format': '{fmt}', 'total': len(addrs), 'results': results}})
"""
        # Give the RPC layer extra headroom over the plugin's own budget.
        rpc_timeout = max(DEFAULT_RPC_TIMEOUT, total_budget + 10.0)
        return call_ida_rpc(code, timeout=rpc_timeout)
    except Exception as e:
        return json.dumps({"error": str(e)})


@server.tool(
    "verify_signature_unique",
    "Verify if signature is unique",
    {"signature": {"type": "string"}, "expected_address": {"type": "string"}},
)
def verify_signature_unique(signature, expected_address):
    try:
        addr = (
            int(expected_address, 16)
            if isinstance(expected_address, str)
            else expected_address
        )
        sig_escaped = signature.replace("\\", "\\\\").replace("'", "\\'")
        code = f"""
import ida_bytes, ida_search, ida_idaapi, idaapi, json
pattern_str = '{sig_escaped}'.replace(' ', '')
matches = []
try:
    ea = ida_bytes.get_imagebase()
    for _ in range(100):
        ea = ida_search.find_binary(ea, ida_idaapi.BADADDR, pattern_str, 16, ida_search.SEARCH_DOWN)
        if ea == ida_idaapi.BADADDR:
            break
        matches.append(hex(ea))
        ea += 1
finally:
    try:
        idaapi.hide_wait_box()
    except Exception:
        pass
expected = hex({addr})
unique = len(matches) == 1
correct = expected in matches if matches else False
json.dumps({{'signature': '{sig_escaped}', 'expected': expected, 'matches': len(matches), 'addresses': matches, 'unique': unique, 'correct': correct}})
"""
        return call_ida_rpc(code)
    except Exception as e:
        return json.dumps({"error": str(e)})


if __name__ == "__main__":
    server.start()
