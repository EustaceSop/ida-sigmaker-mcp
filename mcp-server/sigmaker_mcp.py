#!/usr/bin/env python3
"""IDA SigMaker MCP - Fixed version with persistent IDA connection"""

import json, sys, subprocess, os, threading, queue

IDA_RPC_URL = os.getenv("IDA_RPC_URL", "http://127.0.0.1:13337")
SIGMAKER_PATH = os.getenv("SIGMAKER_PATH", r"D:\ida-sigmaker-mcp")

# 全局 IDA 進程
_ida_process = None
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
            result = self.tools[tool_name]["handler"](**args)
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


def get_ida_process():
    global _ida_process
    if _ida_process is None or _ida_process.poll() is not None:
        cmd = [
            sys.executable,
            r"C:\Users\GayBottle\AppData\Local\Programs\Python\Python311\Lib\site-packages\ida_pro_mcp\server.py",
            "--ida-rpc",
            IDA_RPC_URL,
        ]
        _ida_process = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    return _ida_process


def call_ida_rpc(code):
    global _request_id
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
        proc.stdin.write(json.dumps(payload) + "\n")
        proc.stdin.flush()

        # 讀取響應
        line = proc.stdout.readline()
        if not line:
            raise Exception("No response from IDA")
        result = json.loads(line)
        if "error" in result:
            raise Exception(str(result["error"]))

        # 優先使用 structuredContent.result
        structured = result.get("result", {}).get("structuredContent", {})
        if structured and "result" in structured:
            result_str = structured["result"]
            # 如果是 JSON 字符串，解析它
            try:
                return json.loads(result_str) if result_str else ""
            except:
                return result_str

        # 否則使用 content
        content = result.get("result", {}).get("content", [])
        if content and len(content) > 0:
            return content[0].get("text", "")
        return ""


SIGMAKER_INIT = f"""
import sys
if r'{SIGMAKER_PATH}' not in sys.path:
    sys.path.insert(0, r'{SIGMAKER_PATH}')
from sigmaker import SignatureMaker, SigMakerConfig, XrefFinder, SignatureType
"""

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
        if format.lower() not in ["ida", "x64dbg", "mask", "bitmask"]:
            return json.dumps(
                {"error": f"Invalid format: {format}. Use ida/x64dbg/mask/bitmask"}
            )
        addr = int(address, 16) if isinstance(address, str) else address
        code = f"""
{SIGMAKER_INIT}
import idc, json
addr = {addr}
if not idc.is_code(idc.get_full_flags(addr)):
    result = {{'error': 'Address is not code', 'address': hex(addr), 'suggestion': 'Use address in code section'}}
else:
    cfg = SigMakerConfig(
        output_format=SignatureType.IDA,
        wildcard_operands=True,
        continue_outside_of_function=True,
        wildcard_optimized=True,
        max_single_signature_length={max_length}
    )
    maker = SignatureMaker()
    try:
        gen_sig = maker.make_signature(addr, cfg)
        sig_str = format(gen_sig.signature, '{format.lower()}')
        result = {{'address': hex(addr), 'signature': sig_str, 'format': '{format}', 'length': len(gen_sig.signature), 'unique': True, 'source': 'original sigmaker'}}
    except Exception as e:
        result = {{'error': str(e), 'address': hex(addr)}}
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
        if format.lower() not in ["ida", "x64dbg", "mask", "bitmask"]:
            return json.dumps({"error": f"Invalid format: {format}"})
        addr = int(address, 16) if isinstance(address, str) else address
        code = f"""
{SIGMAKER_INIT}
import json
addr = {addr}
cfg = SigMakerConfig(
    output_format=SignatureType.IDA,
    wildcard_operands=True,
    continue_outside_of_function=True,
    wildcard_optimized=True,
    max_single_signature_length={max_length},
    max_xref_signature_length={max_length}
)
finder = XrefFinder()
try:
    xref_result = finder.find_xrefs(addr, cfg)
    results = []
    for gen_sig in xref_result.signatures[:{top_n}]:
        sig_str = format(gen_sig.signature, '{format.lower()}')
        caller_addr = hex(gen_sig.match.address) if gen_sig.match else 'unknown'
        results.append({{'signature': sig_str, 'caller': caller_addr, 'length': len(gen_sig.signature)}})
    result = {{'target': hex(addr), 'format': '{format}', 'xref_count': len(xref_result.signatures), 'xref_signatures': results, 'source': 'original sigmaker'}}
except Exception as e:
    result = {{'error': str(e), 'target': hex(addr)}}
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
        code = f"""
import ida_bytes, ida_search, ida_idaapi, json
# IDA pattern: space-separated hex, ?? for wildcard
pattern_str = '{pattern}'.replace(' ', '')
results = []
ea = ida_bytes.get_imagebase()
for _ in range({limit}):
    ea = ida_search.find_binary(ea, ida_idaapi.BADADDR, pattern_str, 16, ida_search.SEARCH_DOWN)
    if ea == ida_idaapi.BADADDR:
        break
    results.append(hex(ea))
    ea += 1
json.dumps({{'pattern': '{pattern}', 'matches': len(results), 'addresses': results}})
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
        if format.lower() not in ["ida", "x64dbg", "mask", "bitmask"]:
            return json.dumps({"error": f"Invalid format: {format}"})
        addrs = [int(a, 16) if isinstance(a, str) else a for a in addresses]
        code = f"""
{SIGMAKER_INIT}
import json
import json
addrs = {addrs}
cfg = SigMakerConfig(
    output_format=SignatureType.IDA,
    wildcard_operands=True,
    continue_outside_of_function=True,
    wildcard_optimized=True,
    max_single_signature_length={max_length}
)
maker = SignatureMaker()
results = []
for addr in addrs:
    try:
        gen_sig = maker.make_signature(addr, cfg)
        sig_str = format(gen_sig.signature, '{format.lower()}')
        results.append({{'address': hex(addr), 'signature': sig_str, 'length': len(gen_sig.signature), 'success': True}})
    except Exception as e:
        results.append({{'address': hex(addr), 'error': str(e), 'success': False}})
json.dumps({{'format': '{format}', 'total': len(addrs), 'results': results}})
"""
        return call_ida_rpc(code)
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
        code = f"""
import ida_bytes, ida_search, ida_idaapi, json
pattern_str = '{signature}'.replace(' ', '')
matches = []
ea = ida_bytes.get_imagebase()
for _ in range(100):
    ea = ida_search.find_binary(ea, ida_idaapi.BADADDR, pattern_str, 16, ida_search.SEARCH_DOWN)
    if ea == ida_idaapi.BADADDR:
        break
    matches.append(hex(ea))
    ea += 1
expected = hex({addr})
unique = len(matches) == 1
correct = expected in matches if matches else False
json.dumps({{'signature': '{signature}', 'expected': expected, 'matches': len(matches), 'addresses': matches, 'unique': unique, 'correct': correct}})
"""
        return call_ida_rpc(code)
    except Exception as e:
        return json.dumps({"error": str(e)})


if __name__ == "__main__":
    server.start()
