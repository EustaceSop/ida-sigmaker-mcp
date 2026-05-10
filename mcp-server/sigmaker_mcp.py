#!/usr/bin/env python3
"""
IDA SigMaker MCP Server
Exposes IDA signature generation via RPC to LLM agents
"""

import json
import sys
import requests
from typing import Any, Dict, Callable

IDA_RPC_URL = "http://127.0.0.1:13337"


class MCPServer:
    def __init__(self, name: str, version: str):
        self.name = name
        self.version = version
        self.tools: Dict[str, Dict[str, Any]] = {}

    def tool(self, name: str, description: str, parameters: dict):
        def decorator(func: Callable):
            self.tools[name] = {
                "description": description,
                "parameters": parameters,
                "handler": func,
            }
            return func

        return decorator

    def handle_request(self, request: dict) -> dict:
        method = request.get("method")

        if method == "initialize":
            return {
                "protocolVersion": "2024-11-05",
                "serverInfo": {"name": self.name, "version": self.version},
                "capabilities": {"tools": {}},
            }

        elif method == "tools/list":
            return {
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
            }

        elif method == "tools/call":
            tool_name = request["params"]["name"]
            args = request["params"].get("arguments", {})
            if tool_name not in self.tools:
                raise ValueError(f"Unknown tool: {tool_name}")
            result = self.tools[tool_name]["handler"](**args)
            return {"content": [{"type": "text", "text": str(result)}]}

        return {"error": "Unknown method"}

    def start(self):
        for line in sys.stdin:
            try:
                request = json.loads(line)
                response = self.handle_request(request)
                print(json.dumps(response), flush=True)
            except Exception as e:
                print(json.dumps({"error": str(e)}), flush=True)


def ida_rpc(code: str) -> Any:
    """Execute Python code in IDA via RPC"""
    try:
        resp = requests.post(f"{IDA_RPC_URL}/execute", json={"code": code}, timeout=30)
        result = resp.json()
        if "error" in result:
            raise Exception(result["error"])
        return result.get("result")
    except Exception as e:
        raise Exception(f"IDA RPC error: {str(e)}")


server = MCPServer("ida-sigmaker", "1.0.0")


@server.tool(
    "generate_signature",
    "Generate unique binary signature at address",
    {
        "address": {
            "type": "string",
            "description": "Hex address (e.g., '0x140001000')",
        },
        "format": {
            "type": "string",
            "description": "ida/x64dbg/c_array/raw_bytes",
            "default": "ida",
        },
        "wildcard_operands": {"type": "boolean", "default": True},
        "max_length": {"type": "integer", "default": 100},
    },
)
def generate_signature(
    address: str,
    format: str = "ida",
    wildcard_operands: bool = True,
    max_length: int = 100,
) -> str:
    code = f"""
import idaapi, idc, sys
sys.path.append(r'D:\\ida-sigmaker-mcp')
from sigmaker import SigMaker, SigMakerConfig, SignatureType

ea = {int(address, 16) if isinstance(address, str) and address.startswith("0x") else address}
fmt_map = {{'ida': SignatureType.IDA, 'x64dbg': SignatureType.X64DBG, 'c_array': SignatureType.C_ARRAY, 'raw_bytes': SignatureType.RAW_BYTES}}
cfg = SigMakerConfig(output_format=fmt_map.get('{format}', SignatureType.IDA), wildcard_operands={wildcard_operands}, continue_outside_of_function=True, wildcard_optimized=True, max_single_signature_length={max_length})
sig = SigMaker.make_sig(ea, cfg)
formatted = format(sig.signature, cfg.output_format.value)
result = {{'address': hex(ea), 'signature': formatted, 'length': len(sig.signature), 'format': '{format}'}}
result
"""
    try:
        result = ida_rpc(code)
        return json.dumps(result)
    except Exception as e:
        return json.dumps({"error": str(e)})


@server.tool(
    "generate_xref_signatures",
    "Generate signatures for all XREFs to address",
    {
        "address": {"type": "string"},
        "format": {"type": "string", "default": "ida"},
        "top_n": {"type": "integer", "default": 5},
        "max_length": {"type": "integer", "default": 250},
    },
)
def generate_xref_signatures(
    address: str, format: str = "ida", top_n: int = 5, max_length: int = 250
) -> str:
    code = f"""
import idaapi, sys
sys.path.append(r'D:\\ida-sigmaker-mcp')
from sigmaker import SigMaker, SigMakerConfig, SignatureType

ea = {int(address, 16) if isinstance(address, str) and address.startswith("0x") else address}
fmt_map = {{'ida': SignatureType.IDA, 'x64dbg': SignatureType.X64DBG, 'c_array': SignatureType.C_ARRAY, 'raw_bytes': SignatureType.RAW_BYTES}}
cfg = SigMakerConfig(output_format=fmt_map.get('{format}', SignatureType.IDA), wildcard_operands=True, continue_outside_of_function=True, wildcard_optimized=True, print_top_x={top_n}, max_xref_signature_length={max_length})
xref_sigs = SigMaker.make_sig_xrefs(ea, cfg)
results = [{{'address': hex(sig.address), 'signature': format(sig.signature, cfg.output_format.value), 'length': len(sig.signature)}} for sig in xref_sigs.signatures[:{top_n}]]
{{'target_address': hex(ea), 'xref_count': len(xref_sigs.signatures), 'top_signatures': results}}
"""
    try:
        result = ida_rpc(code)
        return json.dumps(result)
    except Exception as e:
        return json.dumps({"error": str(e)})


@server.tool(
    "search_signature",
    "Search for signature pattern in binary",
    {"pattern": {"type": "string"}, "limit": {"type": "integer", "default": 100}},
)
def search_signature(pattern: str, limit: int = 100) -> str:
    code = f"""
import idaapi, sys
sys.path.append(r'D:\\ida-sigmaker-mcp')
from sigmaker import SigMaker, InMemoryBuffer

buf = InMemoryBuffer.load()
matches = SigMaker.search_sig('{pattern}', buf, limit={limit})
results = [{{'address': hex(addr), 'function': idaapi.get_func_name(addr) or 'N/A'}} for addr in matches]
{{'pattern': '{pattern}', 'match_count': len(results), 'matches': results}}
"""
    try:
        result = ida_rpc(code)
        return json.dumps(result)
    except Exception as e:
        return json.dumps({"error": str(e)})


@server.tool(
    "get_function_signature",
    "Generate signature for entire function",
    {"address": {"type": "string"}, "format": {"type": "string", "default": "ida"}},
)
def get_function_signature(address: str, format: str = "ida") -> str:
    code = f"""
import idaapi, idc, sys
sys.path.append(r'D:\\ida-sigmaker-mcp')
from sigmaker import SigMaker, SigMakerConfig, SignatureType

ea = {int(address, 16) if isinstance(address, str) and address.startswith("0x") else address}
func = idaapi.get_func(ea)
if not func:
    result = {{'error': 'No function at address'}}
else:
    fmt_map = {{'ida': SignatureType.IDA, 'x64dbg': SignatureType.X64DBG, 'c_array': SignatureType.C_ARRAY, 'raw_bytes': SignatureType.RAW_BYTES}}
    cfg = SigMakerConfig(output_format=fmt_map.get('{format}', SignatureType.IDA), wildcard_operands=True, continue_outside_of_function=False, wildcard_optimized=True, max_single_signature_length=500)
    sig = SigMaker.make_sig(func.start_ea, cfg, end=func.end_ea)
    formatted = format(sig.signature, cfg.output_format.value)
    result = {{'function': idaapi.get_func_name(ea), 'start': hex(func.start_ea), 'end': hex(func.end_ea), 'signature': formatted, 'length': len(sig.signature)}}
result
"""
    try:
        result = ida_rpc(code)
        return json.dumps(result)
    except Exception as e:
        return json.dumps({"error": str(e)})


if __name__ == "__main__":
    server.start()
