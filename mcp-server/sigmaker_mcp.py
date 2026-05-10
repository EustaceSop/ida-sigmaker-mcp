#!/usr/bin/env python3
"""
IDA SigMaker MCP Server
Exposes IDA signature generation capabilities to LLM agents via Model Context Protocol
"""

import json
import sys
from typing import Any, Dict, Callable


class MCPServer:
    """Minimal MCP protocol implementation"""

    def __init__(self, name: str, version: str):
        self.name = name
        self.version = version
        self.tools: Dict[str, Dict[str, Any]] = {}

    def tool(self, name: str, description: str, parameters: dict):
        """Decorator to register a tool"""

        def decorator(func: Callable):
            self.tools[name] = {
                "description": description,
                "parameters": parameters,
                "handler": func,
            }
            return func

        return decorator

    def handle_request(self, request: dict) -> dict:
        """Handle incoming MCP requests"""
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
                        "name": tool_name,
                        "description": tool_info["description"],
                        "inputSchema": {
                            "type": "object",
                            "properties": tool_info["parameters"],
                        },
                    }
                    for tool_name, tool_info in self.tools.items()
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
        """Start the MCP server (stdio transport)"""
        for line in sys.stdin:
            try:
                request = json.loads(line)
                response = self.handle_request(request)
                print(json.dumps(response), flush=True)
            except Exception as e:
                print(json.dumps({"error": str(e)}), flush=True)


# Initialize server
server = MCPServer("ida-sigmaker", "1.0.0")


# Tool 1: Generate signature at address
@server.tool(
    "generate_signature",
    "Generate a unique binary signature at the specified address",
    {
        "address": {
            "type": "string",
            "description": "Hex address (e.g., '0x140001000')",
        },
        "format": {
            "type": "string",
            "description": "Output format: ida, x64dbg, c_array, raw_bytes",
            "default": "ida",
        },
        "wildcard_operands": {
            "type": "boolean",
            "description": "Wildcard instruction operands",
            "default": True,
        },
        "max_length": {
            "type": "integer",
            "description": "Maximum signature length",
            "default": 100,
        },
    },
)
def generate_signature(
    address: str,
    format: str = "ida",
    wildcard_operands: bool = True,
    max_length: int = 100,
) -> str:
    """Generate signature at address using IDA Python API"""
    try:
        import idaapi
        import idc
        from sigmaker import SigMaker, SigMakerConfig, SignatureType

        # Parse address
        ea = int(address, 16) if isinstance(address, str) else address

        # Map format string to SignatureType
        format_map = {
            "ida": SignatureType.IDA,
            "x64dbg": SignatureType.X64DBG,
            "c_array": SignatureType.C_ARRAY,
            "raw_bytes": SignatureType.RAW_BYTES,
        }

        # Create config
        cfg = SigMakerConfig(
            output_format=format_map.get(format, SignatureType.IDA),
            wildcard_operands=wildcard_operands,
            continue_outside_of_function=True,
            wildcard_optimized=True,
            max_single_signature_length=max_length,
        )

        # Generate signature
        sig = SigMaker.make_sig(ea, cfg)
        formatted = format(sig.signature, cfg.output_format.value)

        return json.dumps(
            {
                "address": hex(ea),
                "signature": formatted,
                "length": len(sig.signature),
                "format": format,
            }
        )
    except Exception as e:
        return json.dumps({"error": str(e)})


# Tool 2: Generate XREF signatures
@server.tool(
    "generate_xref_signatures",
    "Generate signatures for all cross-references to an address",
    {
        "address": {
            "type": "string",
            "description": "Hex address (e.g., '0x140001000')",
        },
        "format": {
            "type": "string",
            "description": "Output format: ida, x64dbg, c_array, raw_bytes",
            "default": "ida",
        },
        "top_n": {
            "type": "integer",
            "description": "Return top N shortest signatures",
            "default": 5,
        },
        "max_length": {
            "type": "integer",
            "description": "Maximum signature length",
            "default": 250,
        },
    },
)
def generate_xref_signatures(
    address: str, format: str = "ida", top_n: int = 5, max_length: int = 250
) -> str:
    """Generate signatures for all XREFs to address"""
    try:
        import idaapi
        from sigmaker import SigMaker, SigMakerConfig, SignatureType

        ea = int(address, 16) if isinstance(address, str) else address

        format_map = {
            "ida": SignatureType.IDA,
            "x64dbg": SignatureType.X64DBG,
            "c_array": SignatureType.C_ARRAY,
            "raw_bytes": SignatureType.RAW_BYTES,
        }

        cfg = SigMakerConfig(
            output_format=format_map.get(format, SignatureType.IDA),
            wildcard_operands=True,
            continue_outside_of_function=True,
            wildcard_optimized=True,
            print_top_x=top_n,
            max_xref_signature_length=max_length,
        )

        xref_sigs = SigMaker.make_sig_xrefs(ea, cfg)

        results = []
        for sig in xref_sigs.signatures[:top_n]:
            formatted = format(sig.signature, cfg.output_format.value)
            results.append(
                {
                    "address": hex(sig.address),
                    "signature": formatted,
                    "length": len(sig.signature),
                }
            )

        return json.dumps(
            {
                "target_address": hex(ea),
                "xref_count": len(xref_sigs.signatures),
                "top_signatures": results,
            }
        )
    except Exception as e:
        return json.dumps({"error": str(e)})


# Tool 3: Search signature
@server.tool(
    "search_signature",
    "Search for signature pattern in binary",
    {
        "pattern": {"type": "string", "description": "Signature pattern (auto-detects format)"},
        "limit": {"type": "integer", "description": "Maximum number of results", "default": 100}
    }
)
def search_signature(pattern: str, limit: int = 100) -> str:
    try:
        import idaapi
        from sigmaker import SigMaker, InMemoryBuffer
        buf = InMemoryBuffer.load()
        matches = SigMaker.search_sig(pattern, buf, limit=limit)
        results = [{"address": hex(addr), "function": idaapi.get_func_name(addr) or "N/A"} for addr in matches]
        return json.dumps({"pattern": pattern, "match_count": len(results), "matches": results})
    except Exception as e:
        return json.dumps({"error": str(e)})


# Tool 4: Get function signature
@server.tool(
    "get_function_signature",
    "Generate signature for entire function",
    {
        "address": {"type": "string", "description": "Address inside function"},
        "format": {"type": "string", "description": "Output format", "default": "ida"}
    }
)
def get_function_signature(address: str, format: str = "ida") -> str:
    try:
        import idaapi, idc
        from sigmaker import SigMaker, SigMakerConfig, SignatureType
        ea = int(address, 16) if isinstance(address, str) else address
        func = idaapi.get_func(ea)
        if not func:
            return json.dumps({"error": "No function at address"})
        format_map = {"ida": SignatureType.IDA, "x64dbg": SignatureType.X64DBG, "c_array": SignatureType.C_ARRAY, "raw_bytes": SignatureType.RAW_BYTES}
        cfg = SigMakerConfig(output_format=format_map.get(format, SignatureType.IDA), wildcard_operands=True, continue_outside_of_function=False, wildcard_optimized=True, max_single_signature_length=500)
        sig = SigMaker.make_sig(func.start_ea, cfg, end=func.end_ea)
        formatted = format(sig.signature, cfg.output_format.value)
        return json.dumps({"function": idaapi.get_func_name(ea), "start": hex(func.start_ea), "end": hex(func.end_ea), "signature": formatted, "length": len(sig.signature)})
    except Exception as e:
        return json.dumps({"error": str(e)})


if __name__ == "__main__":
    server.start()
