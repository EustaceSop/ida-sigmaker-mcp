#!/usr/bin/env python3
"""
IDA SigMaker MCP Server
Uses ida-pro-mcp py_eval to execute sigmaker code
"""

import json
import sys
from typing import Any, Dict, Callable


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
        req_id = request.get("id")

        if method == "initialize":
            result = {
                "protocolVersion": "2024-11-05",
                "serverInfo": {"name": self.name, "version": self.version},
                "capabilities": {"tools": {}},
            }
            return {"jsonrpc": "2.0", "id": req_id, "result": result}

        elif method == "tools/list":
            result = {
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
            return {"jsonrpc": "2.0", "id": req_id, "result": result}

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


server = MCPServer("ida-sigmaker", "1.0.0")

SIGMAKER_INIT = r"""
import sys, os
sigmaker_path = r'D:\ida-sigmaker-mcp'
if sigmaker_path not in sys.path:
    sys.path.insert(0, sigmaker_path)
try:
    import sigmaker
    from sigmaker import SigMaker, SigMakerConfig, SignatureType, InMemoryBuffer
    SIGMAKER_OK = True
except Exception as e:
    SIGMAKER_OK = False
    SIGMAKER_ERROR = str(e)
"""


@server.tool(
    "generate_signature",
    "Generate unique binary signature at address using manual method",
    {
        "address": {
            "type": "string",
            "description": "Hex address (e.g., '0x140001000')",
        },
        "length": {
            "type": "integer",
            "description": "Signature length in bytes",
            "default": 16,
        },
    },
)
def generate_signature(address: str, length: int = 16) -> str:
    """Generate signature using basic byte extraction + wildcarding"""
    return json.dumps(
        {
            "method": "manual",
            "instructions": [
                f"1. Use ida-pro-mcp get_bytes at {address} for {length} bytes",
                "2. Manually wildcard bytes 3-6 for RIP-relative offsets",
                "3. Test uniqueness with find_bytes",
                "4. Extend length if multiple matches found",
            ],
            "example_workflow": {
                "get_bytes": f'ida-pro-mcp_get_bytes(regions=[{{"address": "{address}", "size": {length}}}])',
                "wildcard_pattern": "Replace bytes at offsets 3-6 with '??'",
                "test_unique": "ida-pro-mcp_find_bytes with wildcarded pattern",
            },
        }
    )


@server.tool(
    "generate_xref_signatures",
    "Find callers and suggest signature locations",
    {"address": {"type": "string"}},
)
def generate_xref_signatures(address: str) -> str:
    return json.dumps(
        {
            "method": "manual_xref",
            "instructions": [
                f"1. Use ida-pro-mcp xrefs_to({address}) to find callers",
                "2. For each caller, extract 16-24 bytes before the CALL instruction",
                "3. Wildcard the CALL target offset (last 4 bytes of CALL)",
                "4. Test each pattern for uniqueness",
            ],
        }
    )


@server.tool(
    "search_signature",
    "Search pattern using ida-pro-mcp",
    {"pattern": {"type": "string", "description": "Hex pattern with ?? wildcards"}},
)
def search_signature(pattern: str) -> str:
    return json.dumps(
        {
            "method": "Use ida-pro-mcp_find_bytes directly",
            "pattern": pattern,
            "note": "ida-pro-mcp find_bytes supports ?? wildcards natively",
        }
    )


@server.tool(
    "manual_signature_guide", "Step-by-step guide for manual signature generation", {}
)
def manual_signature_guide() -> str:
    return json.dumps(
        {
            "title": "Manual Signature Generation Guide",
            "steps": {
                "1_locate": {
                    "tool": "ida-pro-mcp_find_bytes",
                    "purpose": "Find target instruction",
                    "example": "find_bytes(patterns=['48 8B 05'])",
                },
                "2_extract": {
                    "tool": "ida-pro-mcp_get_bytes",
                    "purpose": "Extract surrounding context (16-24 bytes)",
                    "example": "get_bytes(regions=[{'address': '0x140001000', 'size': 24}])",
                },
                "3_analyze": {
                    "tool": "ida-pro-mcp_disasm",
                    "purpose": "Understand instruction structure",
                    "example": "disasm(addr='0x140001000', max_instructions=5)",
                },
                "4_wildcard": {
                    "manual": True,
                    "rules": [
                        "Wildcard immediate values (varies per build)",
                        "Wildcard RIP-relative offsets (bytes 3-6 in LEA/MOV)",
                        "Wildcard CALL/JMP targets",
                        "Keep opcode bytes and register encodings",
                    ],
                },
                "5_test": {
                    "tool": "ida-pro-mcp_find_bytes",
                    "purpose": "Verify uniqueness",
                    "target": "Should return exactly 1 match",
                },
            },
            "example_patterns": {
                "WorldPtr": {
                    "pattern": "48 89 C1 E8 ?? ?? ?? ?? 48 8B 05 ?? ?? ?? ?? 48 8B 40 18 48 8B 88 78 03",
                    "mask": "xxxx????xxx????xxxxxxxxx",
                    "offset": 10,
                },
                "BlipPtr": {
                    "pattern": "48 8D 05 ?? ?? ?? ?? 48 89 03 0F B7 0D ?? ?? ?? ?? 85 C9 74",
                    "mask": "xxx????xxxxxx????xxx",
                    "offset": 0,
                },
            },
        }
    )


if __name__ == "__main__":
    server.start()
