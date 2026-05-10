# IDA SigMaker MCP Server

将 IDA SigMaker 功能暴露给 LLM 智能体的 Model Context Protocol (MCP) 服务器。

## 功能

该 MCP server 提供以下工具：

### 1. `generate_signature`
在指定地址生成唯一的二进制签名。

**参数：**
- `address` (string): 十六进制地址，如 `"0x140001000"`
- `format` (string, 可选): 输出格式 - `ida`, `x64dbg`, `c_array`, `raw_bytes`，默认 `ida`
- `wildcard_operands` (boolean, 可选): 是否通配指令操作数，默认 `true`
- `max_length` (integer, 可选): 最大签名长度，默认 `100`

**返回：**
```json
{
  "address": "0x140001000",
  "signature": "E8 ? ? ? ? 45 33 F6 66 44 89 34 33",
  "length": 13,
  "format": "ida"
}
```

### 2. `generate_xref_signatures`
为地址的所有交叉引用生成签名。

**参数：**
- `address` (string): 目标地址
- `format` (string, 可选): 输出格式，默认 `ida`
- `top_n` (integer, 可选): 返回前 N 个最短签名，默认 `5`
- `max_length` (integer, 可选): 最大签名长度，默认 `250`

**返回：**
```json
{
  "target_address": "0x140001000",
  "xref_count": 15,
  "top_signatures": [
    {
      "address": "0x140002000",
      "signature": "E8 ? ? ? ? 48 8B",
      "length": 7
    }
  ]
}
```

### 3. `search_signature`
在二进制中搜索签名模式。

**参数：**
- `pattern` (string): 签名模式（自动检测格式）
- `limit` (integer, 可选): 最大结果数，默认 `100`

**返回：**
```json
{
  "pattern": "E8 ? ? ? ? 45 33 F6",
  "match_count": 3,
  "matches": [
    {
      "address": "0x140001000",
      "function": "sub_140001000"
    }
  ]
}
```

### 4. `get_function_signature`
为整个函数生成签名。

**参数：**
- `address` (string): 函数内的地址
- `format` (string, 可选): 输出格式，默认 `ida`

**返回：**
```json
{
  "function": "sub_140001000",
  "start": "0x140001000",
  "end": "0x140001050",
  "signature": "48 89 5C 24 08 57 48 83 EC 20...",
  "length": 80
}
```

## 安装

### 1. 确保 IDA SigMaker 已安装

```bash
cd D:\Download\ida-sigmaker-main
pip install -e .
```

### 2. 配置 OpenCode

将以下配置添加到 OpenCode 的 MCP 配置文件：

**Windows:** `%APPDATA%\opencode\mcp-config.json`

```json
{
  "mcpServers": {
    "ida-sigmaker": {
      "command": "python",
      "args": ["D:\\Download\\ida-sigmaker-main\\mcp-server\\sigmaker_mcp.py"],
      "env": {
        "PYTHONPATH": "D:\\Download\\ida-sigmaker-main\\src"
      }
    }
  }
}
```

### 3. 在 IDA Pro 中使用

1. 在 IDA Pro 中打开二进制文件
2. 启动 IDA Python 控制台
3. 运行 MCP server：
```python
exec(open(r"D:\Download\ida-sigmaker-main\mcp-server\sigmaker_mcp.py").read())
```

或者从 OpenCode 连接到 IDA Pro 的 Python 环境。

## 使用示例

### 在 OpenCode 中使用

```
生成地址 0x140001000 的签名
```

LLM 将自动调用：
```
generate_signature(address="0x140001000", format="ida")
```

### 搜索签名

```
搜索签名 "E8 ? ? ? ? 45 33 F6"
```

LLM 将调用：
```
search_signature(pattern="E8 ? ? ? ? 45 33 F6")
```

### 生成函数签名

```
为地址 0x140001000 的函数生成完整签名
```

LLM 将调用：
```
get_function_signature(address="0x140001000")
```

## 支持的签名格式

- **IDA**: `E8 ? ? ? ? 45 33 F6`
- **x64Dbg**: `E8 ?? ?? ?? ?? 45 33 F6`
- **C Array**: `\xE8\x00\x00\x00\x00\x45\x33\xF6 x????xxx`
- **Raw Bytes**: `0xE8, 0x00, 0x00, 0x00, 0x00, 0x45, 0x33, 0xF6`

## 要求

- Python 3.10+
- IDA Pro 9.0+
- IDA SigMaker 插件
- OpenCode 或其他 MCP 客户端

## 架构

```
┌─────────────┐         ┌──────────────┐         ┌─────────────┐
│  OpenCode   │ ◄─MCP──►│ sigmaker_mcp │ ◄─API──►│  IDA Pro    │
│  (LLM)      │         │   (Server)   │         │  (idaapi)   │
└─────────────┘         └──────────────┘         └─────────────┘
```

MCP server 作为桥梁，将 IDA SigMaker 的功能通过标准化协议暴露给 LLM 智能体。

## 故障排除

### 导入错误
确保 `PYTHONPATH` 包含 sigmaker 源码目录：
```bash
export PYTHONPATH="D:\Download\ida-sigmaker-main\src"
```

### IDA API 不可用
MCP server 必须在 IDA Pro 的 Python 环境中运行，因为它依赖 `idaapi` 和 `idc` 模块。

### 连接问题
检查 MCP 配置文件路径和 Python 解释器路径是否正确。

## 许可证

与 IDA SigMaker 主项目相同的许可证。
