# IDA SigMaker MCP Server

將 IDA SigMaker 功能暴露給 LLM 智能體的 Model Context Protocol (MCP) 服務器。由我(此指該帳號/項目擁有者GayBottle)及Claude Opus 4.7製作。

## 功能

該 MCP server 提供以下工具：

### 1. `generate_signature`
在指定地址生成唯一的二進制簽名。

**參數：**
- `address` (string): 十六進制地址，如 `"0x140001000"`
- `format` (string, 可選): 輸出格式 - `ida`, `x64dbg`, `c_array`, `raw_bytes`，默認 `ida`
- `wildcard_operands` (boolean, 可選): 是否通配指令操作數，默認 `true`
- `max_length` (integer, 可選): 最大簽名長度，默認 `100`

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
為地址的所有交叉引用生成簽名。

**參數：**
- `address` (string): 目標地址
- `format` (string, 可選): 輸出格式，默認 `ida`
- `top_n` (integer, 可選): 返回前 N 個最短簽名，默認 `5`
- `max_length` (integer, 可選): 最大簽名長度，默認 `250`

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
在二進制中搜索簽名模式。

**參數：**
- `pattern` (string): 簽名模式（自動檢測格式）
- `limit` (integer, 可選): 最大結果數，默認 `100`

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
為整個函數生成簽名。

**參數：**
- `address` (string): 函數內的地址
- `format` (string, 可選): 輸出格式，默認 `ida`

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

## 安裝

### 1. 確保 IDA SigMaker 已安裝

從 [IDA SigMaker GitHub](https://github.com/mahmoudimus/ida-sigmaker) 下載並安裝插件到 IDA Pro。

### 2. 配置 OpenCode

將以下配置添加到 OpenCode 的 MCP 配置文件：

**Windows:** `%APPDATA%\opencode\mcp-config.json`

```json
{
  "mcpServers": {
    "ida-sigmaker": {
      "command": "python",
      "args": ["D:\\Download\\ida-sigmaker-main\\mcp-server\\sigmaker_mcp.py"],
      "env": {
        "PYTHONPATH": "D:\\path\\to\\ida\\python"
      }
    }
  }
}
```

### 3. 在 IDA Pro 中使用

1. 在 IDA Pro 中打開二進制文件
2. 啟動 IDA Python 控制台
3. 運行 MCP server：
```python
exec(open(r"D:\Download\ida-sigmaker-main\mcp-server\sigmaker_mcp.py").read())
```

或者從 OpenCode 連接到 IDA Pro 的 Python 環境。

## 使用示例

### 在 OpenCode 中使用

```
生成地址 0x140001000 的簽名
```

LLM 將自動調用：
```
generate_signature(address="0x140001000", format="ida")
```

### 搜索簽名

```
搜索簽名 "E8 ? ? ? ? 45 33 F6"
```

LLM 將調用：
```
search_signature(pattern="E8 ? ? ? ? 45 33 F6")
```

### 生成函數簽名

```
為地址 0x140001000 的函數生成完整簽名
```

LLM 將調用：
```
get_function_signature(address="0x140001000")
```

## 支持的簽名格式

- **IDA**: `E8 ? ? ? ? 45 33 F6`
- **x64Dbg**: `E8 ?? ?? ?? ?? 45 33 F6`
- **C Array**: `\xE8\x00\x00\x00\x00\x45\x33\xF6 x????xxx`
- **Raw Bytes**: `0xE8, 0x00, 0x00, 0x00, 0x00, 0x45, 0x33, 0xF6`

## 要求

- Python 3.10+
- IDA Pro 9.0+
- IDA SigMaker 插件
- OpenCode 或其他 MCP 客戶端

## 架構

```
┌─────────────┐         ┌──────────────┐         ┌─────────────┐
│  OpenCode   │ ◄─MCP──►│ sigmaker_mcp │ ◄─API──►│  IDA Pro    │
│  (LLM)      │         │   (Server)   │         │  (idaapi)   │
└─────────────┘         └──────────────┘         └─────────────┘
```

MCP server 作為橋樑，將 IDA SigMaker 的功能通過標準化協議暴露給 LLM 智能體。

## 故障排除

### 導入錯誤
確保 `PYTHONPATH` 包含 IDA Python 目錄：
```bash
export PYTHONPATH="/path/to/ida/python"
```

### IDA API 不可用
MCP server 必須在 IDA Pro 的 Python 環境中運行，因為它依賴 `idaapi` 和 `idc` 模組。

### 連接問題
檢查 MCP 配置文件路徑和 Python 解釋器路徑是否正確。

## 致謝

- **IDA SigMaker**: 基於 [@mahmoudimus](https://github.com/mahmoudimus) 的 [ida-sigmaker](https://github.com/mahmoudimus/ida-sigmaker) 項目
- **MCP 協議**: 參考 [Model Context Protocol 文檔](https://modelcontextprotocol.io/) 和 [OpenCode MCP 文檔](https://www.opencode.asia/ecosystem/mcp-servers/)

## 許可證

與 IDA SigMaker 主項目相同的許可證。詳見 [LICENSE](../LICENSE)。
