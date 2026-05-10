# IDA SigMaker MCP Server

將 IDA SigMaker 功能暴露給 LLM 智能體的 Model Context Protocol (MCP) 服務器。由我(此指該帳號/項目擁有者 GayBottle)及 Claude Opus 4.7 製作。

## 功能

該 MCP server 提供以下工具：

### 1. `generate_signature`
在指定地址生成唯一的二進制簽名。

**參數：**
- `address` (string): 十六進制地址，如 `"0x140001000"`
- `format` (string, 可選): 輸出格式 - `ida`, `x64dbg`, `mask`, `bitmask`，默認 `ida`
- `max_length` (integer, 可選): 最大簽名長度，默認 `100`

**返回：**
```json
{
  "address": "0x140001000",
  "signature": "E8 ? ? ? ? 45 33 F6 66 44 89 34 33",
  "length": 13,
  "format": "ida",
  "unique": true,
  "source": "original sigmaker"
}
```

### 2. `generate_xref_signatures`
為地址的所有交叉引用生成簽名（間接定位目標）。

**參數：**
- `address` (string): 目標地址
- `format` (string, 可選): 輸出格式，默認 `ida`
- `top_n` (integer, 可選): 返回前 N 個最短簽名，默認 `5`
- `max_length` (integer, 可選): 最大簽名長度，默認 `100`

**返回：**
```json
{
  "target": "0x140001000",
  "format": "ida",
  "xref_count": 15,
  "xref_signatures": [
    {
      "signature": "E8 ? ? ? ? 48 8B",
      "caller": "0x140002000",
      "length": 7
    }
  ],
  "source": "original sigmaker"
}
```

### 3. `search_signature`
在二進制中搜索簽名模式。

**參數：**
- `pattern` (string): 簽名模式（IDA 格式：`E8 ? ? ? ?` 或 `E8 ?? ?? ?? ??`）
- `limit` (integer, 可選): 最大結果數，默認 `100`

**返回：**
```json
{
  "pattern": "E8 ? ? ? ? 45 33 F6",
  "matches": 3,
  "addresses": [
    "0x140001000",
    "0x140002000",
    "0x140003000"
  ]
}
```

### 4. `batch_generate_signatures`
批量為多個地址生成簽名。

**參數：**
- `addresses` (array): 地址列表，如 `["0x140001000", "0x140002000"]`
- `format` (string, 可選): 輸出格式，默認 `ida`
- `max_length` (integer, 可選): 最大簽名長度，默認 `100`

**返回：**
```json
{
  "format": "ida",
  "total": 2,
  "results": [
    {
      "address": "0x140001000",
      "signature": "E8 ? ? ? ? 45 33 F6",
      "length": 7,
      "success": true
    },
    {
      "address": "0x140002000",
      "error": "Signature not unique",
      "success": false
    }
  ]
}
```

### 5. `verify_signature_unique`
驗證簽名是否唯一且指向正確地址。

**參數：**
- `signature` (string): 簽名模式
- `expected_address` (string): 預期地址

**返回：**
```json
{
  "signature": "E8 ? ? ? ? 45 33 F6",
  "expected": "0x140001000",
  "matches": 1,
  "addresses": ["0x140001000"],
  "unique": true,
  "correct": true
}
```

## 前置要求

### 1. 軟體版本
- **Python**: 3.11+ (推薦 3.11.9)
- **IDA Pro**: 9.0+ (已測試 9.0)
- **OpenCode**: 最新版本

### 2. IDA SigMaker 插件安裝

#### 方法 A：使用預編譯 DLL（推薦）
1. 下載 `SigMaker64.dll` 從 [IDA SigMaker Releases](https://github.com/A200K/IDA-Pro-SigMaker/releases)
2. 複製到 IDA 插件目錄：
   ```
   C:\Users\<用戶名>\AppData\Roaming\Hex-Rays\IDA Pro\plugins\SigMaker64.dll
   ```

#### 方法 B：從源碼編譯
1. 克隆倉庫：
   ```bash
   git clone https://github.com/A200K/IDA-Pro-SigMaker.git
   ```
2. 使用 Visual Studio 編譯 `SigMaker64.dll`
3. 複製到 IDA 插件目錄

### 3. Python 依賴安裝

```bash
pip install requests
```

### 4. IDA MCP 插件安裝

IDA MCP 插件用於提供 RPC 接口：

```bash
pip install ida-pro-mcp
```

安裝後，IDA Pro 啟動時會自動加載 MCP 插件並監聽 `127.0.0.1:13337`。

## 安裝配置

### 1. 克隆本倉庫

```bash
git clone https://github.com/yourusername/ida-sigmaker-mcp.git
cd ida-sigmaker-mcp
```

### 2. 配置環境變量（可選）

在 `~/.bashrc` 或系統環境變量中設置：

```bash
export SIGMAKER_PATH="D:\ida-sigmaker-mcp"
export IDA_RPC_URL="http://127.0.0.1:13337"
```

如果不設置，將使用默認值。

### 3. 配置 OpenCode

編輯 OpenCode 配置文件：

**Windows:** `C:\Users\<用戶名>\.config\opencode\opencode.json`

添加以下配置：

```json
{
  "mcpServers": {
    "ida-sigmaker": {
      "type": "local",
      "command": ["python", "D:/ida-sigmaker-mcp/mcp-server/sigmaker_mcp.py"],
      "enabled": true,
      "timeout": 30000
    }
  }
}
```

**注意：** 
- 路徑使用正斜杠 `/` 或雙反斜杠 `\\`
- `timeout` 設置為 30 秒，避免大型二進制分析超時

### 4. 啟動服務

1. **啟動 IDA Pro** 並打開目標二進制文件
   - IDA MCP 插件會自動啟動 RPC 服務器（端口 13337）
   
2. **啟動 OpenCode**
   - OpenCode 會自動啟動 `sigmaker_mcp.py`
   - 無需手動啟動任何服務

### 5. 驗證安裝

在 OpenCode 中測試：

```
生成地址 0x140001000 的簽名
```

如果返回簽名結果，說明安裝成功。

## 使用示例

### 在 OpenCode 中使用

#### 生成單個簽名
```
為地址 0x140031670 生成 IDA 格式的簽名
```

#### 批量生成簽名
```
為地址 0x140031670, 0x140031510, 0x1400315f0 批量生成簽名
```

#### 搜索簽名
```
搜索簽名 "48 89 C1 E8 ?? ?? ?? ??"
```

#### 驗證簽名唯一性
```
驗證簽名 "98 0C ? 86 E8" 是否唯一且指向 0x140031670
```

#### 生成 XREF 簽名
```
為地址 0x140031670 生成前 3 個 xref 簽名
```

## 支持的簽名格式

- **IDA**: `E8 ? ? ? ? 45 33 F6` (單個 `?` 作為通配符)
- **x64Dbg**: `E8 ?? ?? ?? ?? 45 33 F6` (雙 `??` 作為通配符)
- **Mask**: `E8 00 00 00 00 45 33 F6` + `x????xxx`
- **BitMask**: 位級別的掩碼格式

## 架構

```
┌─────────────────┐
│   OpenCode      │  (AI 智能體)
│   (LLM Agent)   │
└────────┬────────┘
         │ stdin/stdout (JSON-RPC)
         ▼
┌─────────────────┐
│ sigmaker_mcp.py │  (MCP Server)
└────────┬────────┘
         │ subprocess stdin/stdout
         ▼
┌─────────────────┐
│ ida_pro_mcp     │  (IDA MCP Server)
│   server.py     │
└────────┬────────┘
         │ HTTP JSON-RPC (127.0.0.1:13337)
         ▼
┌─────────────────┐
│   IDA Pro       │  (ida.exe)
│   ida_mcp       │  (內部插件)
└────────┬────────┘
         │ Python API (idaapi)
         ▼
┌─────────────────┐
│  SigMaker64.dll │  (原始插件)
│   sigmaker.py   │
└─────────────────┘
```

**工作流程：**
1. OpenCode 啟動時自動啟動 `sigmaker_mcp.py`
2. IDA Pro 啟動時自動加載 `ida_mcp` 插件並監聽 13337 端口
3. 智能體調用 sigmaker 工具時，`sigmaker_mcp.py` 啟動臨時 subprocess 連接 IDA MCP
4. IDA MCP 通過 Python API 調用原始 sigmaker 插件
5. 結果通過相同路徑返回給智能體

## 故障排除

### 1. "IDA RPC error: No response from IDA"
**原因：** IDA Pro 未啟動或 IDA MCP 插件未加載

**解決：**
- 確保 IDA Pro 正在運行
- 檢查 IDA 是否加載了 `ida_mcp` 插件
- 驗證端口 13337 是否被佔用：`netstat -ano | findstr 13337`

### 2. "Cannot create code signature for data"
**原因：** 目標地址是數據區而非代碼區

**解決：**
- 確保地址指向代碼段
- 使用 IDA 的 `C` 鍵將數據轉換為代碼
- 或使用 xref 簽名間接定位

### 3. "Signature not unique"
**原因：** 生成的簽名在二進制中有多個匹配

**解決：**
- 增加 `max_length` 參數
- 使用 `generate_xref_signatures` 生成基於調用者的簽名
- 手動調整簽名模式

### 4. "Module 'sigmaker' not found"
**原因：** `SIGMAKER_PATH` 環境變量未設置或路徑錯誤

**解決：**
- 設置環境變量：`export SIGMAKER_PATH="D:\ida-sigmaker-mcp"`
- 或在 OpenCode 配置中添加 `env` 字段

### 5. MCP 服務器未啟動
**原因：** OpenCode 配置錯誤或 Python 路徑錯誤

**解決：**
- 檢查 `opencode.json` 配置文件路徑
- 確保 Python 在 PATH 中：`python --version`
- 查看 OpenCode 日誌：`~/.config/opencode/logs/`

## 性能優化

- **持久化連接：** MCP 服務器使用持久化 subprocess 連接，避免每次調用都啟動新進程
- **批量操作：** 使用 `batch_generate_signatures` 批量生成簽名，減少 RPC 開銷
- **超時設置：** 大型二進制分析時增加 `timeout` 值

## 致謝

- **IDA SigMaker**: 基於 [@A200K](https://github.com/A200K/IDA-Pro-SigMaker) 的 IDA Pro SigMaker 項目
- **原始 Python 版本**: [@mahmoudimus](https://github.com/mahmoudimus/ida-sigmaker)
- **MCP 協議**: [Model Context Protocol](https://modelcontextprotocol.io/)
- **OpenCode**: [OpenCode MCP 文檔](https://www.opencode.asia/ecosystem/mcp-servers/)

## 許可證

與 IDA SigMaker 主項目相同的許可證。詳見 [LICENSE](../LICENSE)。
