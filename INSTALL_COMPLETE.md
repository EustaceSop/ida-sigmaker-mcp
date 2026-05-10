# IDA SigMaker MCP 安装完成

## 已完成的配置

✅ **MCP Server 已安装到**: `D:\ida-sigmaker-mcp\mcp-server\sigmaker_mcp.py`
✅ **SigMaker 源码已下载**: `D:\ida-sigmaker-mcp\sigmaker.py`
✅ **OpenCode 配置已更新**: `C:\Users\GayBottle\.config\opencode\opencode.json`

## 配置详情

```json
{
  "ida-sigmaker": {
    "type": "local",
    "command": ["python", "D:/ida-sigmaker-mcp/mcp-server/sigmaker_mcp.py"],
    "enabled": true,
    "timeout": 30000
  }
}
```

## 使用前提

1. **IDA Pro 必须运行** 并启用 RPC 服务器在 `http://127.0.0.1:13337`
2. **ida-pro-mcp** 必须已启动（你的配置中已启用）

## 可用工具

### 1. `generate_signature` - 生成稳定签名
生成在游戏更新后仍然有效的唯一签名。

**示例：**
```
生成地址 0x140001000 的签名，使用 IDA 格式
```

### 2. `generate_xref_signatures` - 生成 XREF 签名
为所有调用目标地址的位置生成签名，找到最短最稳定的。

**示例：**
```
为地址 0x140002000 生成前 5 个最短的 XREF 签名
```

### 3. `search_signature` - 搜索签名
在二进制中搜索签名模式，验证签名唯一性。

**示例：**
```
搜索签名 "E8 ? ? ? ? 45 33 F6"
```

### 4. `get_function_signature` - 函数签名
为整个函数生成签名。

**示例：**
```
为地址 0x140001000 的函数生成完整签名
```

## 签名稳定性技巧

### 使用 XREF 签名（推荐）
XREF 签名比直接地址签名更稳定，因为：
- 调用者代码通常不会改变
- 即使目标函数被修改，调用点仍然存在
- 可以找到多个调用点，选择最稳定的

### 配置参数
- `wildcard_operands=True`: 通配操作数（地址、立即数）
- `wildcard_optimized=True`: 优化通配符位置
- `max_length`: 限制签名长度，越短越稳定

### 验证签名
生成签名后，使用 `search_signature` 验证：
- 结果应该只有 1 个匹配
- 如果有多个匹配，增加签名长度或使用 XREF

## 重启 OpenCode

配置已更新，请重启 OpenCode 以加载新的 MCP server。

## 测试命令

重启后，你可以直接对我说：

```
使用 ida-sigmaker 为地址 0x140001000 生成签名
```

我会自动调用 MCP 工具并返回结果。
