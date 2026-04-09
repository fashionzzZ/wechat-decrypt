# WeChat Live Server - 实时解密查询服务

基于 wechat-decrypt 的实时解密架构，提供 HTTP API + WebSocket 实时推送。

## 特性

- **实时解密**: 按需解密数据库页面，支持 WAL 增量同步
- **跨平台**: 纯 Python 实现，支持 macOS (Intel/Apple Silicon)、Windows、Linux
- **HTTP API**: RESTful 接口，支持查询会话、消息、联系人
- **WebSocket**: 双向通信，支持实时消息推送
- **增量同步**: 只同步变化的 WAL 页面，性能优化

## 安装依赖

```bash
pip install -r requirements.txt
```

## 配置

1. 复制配置模板：
```bash
cp config.example.json config.json
```

2. 编辑 `config.json`，设置微信数据目录：
```json
{
    "db_dir": "/Users/xxx/Library/Containers/com.tencent.xinWeChat/Data/Documents/xwechat_files/wxid_xxx/db_storage",
    "keys_file": "all_keys.json",
    "decrypted_dir": "decrypted"
}
```

3. 提取数据库密钥：
```bash
# macOS (Intel 和 Apple Silicon 都支持)
sudo cc -O2 -o find_all_keys_macos find_all_keys_macos.c -framework Foundation
sudo ./find_all_keys_macos

# Windows
python find_all_keys.py

# Linux
sudo python find_all_keys.py
```

## 启动服务

```bash
python live_server.py
```

选项：
```bash
python live_server.py --host 127.0.0.1 --port 5678
python live_server.py --no-monitor  # 禁用实时监听
```

## API 接口

### HTTP API

#### 获取 API 信息
```bash
GET /
```

#### 获取会话列表
```bash
GET /api/sessions?limit=100
```

响应：
```json
{
  "sessions": [
    {
      "session_id": "wxid_xxx",
      "username": "wxid_xxx",
      "display_name": "联系人名称",
      "unread_count": 0,
      "last_message": {...},
      "last_time": 1234567890
    }
  ]
}
```

#### 获取会话消息
```bash
GET /api/messages/<session_id>?offset=0&limit=100&start_time=0&end_time=0
```

#### 获取联系人列表
```bash
GET /api/contacts?query=搜索词&limit=100
```

#### 搜索消息
```bash
GET /api/search?keyword=关键词&session_id=&limit=100
```

#### 获取统计信息
```bash
GET /api/stats
```

### WebSocket API

连接：
```javascript
const ws = new WebSocket('ws://127.0.0.1:5679');

ws.onopen = () => {
  // 订阅会话更新
  ws.send(JSON.stringify({
    action: 'subscribe',
    session_id: 'wxid_xxx'
  }));
};

ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  console.log('Received:', data);
};
```

支持的 action：
- `subscribe`: 订阅会话更新
- `get_messages`: 获取消息
- `ping`: 心跳检测

## 与 WeFlow 集成

WeFlow 可以通过 HTTP API 调用 live_server，替代原生库：

```typescript
// Electron 主进程调用示例
async function getSessions() {
  const response = await fetch('http://127.0.0.1:5678/api/sessions');
  const data = await response.json();
  return data.sessions;
}

async function getMessages(sessionId: string) {
  const response = await fetch(`http://127.0.0.1:5678/api/messages/${sessionId}?limit=100`);
  const data = await response.json();
  return data.messages;
}
```

## 架构对比

| 特性 | WeFlow (原生库) | live_server (Python) |
|------|-----------------|----------------------|
| 数据库访问 | 实时解密 (DLL) | 实时解密 (Python) |
| 密钥提取 | Hook/注入 | 内存扫描 (C) |
| 图片解密 | Node.js crypto | Python pycryptodome |
| 实时监听 | 命名管道 | WAL 轮询 + WebSocket |
| 跨平台 | 需要各平台 DLL | 纯 Python，自动适配 |
| Intel Mac | ❌ 不支持 | ✅ 支持 |

## 性能优化

- **连接池**: 复用数据库连接，避免频繁创建
- **WAL 增量**: 只同步变化的页面，而非全库解密
- **页面缓存**: 缓存热点页面，减少解密次数
- **联系人缓存**: 缓存联系人信息，60秒刷新

## 测试

```bash
python test_live_server.py
```

## 注意事项

1. **SIP (系统完整性保护)**: macOS 需要关闭 SIP 才能读取微信进程内存
   ```bash
   # 重启进入恢复模式，打开终端执行
   csrutil disable
   ```

2. **微信版本**: 仅支持微信 4.0 及以上版本

3. **权限**: 密钥提取需要管理员/root权限

## 开发计划

- [x] Phase 1: 基础 HTTP API + WebSocket
- [ ] Phase 2: 性能优化（连接池、缓存）
- [ ] Phase 3: 与 WeFlow 完整集成
- [ ] Phase 4: 图片实时解密 API
