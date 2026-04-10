"""
WeChat 实时解密查询服务 - Phase 1

基于 wechat-decrypt 的实时解密架构，提供 HTTP API + WebSocket 实时推送。
支持 Intel Mac 和 Apple Silicon。

特性:
- 实时解密: 按需解密数据库页面，支持 WAL 增量同步
- WebSocket: 双向通信，支持实时消息推送
- 查询 API: 完整的会话、消息、联系人查询接口
- 跨平台: Python 实现，支持 x86_64 和 arm64

启动:
    python live_server.py
    python live_server.py --port 5678 --host 127.0.0.1

API:
    GET  /api/sessions              - 获取会话列表
    GET  /api/messages/<session>    - 获取指定会话消息
    GET  /api/contacts              - 获取联系人列表
    GET  /api/query                 - 执行自定义 SQL 查询
    WS   /ws                        - WebSocket 实时连接
"""

import os
import sys
import json
import time
import sqlite3
import struct
import hashlib
import tempfile
import threading
import asyncio
import hmac as hmac_mod

# 可选的 WebSocket 支持
try:
    import websockets
    WEBSOCKETS_AVAILABLE = True
except ImportError:
    WEBSOCKETS_AVAILABLE = False
    print("[Warning] websockets module not found, WebSocket support disabled")
    print("Install with: pip install websockets")
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
import urllib.parse

from Crypto.Cipher import AES
from decode_image import decrypt_dat_file, extract_md5_from_packed_info
from key_utils import get_key_info, strip_key_metadata
from config import load_config

# ============ 常量 ============
PAGE_SZ = 4096
KEY_SZ = 32
SALT_SZ = 16
RESERVE_SZ = 80
SQLITE_HDR = b'SQLite format 3\x00'
WAL_HEADER_SZ = 32
WAL_FRAME_HEADER_SZ = 24

# ============ 配置 (延迟加载) ============
_cfg = None
DB_DIR = None
KEYS_FILE = None
DECRYPTED_DIR = None
WECHAT_BASE_DIR = None
ALL_KEYS = None

def _load_config():
    """延迟加载配置"""
    global _cfg, DB_DIR, KEYS_FILE, DECRYPTED_DIR, WECHAT_BASE_DIR, ALL_KEYS
    if _cfg is not None:
        return

    _cfg = load_config()
    DB_DIR = _cfg["db_dir"]
    KEYS_FILE = _cfg["keys_file"]
    DECRYPTED_DIR = _cfg.get("decrypted_dir", os.path.join(os.path.dirname(__file__), "decrypted"))

    # 推导微信基础目录
    if os.path.basename(DB_DIR) == "db_storage":
        WECHAT_BASE_DIR = os.path.dirname(DB_DIR)
    else:
        WECHAT_BASE_DIR = DB_DIR

    # 加载密钥
    with open(KEYS_FILE, encoding="utf-8") as f:
        ALL_KEYS = strip_key_metadata(json.load(f))

# ============ 解密函数 ============

def derive_mac_key(enc_key: bytes, salt: bytes) -> bytes:
    """从 enc_key 派生 HMAC 密钥"""
    mac_salt = bytes(b ^ 0x3a for b in salt)
    return hashlib.pbkdf2_hmac("sha512", enc_key, mac_salt, 2, dklen=KEY_SZ)


def decrypt_page(enc_key: bytes, page_data: bytes, pgno: int) -> bytes:
    """解密单个页面"""
    iv = page_data[PAGE_SZ - RESERVE_SZ: PAGE_SZ - RESERVE_SZ + 16]

    if pgno == 1:
        encrypted = page_data[SALT_SZ: PAGE_SZ - RESERVE_SZ]
        cipher = AES.new(enc_key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(encrypted)
        return bytes(SQLITE_HDR + decrypted + b'\x00' * RESERVE_SZ)
    else:
        encrypted = page_data[:PAGE_SZ - RESERVE_SZ]
        cipher = AES.new(enc_key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(encrypted)
        return decrypted + b'\x00' * RESERVE_SZ


def verify_page_hmac(enc_key: bytes, page_data: bytes, pgno: int) -> bool:
    """验证页面 HMAC"""
    salt = page_data[:SALT_SZ]
    mac_key = derive_mac_key(enc_key, salt)
    stored_hmac = page_data[PAGE_SZ - 64:PAGE_SZ]

    hmac_data = page_data[SALT_SZ:PAGE_SZ - RESERVE_SZ + 16]
    hm = hmac_mod.new(mac_key, hmac_data, hashlib.sha512)
    hm.update(struct.pack('<I', pgno))
    return hm.digest() == stored_hmac


# ============ 实时数据库管理器 ============

@dataclass
class DBConnection:
    """数据库连接包装器"""
    conn: sqlite3.Connection
    db_path: str
    enc_key: bytes
    last_mtime: float = 0
    last_wal_mtime: float = 0
    lock: threading.Lock = field(default_factory=threading.Lock)


class LiveDBManager:
    """
    实时数据库管理器

    管理解密后的数据库连接，支持:
    - 按需解密和缓存
    - WAL 增量同步
    - 连接池管理
    """

    def __init__(self, cache_dir: Optional[str] = None):
        self.cache_dir = cache_dir or os.path.join(tempfile.gettempdir(), "wechat_live_cache")
        os.makedirs(self.cache_dir, exist_ok=True)

        # 连接池: rel_key -> DBConnection
        self.connections: Dict[str, DBConnection] = {}
        self.connections_lock = threading.RLock()

        # 页面缓存: (rel_key, pgno) -> decrypted_page
        self.page_cache: Dict[tuple, bytes] = {}
        self.page_cache_lock = threading.Lock()
        self.max_page_cache = 1000  # 最多缓存 1000 个页面

        # WAL 位置跟踪
        self.wal_positions: Dict[str, int] = {}  # rel_key -> 已读取的 WAL 位置

    def _get_cache_path(self, rel_key: str) -> str:
        """获取缓存文件路径"""
        h = hashlib.md5(rel_key.encode()).hexdigest()[:12]
        return os.path.join(self.cache_dir, f"{h}.db")

    def _decrypt_full_db(self, db_path: str, out_path: str, enc_key: bytes) -> int:
        """完整解密数据库"""
        file_size = os.path.getsize(db_path)
        total_pages = file_size // PAGE_SZ

        with open(db_path, 'rb') as fin, open(out_path, 'wb') as fout:
            for pgno in range(1, total_pages + 1):
                page = fin.read(PAGE_SZ)
                if len(page) < PAGE_SZ:
                    if len(page) > 0:
                        page = page + b'\x00' * (PAGE_SZ - len(page))
                    else:
                        break

                decrypted = decrypt_page(enc_key, page, pgno)
                fout.write(decrypted)

        return total_pages

    def _apply_wal_incremental(self, db_path: str, out_path: str, enc_key: bytes,
                                rel_key: str) -> int:
        """增量应用 WAL 变更"""
        wal_path = db_path + "-wal"
        if not os.path.exists(wal_path):
            return 0

        wal_size = os.path.getsize(wal_path)
        if wal_size <= WAL_HEADER_SZ:
            return 0

        # 获取上次读取位置
        last_pos = self.wal_positions.get(rel_key, WAL_HEADER_SZ)

        frame_size = WAL_FRAME_HEADER_SZ + PAGE_SZ
        patched = 0

        with open(wal_path, 'rb') as wf, open(out_path, 'r+b') as df:
            # 读取 WAL 头
            if last_pos == WAL_HEADER_SZ:
                wf.seek(0)
                wal_hdr = wf.read(WAL_HEADER_SZ)
                wal_salt1 = struct.unpack('>I', wal_hdr[16:20])[0]
                wal_salt2 = struct.unpack('>I', wal_hdr[20:24])[0]
            else:
                wf.seek(16)
                wal_salt1 = struct.unpack('>I', wf.read(4))[0]
                wal_salt2 = struct.unpack('>I', wf.read(4))[0]
                wf.seek(last_pos)

            while wf.tell() + frame_size <= wal_size:
                fh = wf.read(WAL_FRAME_HEADER_SZ)
                if len(fh) < WAL_FRAME_HEADER_SZ:
                    break

                pgno = struct.unpack('>I', fh[0:4])[0]
                frame_salt1 = struct.unpack('>I', fh[8:12])[0]
                frame_salt2 = struct.unpack('>I', fh[12:16])[0]
                ep = wf.read(PAGE_SZ)

                if len(ep) < PAGE_SZ:
                    break

                if pgno == 0 or pgno > 1000000:
                    continue
                if frame_salt1 != wal_salt1 or frame_salt2 != wal_salt2:
                    continue

                dec = decrypt_page(enc_key, ep, pgno)
                df.seek((pgno - 1) * PAGE_SZ)
                df.write(dec)
                patched += 1

            # 更新位置
            self.wal_positions[rel_key] = wf.tell()

        return patched

    def get_connection(self, rel_key: str) -> Optional[sqlite3.Connection]:
        """
        获取数据库连接（实时解密 + WAL 同步）

        Args:
            rel_key: 相对路径，如 "session/session.db"

        Returns:
            sqlite3.Connection 或 None
        """
        _load_config()  # 确保配置已加载

        with self.connections_lock:
            # 检查现有连接
            if rel_key in self.connections:
                db_conn = self.connections[rel_key]

                # 检查是否需要同步 WAL
                db_path = os.path.join(DB_DIR, rel_key.replace('/', os.sep))
                wal_path = db_path + "-wal"

                try:
                    current_mtime = os.path.getmtime(db_path)
                    current_wal_mtime = os.path.getmtime(wal_path) if os.path.exists(wal_path) else 0
                except OSError:
                    return db_conn.conn

                # 如果 WAL 有变化，增量同步
                if current_wal_mtime != db_conn.last_wal_mtime:
                    with db_conn.lock:
                        self._apply_wal_incremental(db_path, self._get_cache_path(rel_key),
                                                    db_conn.enc_key, rel_key)
                        db_conn.last_wal_mtime = current_wal_mtime

                return db_conn.conn

            # 创建新连接
            key_info = get_key_info(ALL_KEYS, rel_key)
            if not key_info:
                return None

            rel_path = rel_key.replace('/', os.sep)
            db_path = os.path.join(DB_DIR, rel_path)

            if not os.path.exists(db_path):
                return None

            try:
                db_mtime = os.path.getmtime(db_path)
                wal_path = db_path + "-wal"
                wal_mtime = os.path.getmtime(wal_path) if os.path.exists(wal_path) else 0
            except OSError:
                return None

            enc_key = bytes.fromhex(key_info["enc_key"])
            cache_path = self._get_cache_path(rel_key)

            # 解密数据库
            self._decrypt_full_db(db_path, cache_path, enc_key)

            # 应用 WAL
            self._apply_wal_incremental(db_path, cache_path, enc_key, rel_key)

            # 创建连接
            conn = sqlite3.connect(cache_path, check_same_thread=False)
            conn.row_factory = sqlite3.Row

            db_conn = DBConnection(
                conn=conn,
                db_path=db_path,
                enc_key=enc_key,
                last_mtime=db_mtime,
                last_wal_mtime=wal_mtime
            )

            self.connections[rel_key] = db_conn
            return conn

    def execute(self, rel_key: str, sql: str, params: tuple = ()) -> List[Dict]:
        """
        执行 SQL 查询

        Args:
            rel_key: 相对路径
            sql: SQL 语句
            params: 查询参数

        Returns:
            查询结果列表
        """
        conn = self.get_connection(rel_key)
        if not conn:
            return []

        try:
            cursor = conn.execute(sql, params)
            rows = cursor.fetchall()
            return [dict(row) for row in rows]
        except sqlite3.Error as e:
            print(f"[LiveDB] Query error: {e}")
            return []

    def close(self, rel_key: Optional[str] = None):
        """关闭连接"""
        with self.connections_lock:
            if rel_key:
                if rel_key in self.connections:
                    self.connections[rel_key].conn.close()
                    del self.connections[rel_key]
            else:
                for db_conn in self.connections.values():
                    db_conn.conn.close()
                self.connections.clear()


# ============ 全局管理器 (延迟初始化) ============

db_manager: Optional[LiveDBManager] = None
api = None  # WeChatAPI 实例，延迟初始化

def get_db_manager() -> LiveDBManager:
    """获取数据库管理器（延迟初始化）"""
    global db_manager
    if db_manager is None:
        db_manager = LiveDBManager()
    return db_manager

def get_api():
    """获取 API 实例（延迟初始化）"""
    global api
    if api is None:
        _load_config()  # 确保配置已加载
        api = WeChatAPI(get_db_manager())
    return api

# ============ 数据模型 ============

@dataclass
class Session:
    """会话"""
    session_id: str
    username: str
    display_name: str
    avatar_url: str = ""
    unread_count: int = 0
    last_message: Optional[Dict] = None
    last_time: int = 0


@dataclass
class Message:
    """消息"""
    msg_id: int
    local_id: int
    session_id: str
    sender: str
    sender_name: str
    content: str
    msg_type: int
    sub_type: int
    create_time: int
    extra: Dict = field(default_factory=dict)


# ============ 查询接口 ============

class WeChatAPI:
    """微信数据查询 API"""

    def __init__(self, db_manager: LiveDBManager):
        self.db = db_manager
        self._contact_cache: Dict[str, str] = {}
        self._contact_cache_time = 0

    def _ensure_contact_cache(self):
        """确保联系人缓存有效"""
        if time.time() - self._contact_cache_time > 60:  # 60秒刷新
            self._contact_cache = self._load_contact_names()
            self._contact_cache_time = time.time()

    def _load_contact_names(self) -> Dict[str, str]:
        """加载联系人名称映射"""
        rows = self.db.execute("contact/contact.db",
            "SELECT username, nick_name, remark FROM contact")
        return {
            row["username"]: row["remark"] or row["nick_name"] or row["username"]
            for row in rows
        }

    def get_display_name(self, username: str) -> str:
        """获取显示名称"""
        self._ensure_contact_cache()
        return self._contact_cache.get(username, username)

    def get_sessions(self, limit: int = 100) -> List[Session]:
        """获取会话列表"""
        rows = self.db.execute("session/session.db", """
            SELECT s.username, s.last_read_msg_id, s.unread_count,
                   m.content, m.create_time, m.msg_type, m.sub_type
            FROM Session s
            LEFT JOIN SessionMessage m ON s.username = m.username
                AND s.last_read_msg_id = m.msg_server_id
            ORDER BY s.sort_seq DESC
            LIMIT ?
        """, (limit,))

        sessions = []
        for row in rows:
            session = Session(
                session_id=row["username"],
                username=row["username"],
                display_name=self.get_display_name(row["username"]),
                unread_count=row.get("unread_count", 0),
                last_time=row.get("create_time", 0)
            )
            if row.get("content"):
                session.last_message = {
                    "content": row["content"],
                    "create_time": row.get("create_time", 0),
                    "msg_type": row.get("msg_type", 0)
                }
            sessions.append(session)

        return sessions

    def get_messages(self, session_id: str, offset: int = 0,
                     limit: int = 100, start_time: int = 0,
                     end_time: int = 0) -> List[Message]:
        """获取指定会话的消息"""
        # 查找对应的数据库
        db_key = None
        for i in range(50):  # 最多 50 个分片
            key = f"message/message_{i}.db"
            if get_key_info(ALL_KEYS, key):
                # 检查是否有这个会话的表
                test_rows = self.db.execute(key,
                    "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE ?",
                    (f"Chat_{session_id}%",))
                if test_rows:
                    db_key = key
                    break

        if not db_key:
            return []

        # 构建查询
        table_name = f"Chat_{session_id}"
        params = []
        where_clauses = []

        if start_time:
            where_clauses.append("create_time >= ?")
            params.append(start_time)
        if end_time:
            where_clauses.append("create_time <= ?")
            params.append(end_time)

        where_sql = " AND ".join(where_clauses) if where_clauses else "1=1"
        params.extend([limit, offset])

        rows = self.db.execute(db_key, f"""
            SELECT local_id, msg_id, sender, content, msg_type, sub_type, create_time
            FROM [{table_name}]
            WHERE {where_sql}
            ORDER BY create_time DESC
            LIMIT ? OFFSET ?
        """, tuple(params))

        messages = []
        for row in rows:
            msg = Message(
                msg_id=row.get("msg_id", 0),
                local_id=row["local_id"],
                session_id=session_id,
                sender=row["sender"],
                sender_name=self.get_display_name(row["sender"]),
                content=row.get("content", ""),
                msg_type=row.get("msg_type", 0),
                sub_type=row.get("sub_type", 0),
                create_time=row["create_time"]
            )
            messages.append(msg)

        return messages

    def get_contacts(self, query: str = "", limit: int = 100) -> List[Dict]:
        """获取联系人列表"""
        if query:
            pattern = f"%{query}%"
            rows = self.db.execute("contact/contact.db", """
                SELECT username, nick_name, remark, avatar
                FROM contact
                WHERE username LIKE ? OR nick_name LIKE ? OR remark LIKE ?
                LIMIT ?
            """, (pattern, pattern, pattern, limit))
        else:
            rows = self.db.execute("contact/contact.db", """
                SELECT username, nick_name, remark, avatar
                FROM contact
                LIMIT ?
            """, (limit,))

        return [dict(row) for row in rows]

    def search_messages(self, keyword: str, session_id: str = "",
                       limit: int = 100) -> List[Message]:
        """搜索消息"""
        # 简化实现：搜索所有 message 数据库
        all_messages = []
        pattern = f"%{keyword}%"

        for i in range(50):
            db_key = f"message/message_{i}.db"
            if not get_key_info(ALL_KEYS, db_key):
                continue

            # 获取所有表名
            tables = self.db.execute(db_key,
                "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'Chat_%'")

            for table in tables:
                table_name = table["name"]
                if session_id and not table_name.endswith(session_id):
                    continue

                rows = self.db.execute(db_key, f"""
                    SELECT local_id, msg_id, sender, content, msg_type, sub_type, create_time
                    FROM [{table_name}]
                    WHERE content LIKE ?
                    LIMIT ?
                """, (pattern, limit))

                sid = table_name.replace("Chat_", "")
                for row in rows:
                    msg = Message(
                        msg_id=row.get("msg_id", 0),
                        local_id=row["local_id"],
                        session_id=sid,
                        sender=row["sender"],
                        sender_name=self.get_display_name(row["sender"]),
                        content=row.get("content", ""),
                        msg_type=row.get("msg_type", 0),
                        sub_type=row.get("sub_type", 0),
                        create_time=row["create_time"]
                    )
                    all_messages.append(msg)

                    if len(all_messages) >= limit:
                        return all_messages

        return all_messages


# ============ API 实例 ============

api = WeChatAPI(db_manager)


# ============ HTTP 处理器 ============

class APIHandler(BaseHTTPRequestHandler):
    """HTTP API 处理器"""

    def log_message(self, format, *args):
        """自定义日志"""
        print(f"[HTTP] {self.address_string()} - {format % args}")

    def _send_json(self, data: Any, status: int = 200):
        """发送 JSON 响应"""
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json.dumps(data, ensure_ascii=False, default=str).encode())

    def _send_error(self, message: str, status: int = 400):
        """发送错误响应"""
        self._send_json({"error": message}, status)

    def do_GET(self):
        """处理 GET 请求"""
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        params = urllib.parse.parse_qs(parsed.query)

        # 解析参数
        def get_param(name: str, default: Any = None, type_func = str):
            if name not in params:
                return default
            try:
                return type_func(params[name][0])
            except (ValueError, TypeError):
                return default

        try:
            # 获取 API 实例
            api_instance = get_api()
            db = get_db_manager()

            if path == "/api/sessions":
                limit = get_param("limit", 100, int)
                sessions = api_instance.get_sessions(limit)
                self._send_json({
                    "sessions": [
                        {
                            "session_id": s.session_id,
                            "username": s.username,
                            "display_name": s.display_name,
                            "unread_count": s.unread_count,
                            "last_message": s.last_message,
                            "last_time": s.last_time
                        }
                        for s in sessions
                    ]
                })

            elif path.startswith("/api/messages/"):
                session_id = path[len("/api/messages/"):]
                if not session_id:
                    self._send_error("Missing session_id")
                    return

                offset = get_param("offset", 0, int)
                limit = get_param("limit", 100, int)
                start_time = get_param("start_time", 0, int)
                end_time = get_param("end_time", 0, int)

                messages = api_instance.get_messages(session_id, offset, limit, start_time, end_time)
                self._send_json({
                    "session_id": session_id,
                    "messages": [
                        {
                            "msg_id": m.msg_id,
                            "local_id": m.local_id,
                            "sender": m.sender,
                            "sender_name": m.sender_name,
                            "content": m.content,
                            "msg_type": m.msg_type,
                            "sub_type": m.sub_type,
                            "create_time": m.create_time
                        }
                        for m in messages
                    ]
                })

            elif path == "/api/contacts":
                query = get_param("query", "")
                limit = get_param("limit", 100, int)
                contacts = api_instance.get_contacts(query, limit)
                self._send_json({"contacts": contacts})

            elif path == "/api/search":
                keyword = get_param("keyword", "")
                session_id = get_param("session_id", "")
                limit = get_param("limit", 100, int)

                if not keyword:
                    self._send_error("Missing keyword")
                    return

                messages = api_instance.search_messages(keyword, session_id, limit)
                self._send_json({
                    "keyword": keyword,
                    "messages": [
                        {
                            "msg_id": m.msg_id,
                            "local_id": m.local_id,
                            "session_id": m.session_id,
                            "sender": m.sender,
                            "sender_name": m.sender_name,
                            "content": m.content,
                            "create_time": m.create_time
                        }
                        for m in messages
                    ]
                })

            elif path == "/api/stats":
                """获取统计信息"""
                self._send_json({
                    "cached_connections": len(db.connections),
                    "db_dir": DB_DIR,
                    "keys_loaded": len(ALL_KEYS)
                })

            elif path == "/":
                """API 文档"""
                self._send_json({
                    "name": "WeChat Live Server",
                    "version": "1.0.0",
                    "endpoints": [
                        "GET /api/sessions?limit=100",
                        "GET /api/messages/<session_id>?offset=0&limit=100",
                        "GET /api/contacts?query=&limit=100",
                        "GET /api/search?keyword=xxx&session_id=&limit=100",
                        "GET /api/stats",
                        "WS /ws"
                    ]
                })

            else:
                self._send_error("Not found", 404)

        except Exception as e:
            print(f"[HTTP] Error: {e}")
            self._send_error(str(e), 500)

    def do_OPTIONS(self):
        """处理 CORS 预检"""
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_POST(self):
        """处理 POST 请求"""
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        # 读取请求体
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length).decode('utf-8')

        try:
            data = json.loads(body) if body else {}
        except json.JSONDecodeError:
            self._send_error("Invalid JSON", 400)
            return

        try:
            if path == "/api/configure":
                """配置数据库路径和密钥"""
                global DB_DIR, ALL_KEYS

                db_path = data.get('db_path')
                hex_key = data.get('hex_key')
                wxid = data.get('wxid')

                if not db_path or not hex_key:
                    self._send_error("Missing db_path or hex_key", 400)
                    return

                # 更新全局配置
                DB_DIR = os.path.dirname(db_path)
                key_info = parse_key_string(hex_key)
                if key_info:
                    ALL_KEYS = [key_info]

                print(f"[HTTP] Configured: DB_DIR={DB_DIR}, wxid={wxid}")
                self._send_json({
                    "success": True,
                    "db_dir": DB_DIR,
                    "keys_loaded": len(ALL_KEYS)
                })

            else:
                self._send_error("Not found", 404)

        except Exception as e:
            print(f"[HTTP] POST Error: {e}")
            self._send_error(str(e), 500)


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """多线程 HTTP 服务器"""
    daemon_threads = True
    allow_reuse_address = True


# ============ WebSocket 服务器 ============

class WebSocketManager:
    """WebSocket 连接管理器"""

    def __init__(self):
        self.clients: set = set()
        self.clients_lock = asyncio.Lock()
        self.enabled = WEBSOCKETS_AVAILABLE

    async def register(self, websocket):
        """注册客户端"""
        if not self.enabled:
            return
        async with self.clients_lock:
            self.clients.add(websocket)
        print(f"[WebSocket] Client connected, total: {len(self.clients)}")

    async def unregister(self, websocket):
        """注销客户端"""
        if not self.enabled:
            return
        async with self.clients_lock:
            self.clients.discard(websocket)
        print(f"[WebSocket] Client disconnected, total: {len(self.clients)}")

    async def broadcast(self, message: Dict):
        """广播消息给所有客户端"""
        if not self.enabled or not self.clients:
            return

        data = json.dumps(message, ensure_ascii=False)
        disconnected = []

        async with self.clients_lock:
            for client in self.clients:
                try:
                    await client.send(data)
                except websockets.exceptions.ConnectionClosed:
                    disconnected.append(client)
                except Exception as e:
                    print(f"[WebSocket] Send error: {e}")
                    disconnected.append(client)

            # 清理断开的连接
            for client in disconnected:
                self.clients.discard(client)

    async def handle_client(self, websocket, path):
        """处理客户端连接"""
        if not self.enabled:
            return
        await self.register(websocket)
        try:
            async for message in websocket:
                try:
                    data = json.loads(message)
                    await self.handle_message(websocket, data)
                except json.JSONDecodeError:
                    await websocket.send(json.dumps({"error": "Invalid JSON"}))
        except websockets.exceptions.ConnectionClosed:
            pass
        finally:
            await self.unregister(websocket)

    async def handle_message(self, websocket, data: Dict):
        """处理客户端消息"""
        if not self.enabled:
            return
        action = data.get("action")

        if action == "subscribe":
            # 订阅会话更新
            session_id = data.get("session_id")
            await websocket.send(json.dumps({
                "type": "subscribed",
                "session_id": session_id
            }))

        elif action == "get_messages":
            # 获取消息
            session_id = data.get("session_id")
            limit = data.get("limit", 100)
            api_instance = get_api()
            messages = api_instance.get_messages(session_id, limit=limit)
            await websocket.send(json.dumps({
                "type": "messages",
                "session_id": session_id,
                "messages": [
                    {
                        "msg_id": m.msg_id,
                        "local_id": m.local_id,
                        "sender": m.sender,
                        "sender_name": m.sender_name,
                        "content": m.content,
                        "msg_type": m.msg_type,
                        "create_time": m.create_time
                    }
                    for m in messages
                ]
            }))

        elif action == "ping":
            await websocket.send(json.dumps({"type": "pong"}))


ws_manager = WebSocketManager()


# ============ 实时监听线程 ============

class LiveMonitor:
    """实时数据库变更监听器"""

    def __init__(self, ws_manager: WebSocketManager, interval: float = 0.5):
        self.ws_manager = ws_manager
        self.interval = interval
        self.running = False
        self.thread: Optional[threading.Thread] = None
        self.last_session_mtime = 0

    def start(self):
        """启动监听"""
        self.running = True
        self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.thread.start()
        print("[Monitor] Started")

    def stop(self):
        """停止监听"""
        self.running = False
        if self.thread:
            self.thread.join(timeout=2)
        print("[Monitor] Stopped")

    def _monitor_loop(self):
        """监听循环"""
        while self.running:
            try:
                self._check_session_updates()
            except Exception as e:
                print(f"[Monitor] Error: {e}")

            time.sleep(self.interval)

    def _check_session_updates(self):
        """检查会话更新"""
        session_db = os.path.join(DB_DIR, "session", "session.db")
        wal_path = session_db + "-wal"

        try:
            current_mtime = os.path.getmtime(session_db)
            current_wal_mtime = os.path.getmtime(wal_path) if os.path.exists(wal_path) else 0

            if current_mtime != self.last_session_mtime or current_wal_mtime > 0:
                # 同步 WAL
                get_db_manager().get_connection("session/session.db")

                # 检查新消息
                # 简化实现：广播更新事件
                # 使用主线程的事件循环
                try:
                    loop = asyncio.get_event_loop()
                    if loop.is_running():
                        asyncio.run_coroutine_threadsafe(
                            self.ws_manager.broadcast({
                                "type": "update",
                                "source": "session",
                                "timestamp": int(time.time())
                            }),
                            loop
                        )
                except RuntimeError:
                    # 没有事件循环，跳过广播
                    pass

                self.last_session_mtime = current_mtime
        except OSError:
            pass


# ============ 主函数 ============

def run_http_server(host: str, port: int):
    """运行 HTTP 服务器"""
    server = ThreadedHTTPServer((host, port), APIHandler)
    print(f"[HTTP] Server started at http://{host}:{port}")
    server.serve_forever()


async def run_websocket_server(host: str, port: int):
    """运行 WebSocket 服务器"""
    if not WEBSOCKETS_AVAILABLE:
        print("[WebSocket] WebSocket support disabled (websockets module not found)")
        # 保持运行，不退出
        await asyncio.Future()
        return

    async with websockets.serve(ws_manager.handle_client, host, port + 1):
        print(f"[WebSocket] Server started at ws://{host}:{port + 1}")
        await asyncio.Future()  # 永远运行


def main():
    import argparse

    parser = argparse.ArgumentParser(description="WeChat Live Server")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind")
    parser.add_argument("--port", type=int, default=5678, help="HTTP port")
    parser.add_argument("--no-monitor", action="store_true", help="Disable live monitor")
    args = parser.parse_args()

    # 确保配置已加载
    _load_config()

    print("=" * 60)
    print("  WeChat Live Server - Phase 1")
    print("  Real-time decryption query service")
    print("=" * 60)
    print(f"Database: {DB_DIR}")
    print(f"Keys: {len(ALL_KEYS) if ALL_KEYS else 0} loaded")
    print()

    # 启动实时监听
    monitor = None
    if not args.no_monitor:
        monitor = LiveMonitor(ws_manager, interval=0.5)
        monitor.start()

    # 在事件循环中运行 WebSocket 和 HTTP
    loop = asyncio.get_event_loop()

    # 在后台线程运行 HTTP 服务器
    http_thread = threading.Thread(
        target=run_http_server,
        args=(args.host, args.port),
        daemon=True
    )
    http_thread.start()

    try:
        # 在主线程运行 WebSocket 服务器
        loop.run_until_complete(run_websocket_server(args.host, args.port))
    except KeyboardInterrupt:
        print("\n[Server] Shutting down...")
    finally:
        if monitor:
            monitor.stop()
        if db_manager is not None:
            db_manager.close()
        loop.close()


if __name__ == "__main__":
    main()
