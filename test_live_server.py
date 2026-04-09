"""
Live Server 测试脚本

测试实时解密查询服务的功能
"""

import unittest
import os
import sys
import json
import tempfile
import sqlite3
import threading
import time
import urllib.request
import urllib.error

# 添加当前目录到路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from live_server import LiveDBManager, decrypt_page, PAGE_SZ, SQLITE_HDR
from Crypto.Cipher import AES


class TestDecryptFunctions(unittest.TestCase):
    """测试解密函数"""

    def test_decrypt_page_page1(self):
        """测试第 1 页解密"""
        # 创建测试数据
        enc_key = b'\x00' * 32  # 测试密钥
        salt = b'\x01' * 16

        # 构造加密页面
        page = bytearray(PAGE_SZ)
        page[:16] = salt  # salt

        # 加密数据部分
        iv = b'\x02' * 16
        cipher = AES.new(enc_key, AES.MODE_CBC, iv)
        plaintext = b'A' * (PAGE_SZ - 16 - 80)  # 填充数据
        encrypted = cipher.encrypt(plaintext)

        page[16:PAGE_SZ-80] = encrypted
        page[PAGE_SZ-80:PAGE_SZ-64] = iv

        # 解密
        decrypted = decrypt_page(enc_key, bytes(page), 1)

        # 验证 SQLite header
        self.assertEqual(decrypted[:16], SQLITE_HDR)


class TestLiveDBManager(unittest.TestCase):
    """测试 LiveDBManager"""

    def setUp(self):
        """测试前准备"""
        self.temp_dir = tempfile.mkdtemp()
        self.db_manager = LiveDBManager(cache_dir=self.temp_dir)

    def tearDown(self):
        """测试后清理"""
        self.db_manager.close()
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_cache_path_generation(self):
        """测试缓存路径生成"""
        path = self.db_manager._get_cache_path("session/session.db")
        self.assertTrue(path.startswith(self.temp_dir))
        self.assertTrue(path.endswith(".db"))


class TestAPIEndpoints(unittest.TestCase):
    """测试 API 端点 (需要服务器运行)"""

    BASE_URL = "http://127.0.0.1:5678"

    @classmethod
    def setUpClass(cls):
        """启动测试服务器"""
        # 检查服务器是否已在运行
        try:
            urllib.request.urlopen(cls.BASE_URL, timeout=1)
            cls.server_running = True
        except:
            cls.server_running = False
            print("\n[Warning] 测试服务器未运行，跳过 API 测试")
            print("启动服务器: python live_server.py")

    def test_root_endpoint(self):
        """测试根端点"""
        if not self.server_running:
            self.skipTest("服务器未运行")

        try:
            response = urllib.request.urlopen(f"{self.BASE_URL}/")
            data = json.loads(response.read().decode())
            self.assertIn("name", data)
            self.assertEqual(data["name"], "WeChat Live Server")
        except urllib.error.URLError as e:
            self.fail(f"请求失败: {e}")

    def test_stats_endpoint(self):
        """测试统计端点"""
        if not self.server_running:
            self.skipTest("服务器未运行")

        try:
            response = urllib.request.urlopen(f"{self.BASE_URL}/api/stats")
            data = json.loads(response.read().decode())
            self.assertIn("cached_connections", data)
            self.assertIn("db_dir", data)
        except urllib.error.URLError as e:
            self.fail(f"请求失败: {e}")


class TestWebSocket(unittest.TestCase):
    """测试 WebSocket (需要服务器运行)"""

    @classmethod
    def setUpClass(cls):
        """检查服务器"""
        try:
            import websockets
            cls.websockets_available = True
        except ImportError:
            cls.websockets_available = False

    def test_websocket_import(self):
        """测试 websockets 模块是否可用"""
        if not self.websockets_available:
            self.skipTest("websockets 模块未安装")

        import websockets
        self.assertTrue(hasattr(websockets, 'serve'))


def run_tests():
    """运行测试"""
    # 创建测试套件
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    # 添加测试
    suite.addTests(loader.loadTestsFromTestCase(TestDecryptFunctions))
    suite.addTests(loader.loadTestsFromTestCase(TestLiveDBManager))
    suite.addTests(loader.loadTestsFromTestCase(TestAPIEndpoints))
    suite.addTests(loader.loadTestsFromTestCase(TestWebSocket))

    # 运行测试
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    return result.wasSuccessful()


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
