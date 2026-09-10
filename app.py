"""
河北工程大学教务系统 - 课表成绩查询工具
生产级 Flask 后端服务
- 无服务端个人数据缓存（课表、成绩和学业数据仅以加密形式存浏览器 localStorage）
- 仅记录使用过的用户学号和姓名（不记录密码、不记录课表成绩数据）
- 含限流、重试、日志
"""
import re
import json
import time
import base64
import sqlite3
import logging
import secrets
import os
import hashlib
import hmac
import unicodedata
from difflib import SequenceMatcher
from html import unescape
from html.parser import HTMLParser
from collections import defaultdict
from threading import Lock
from pathlib import Path

import requests
from flask import Flask, render_template, request, jsonify, Response
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5, AES
from Crypto.Util.Padding import pad
try:
    from pypinyin import lazy_pinyin
except ImportError:  # 本地未安装时仍允许服务启动，线上依赖会提供拼音搜索
    lazy_pinyin = None

# ========== 日志配置 ==========
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# 公开数据接口的轻量防爬：正常页面请求会自动携带该会话标记，
# 直接批量请求接口则需要先完成页面访问，并受独立频率限制。
PUBLIC_DATA_PATHS = {
    "/api/class-schedule/search",
    "/api/class-schedule/detail",
    "/api/class-schedule/stats",
    "/api/classrooms-cached",
    "/api/classroom-options-cached",
    "/api/classroom-options-public",
    "/api/stats/class-bind",
}
PUBLIC_DATA_LIMIT = 45
PUBLIC_DATA_WINDOW = 60
_public_data_rate = defaultdict(list)
_public_data_rate_lock = Lock()


def _client_ip():
    """获取反向代理后的客户端地址；线上 Nginx 会写入 X-Real-IP。"""
    return request.headers.get("X-Real-IP", request.remote_addr or "unknown").split(",", 1)[0].strip()


def _allow_public_data_request(ip):
    now = time.time()
    with _public_data_rate_lock:
        recent = [stamp for stamp in _public_data_rate[ip] if now - stamp < PUBLIC_DATA_WINDOW]
        if len(recent) >= PUBLIC_DATA_LIMIT:
            _public_data_rate[ip] = recent
            return False
        recent.append(now)
        _public_data_rate[ip] = recent
        return True


@app.before_request
def protect_public_data_apis():
    if request.path not in PUBLIC_DATA_PATHS:
        return None
    if not request.cookies.get("hebeu_client"):
        return jsonify({"success": False, "error": "请从网页进入后再访问"}), 403
    if not _allow_public_data_request(_client_ip()):
        response = jsonify({"success": False, "error": "访问过于频繁，请稍后再试"})
        response.headers["Retry-After"] = str(PUBLIC_DATA_WINDOW)
        return response, 429
    return None


@app.before_request
def block_bad_user_agents():
    """基础反爬：拒绝明显的爬虫UA"""
    if request.path.startswith("/api/") and is_bad_user_agent():
        logger.info(f"拦截爬虫UA: IP={_client_ip()}, UA={request.headers.get('User-Agent', '空')}")
        return jsonify({"success": False, "error": "不支持的客户端"}), 403
    return None


@app.after_request
def prevent_html_cache(response):
    """页面更新后立即对浏览器可见，数据本身仍由前端 localStorage 持久保存。"""
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=()"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    response.headers["X-Permitted-Cross-Domain-Policies"] = "none"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; "
        "form-action 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; connect-src 'self'; font-src 'self'; frame-src 'none'; "
        "upgrade-insecure-requests"
    )
    if request.is_secure or request.headers.get("X-Forwarded-Proto") == "https":
        response.headers["Strict-Transport-Security"] = "max-age=31536000"
    if request.path == "/":
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        if not request.cookies.get("hebeu_client"):
            response.set_cookie(
                "hebeu_client", secrets.token_urlsafe(24), max_age=86400,
                httponly=True, samesite="Lax",
                secure=(request.is_secure or request.headers.get("X-Forwarded-Proto") == "https"),
            )
    if request.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
    if request.path in PUBLIC_DATA_PATHS:
        response.headers["X-Robots-Tag"] = "noindex, nofollow, noarchive"
        response.headers["Cache-Control"] = "no-store"
    return response

# ========== 配置 ==========
BASE_URL = "https://jwglxxfwpt.hebeu.edu.cn"
LOGIN_URL = f"{BASE_URL}/xtgl/login_slogin.html"
PUBLIC_KEY_URL = f"{BASE_URL}/xtgl/login_getPublicKey.html"
SCHEDULE_URL = f"{BASE_URL}/kbcx/xskbcx_cxXsgrkb.html?gnmkdm=N2151"
SCORE_PAGE_URL = f"{BASE_URL}/cjcx/cjcx_cxDgXscj.html?gnmkdm=N305005"
SCORE_URL = f"{BASE_URL}/cjcx/cjcx_cxXsgrcj.html?doType=query&gnmkdm=N305005"
ACADEMIA_PAGE_URL = f"{BASE_URL}/xsxy/xsxyqk_cxXsxyqkIndex.html?gnmkdm=N105515&layout=default"
ACADEMIA_DETAIL_URL = f"{BASE_URL}/xsxy/xsxyqk_cxJxzxjhxfyqKcxx.html?gnmkdm=N105515"
CLASSROOM_PAGE_URL = f"{BASE_URL}/cdjy/cdjy_cxKxcdlb.html?gnmkdm=N2155&layout=default"
CLASSROOM_URL = f"{BASE_URL}/cdjy/cdjy_cxKxcdlb.html?doType=query&gnmkdm=N2155"

DB_PATH = Path(__file__).parent / "users.db"
ADMIN_USER = os.environ.get("HEBEU_ADMIN_USER", "admin")
ADMIN_PASSWORD = os.environ.get("HEBEU_ADMIN_PASSWORD", "")
RATE_LIMIT = 15          # 每IP每分钟最多15次请求
MAX_RETRIES = 2          # 网络请求最大重试次数
REQUEST_TIMEOUT = 20     # 单次请求超时

# 登录失败锁定配置
LOGIN_MAX_FAILS = 5      # 连续失败次数阈值
LOGIN_LOCK_TIME = 900    # 锁定时间（秒）= 15分钟
_login_fails = defaultdict(lambda: {"count": 0, "lock_until": 0})
_login_fails_lock = Lock()

# 基础反爬：拒绝明显的爬虫UA
BAD_UA_PATTERNS = ["python-requests", "curl/", "wget/", "scrapy", "httpx", "aiohttp", "go-http-client", "java/", "okhttp"]

# 接口加密配置（AES-256-CBC）
# 注意：这是轻量级反爬，密钥在前端也有，目的是增加爬虫分析成本，不是真正的安全
API_ENCRYPT_KEY = b"hebeu_schedule_2026_securekey123"  # 32字节
API_ENCRYPT_IV_LEN = 16

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                  "AppleWebKit/537.36 (KHTML, like Gecko) "
                  "Chrome/120.0.0.0 Safari/537.36",
    "Accept": "application/json, text/javascript, */*; q=0.01",
    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
    "Origin": BASE_URL,
    "Referer": LOGIN_URL,
    "X-Requested-With": "XMLHttpRequest",
}

# ========== 数据库初始化 ==========
_db_lock = Lock()

def _derive_floor(room_name):
    """从常见教室编号（如 J02东309、0201）推断楼层，无法判断时留空。"""
    digits = re.findall(r"\d{3,4}", str(room_name or ""))
    if not digits:
        return ""
    number = digits[-1]
    floor = number[0] if len(number) == 3 else number[-3]
    return f"{floor}楼" if floor.isdigit() and floor != "0" else ""

def init_db():
    """初始化用户表和空教室缓存表"""
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                xh TEXT UNIQUE NOT NULL,
                name TEXT DEFAULT '',
                major TEXT DEFAULT '',
                created_at TIMESTAMP DEFAULT (datetime('now', 'localtime')),
                last_used_at TIMESTAMP DEFAULT (datetime('now', 'localtime')),
                use_count INTEGER DEFAULT 1
            )
        """)
        # 为旧库添加major字段
        try:
            conn.execute("ALTER TABLE users ADD COLUMN major TEXT DEFAULT ''")
        except sqlite3.OperationalError:
            pass
        conn.execute("""
            CREATE TABLE IF NOT EXISTS classroom_cache (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cache_key TEXT UNIQUE NOT NULL,
                semester TEXT DEFAULT '',
                campus TEXT DEFAULT '',
                building TEXT DEFAULT '',
                category TEXT DEFAULT '',
                weeks TEXT DEFAULT '',
                weekdays TEXT DEFAULT '',
                sections TEXT DEFAULT '',
                data TEXT NOT NULL,
                total INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT (datetime('now', 'localtime')),
                expires_at TIMESTAMP
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_classroom_cache_key ON classroom_cache(cache_key)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_classroom_cache_expires ON classroom_cache(expires_at)")
        # 班级课表（批量爬取，供专业搜索查询）
        conn.execute("""
            CREATE TABLE IF NOT EXISTS class_schedule (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                semester TEXT NOT NULL,
                xqh_id TEXT,
                njdm_id TEXT,
                jg_id TEXT,
                jgmc TEXT,
                zyh_id TEXT,
                zymc TEXT,
                bh_id TEXT,
                bjmc TEXT,
                pyccmc TEXT,
                course_count INTEGER DEFAULT 0,
                course_data TEXT,
                week_data TEXT,
                status TEXT DEFAULT 'pending',
                error_msg TEXT,
                created_at TIMESTAMP DEFAULT (datetime('now', 'localtime')),
                updated_at TIMESTAMP DEFAULT (datetime('now', 'localtime')),
                UNIQUE(semester, xqh_id, njdm_id, zyh_id, bh_id)
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_class_search ON class_schedule(zymc, bjmc, njdm_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_class_status ON class_schedule(status)")
        # 空教室批量缓存表；旧库没有该表时自动补建，已有库则补充楼层字段。
        conn.execute("""
            CREATE TABLE IF NOT EXISTS classroom_free (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                semester TEXT NOT NULL, week INTEGER NOT NULL,
                weekday INTEGER NOT NULL, section INTEGER NOT NULL,
                campus TEXT, room_id TEXT, room_name TEXT,
                category TEXT, building TEXT, floor TEXT DEFAULT '', seats TEXT,
                created_at TEXT,
                UNIQUE(semester, week, weekday, section, room_id)
            )
        """)
        try:
            conn.execute("ALTER TABLE classroom_free ADD COLUMN floor TEXT DEFAULT ''")
        except sqlite3.OperationalError:
            pass
        conn.execute("CREATE INDEX IF NOT EXISTS idx_classroom_free_query ON classroom_free(semester, week, weekday, section)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_classroom_free_room ON classroom_free(room_name)")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS stats_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TIMESTAMP DEFAULT (datetime('now', 'localtime')),
                event_type TEXT NOT NULL,
                ip_hash TEXT DEFAULT '',
                device_type TEXT DEFAULT '',
                os_name TEXT DEFAULT '',
                browser TEXT DEFAULT '',
                device_model TEXT DEFAULT '',
                xh TEXT DEFAULT '',
                student_name TEXT DEFAULT '',
                major TEXT DEFAULT '',
                class_id INTEGER,
                class_name TEXT DEFAULT '',
                class_major TEXT DEFAULT ''
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_stats_events_time ON stats_events(created_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_stats_events_type ON stats_events(event_type)")
        # 页面访问统计：每次打开首页记录一次，仅保存不可逆 IP 哈希和粗略设备信息。
        conn.execute("""
            CREATE TABLE IF NOT EXISTS page_views (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TIMESTAMP DEFAULT (datetime('now', 'localtime')),
                ip_hash TEXT NOT NULL,
                device_type TEXT DEFAULT '',
                device_model TEXT DEFAULT '',
                os_name TEXT DEFAULT '',
                browser TEXT DEFAULT '',
                referrer TEXT DEFAULT ''
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_page_views_time ON page_views(created_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_page_views_ip_time ON page_views(ip_hash, created_at)")
        # map.suyu.ink 访问统计表
        conn.execute("""
            CREATE TABLE IF NOT EXISTS map_views (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TIMESTAMP DEFAULT (datetime('now', 'localtime')),
                ip_hash TEXT NOT NULL,
                device_type TEXT DEFAULT '',
                device_model TEXT DEFAULT '',
                os_name TEXT DEFAULT '',
                browser TEXT DEFAULT '',
                referrer TEXT DEFAULT '',
                page TEXT DEFAULT ''
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_map_views_time ON map_views(created_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_map_views_ip_time ON map_views(ip_hash, created_at)")
        # 登录失败锁定表（多进程共享）
        conn.execute("""
            CREATE TABLE IF NOT EXISTS login_fails (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_xh TEXT UNIQUE NOT NULL,
                fail_count INTEGER DEFAULT 0,
                lock_until INTEGER DEFAULT 0,
                updated_at TIMESTAMP DEFAULT (datetime('now', 'localtime'))
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_login_fails_key ON login_fails(ip_xh)")
        # 为旧版爬虫留下的记录回填楼层，后续新数据由爬虫直接写入。
        old_rooms = conn.execute("SELECT id, room_name FROM classroom_free WHERE COALESCE(TRIM(floor), '') = ''").fetchall()
        for room_id, room_name in old_rooms:
            floor = _derive_floor(room_name)
            if floor:
                conn.execute("UPDATE classroom_free SET floor = ? WHERE id = ?", (floor, room_id))
        conn.commit()
    # 用户学号和教室缓存属于敏感数据，避免同机其他账号直接读取 SQLite 文件。
    try:
        DB_PATH.chmod(0o600)
        for suffix in ("-wal", "-shm"):
            sidecar = Path(f"{DB_PATH}{suffix}")
            if sidecar.exists():
                sidecar.chmod(0o600)
    except OSError as exc:
        logger.warning(f"无法收紧数据库文件权限: {exc}")
    logger.info(f"数据库初始化完成: {DB_PATH}")

# ========== 公共Session管理（空教室查询免登录） ==========
_public_session = None
_public_session_lock = Lock()
PUBLIC_XH = os.environ.get("HEBEU_PUBLIC_XH", "").strip()
PUBLIC_PWD = os.environ.get("HEBEU_PUBLIC_PWD", "")
CACHE_TTL_HOURS = 24  # 空教室缓存24小时

def _get_public_session():
    """获取公共登录session，过期自动重登"""
    global _public_session
    with _public_session_lock:
        if not PUBLIC_XH or not PUBLIC_PWD:
            logger.error("公共空教室查询凭据未配置")
            return None
        if _public_session is None:
            try:
                _public_session = login_to_edu_system(PUBLIC_XH, PUBLIC_PWD)
                logger.info("公共session登录成功")
            except Exception as e:
                logger.error(f"公共session登录失败: {e}")
                raise
        return _public_session

def _refresh_public_session():
    """强制刷新公共session"""
    global _public_session
    with _public_session_lock:
        if not PUBLIC_XH or not PUBLIC_PWD:
            logger.error("公共空教室查询凭据未配置")
            return None
        try:
            _public_session = login_to_edu_system(PUBLIC_XH, PUBLIC_PWD)
            logger.info("公共session刷新成功")
        except Exception as e:
            logger.error(f"公共session刷新失败: {e}")
            raise

def _cache_key(semester, campus, building, category, weeks, weekdays, sections):
    """生成缓存key"""
    return f"{semester}|{campus}|{building}|{category}|{weeks}|{weekdays}|{sections}"

def _get_classroom_cache(cache_key):
    """从数据库读取空教室缓存，未过期返回数据"""
    try:
        with sqlite3.connect(DB_PATH) as conn:
            row = conn.execute(
                "SELECT data, total, expires_at FROM classroom_cache WHERE cache_key = ?",
                (cache_key,)
            ).fetchone()
            if row:
                data_json, total, expires_at = row
                # 检查是否过期
                if expires_at:
                    from datetime import datetime
                    if datetime.strptime(expires_at, "%Y-%m-%d %H:%M:%S") > datetime.now():
                        return {"data": json.loads(data_json), "total": total}
        return None
    except Exception as e:
        logger.warning(f"读取空教室缓存失败: {e}")
        return None

def _set_classroom_cache(cache_key, semester, campus, building, category, weeks, weekdays, sections, data, total):
    """写入空教室缓存"""
    try:
        from datetime import datetime, timedelta
        expires_at = (datetime.now() + timedelta(hours=CACHE_TTL_HOURS)).strftime("%Y-%m-%d %H:%M:%S")
        with _db_lock, sqlite3.connect(DB_PATH) as conn:
            conn.execute(
                """INSERT OR REPLACE INTO classroom_cache 
                   (cache_key, semester, campus, building, category, weeks, weekdays, sections, data, total, expires_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (cache_key, semester, campus, building, category, weeks, weekdays, sections,
                 json.dumps(data, ensure_ascii=False), total, expires_at)
            )
            conn.commit()
        logger.info(f"空教室缓存写入: {cache_key} (共{total}间)")
    except Exception as e:
        logger.warning(f"写入空教室缓存失败: {e}")

def record_user(xh: str, name: str = "", major: str = ""):
    """记录用户基础信息；密码、课表、成绩不落库。name为空时不覆盖已有姓名。"""
    try:
        with _db_lock, sqlite3.connect(DB_PATH) as conn:
            cursor = conn.execute("SELECT id, use_count, name FROM users WHERE xh = ?", (xh,))
            row = cursor.fetchone()
            if row:
                if name:
                    conn.execute(
                        "UPDATE users SET name = ?, major = ?, last_used_at = datetime('now', 'localtime'), use_count = ? WHERE xh = ?",
                        (name, major, row[1] + 1, xh)
                    )
                else:
                    conn.execute(
                        "UPDATE users SET last_used_at = datetime('now', 'localtime'), use_count = ? WHERE xh = ?",
                        (row[1] + 1, xh)
                    )
            else:
                conn.execute(
                    "INSERT INTO users (xh, name, major, created_at, last_used_at) VALUES (?, ?, ?, datetime('now', 'localtime'), datetime('now', 'localtime'))",
                    (xh, name, major)
                )
            conn.commit()
    except Exception as e:
        logger.error(f"记录用户失败: {e}")

STATS_IP_SALT = os.environ.get("HEBEU_STATS_IP_SALT", "local-development-salt").encode()

def _device_summary(user_agent: str) -> dict:
    ua = (user_agent or "").lower()
    # 先判断移动设备，避免iPhone/iPad的UA里的"Mac OS"被误判成macOS
    if "iphone" in ua:
        device_type, model = "mobile", "iPhone"
        os_name = "iOS"
    elif "ipad" in ua:
        device_type, model = "tablet", "iPad"
        os_name = "iPadOS"
    elif "android" in ua:
        device_type = "mobile"
        os_name = "Android"
        # 尝试从UA提取Android手机型号，格式通常是 "Android 13; Pixel 7 Build/..."
        model = "Android设备"
        try:
            import re as _re
            # 匹配 "Android X.Y; 型号 Build/" 或 "Android X.Y; 型号)"
            m = _re.search(r'android\s+[\d.]+\s*;\s*([^;)]+?)(?:\s+build/|\))', user_agent, _re.IGNORECASE)
            if m:
                raw_model = m.group(1).strip()
                # 清理型号名称，去掉多余空格
                model = ' '.join(raw_model.split())[:60] or "Android设备"
        except Exception:
            pass
    else:
        device_type, model = "desktop", "电脑"
        if "mac os" in ua:
            os_name = "macOS"
        elif "windows" in ua:
            os_name = "Windows"
        elif "linux" in ua:
            os_name = "Linux"
        else:
            os_name = "其他"

    if "edg" in ua:
        browser = "Edge"
    elif "chrome" in ua:
        browser = "Chrome"
    elif "safari" in ua and "chrome" not in ua:
        browser = "Safari"
    elif "firefox" in ua:
        browser = "Firefox"
    elif "micromessenger" in ua or "wechat" in ua:
        browser = "微信"
    elif "qq" in ua:
        browser = "QQ"
    else:
        browser = "其他"

    return {"device_type": device_type, "device_model": model, "browser": browser, "os_name": os_name}

def record_stats_event(event_type: str, *, xh="", student_name="", major="", class_id=None, class_name="", class_major=""):
    """写入最小化统计信息，不保存原始 IP、完整 UA 或密码。"""
    ip = _client_ip()
    ip_hash = hmac.new(STATS_IP_SALT, ip.encode(), hashlib.sha256).hexdigest()
    device = _device_summary(request.headers.get("User-Agent", ""))
    try:
        with _db_lock, sqlite3.connect(DB_PATH) as conn:
            conn.execute("""
                INSERT INTO stats_events
                (created_at, event_type, ip_hash, device_type, os_name, browser, device_model,
                 xh, student_name, major, class_id, class_name, class_major)
                VALUES (datetime('now', 'localtime'), ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (event_type, ip_hash, device["device_type"], device["os_name"],
                  device["browser"], device["device_model"], xh, student_name,
                  major, class_id, class_name, class_major))
            conn.commit()
    except Exception as exc:
        logger.warning(f"统计记录失败: {exc}")

def record_page_view():
    """记录一次首页打开；不保存原始 IP 和完整 User-Agent。"""
    ip = _client_ip()
    ip_hash = hmac.new(STATS_IP_SALT, ip.encode(), hashlib.sha256).hexdigest()
    device = _device_summary(request.headers.get("User-Agent", ""))
    try:
        with _db_lock, sqlite3.connect(DB_PATH) as conn:
            conn.execute("""
                INSERT INTO page_views
                (ip_hash, device_type, device_model, os_name, browser, referrer)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (ip_hash, device["device_type"], device["device_model"],
                  device["os_name"], device["browser"],
                  request.headers.get("Referer", "")[:500]))
            conn.commit()
    except Exception as exc:
        logger.warning(f"页面访问统计失败: {exc}")

# ========== IP 限流 ==========
_rate_limit = defaultdict(list)
_rate_lock = Lock()

def check_rate_limit(ip: str) -> bool:
    now = time.time()
    with _rate_lock:
        _rate_limit[ip] = [t for t in _rate_limit[ip] if now - t < 60]
        if len(_rate_limit[ip]) >= RATE_LIMIT:
            return False
        _rate_limit[ip].append(now)
        return True


def check_login_lock(ip: str, xh: str) -> tuple[bool, str]:
    """检查登录是否被锁定，返回(是否允许, 提示信息)"""
    key = f"{ip}:{xh}"
    now = int(time.time())
    try:
        with sqlite3.connect(DB_PATH) as conn:
            row = conn.execute(
                "SELECT fail_count, lock_until FROM login_fails WHERE ip_xh = ?",
                (key,)
            ).fetchone()
            if row and row[1] > now:
                remain = row[1] - now
                return False, f"登录失败次数过多，请{remain // 60}分钟后再试"
    except Exception as e:
        logger.error(f"检查登录锁定失败: {e}")
    return True, ""


def record_login_fail(ip: str, xh: str):
    """记录一次登录失败"""
    key = f"{ip}:{xh}"
    now = int(time.time())
    try:
        with sqlite3.connect(DB_PATH) as conn:
            row = conn.execute(
                "SELECT fail_count, lock_until FROM login_fails WHERE ip_xh = ?",
                (key,)
            ).fetchone()
            if row:
                count = row[0] + 1 if row[1] <= now else row[0]
                lock_until = now + LOGIN_LOCK_TIME if count >= LOGIN_MAX_FAILS else 0
                conn.execute(
                    "UPDATE login_fails SET fail_count = ?, lock_until = ?, updated_at = CURRENT_TIMESTAMP WHERE ip_xh = ?",
                    (count, lock_until, key)
                )
            else:
                count = 1
                lock_until = now + LOGIN_LOCK_TIME if count >= LOGIN_MAX_FAILS else 0
                conn.execute(
                    "INSERT INTO login_fails (ip_xh, fail_count, lock_until) VALUES (?, ?, ?)",
                    (key, count, lock_until)
                )
            conn.commit()
            if count >= LOGIN_MAX_FAILS:
                logger.warning(f"登录锁定: IP={ip}, 学号={xh}, 失败{count}次")
    except Exception as e:
        logger.error(f"记录登录失败失败: {e}")


def reset_login_fail(ip: str, xh: str):
    """登录成功后重置失败计数"""
    key = f"{ip}:{xh}"
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute("DELETE FROM login_fails WHERE ip_xh = ?", (key,))
            conn.commit()
    except Exception as e:
        logger.error(f"重置登录失败计数失败: {e}")


def is_bad_user_agent() -> bool:
    """基础反爬：检查User-Agent是否为明显的爬虫"""
    ua = request.headers.get("User-Agent", "").lower()
    if not ua:
        return True
    for pattern in BAD_UA_PATTERNS:
        if pattern in ua:
            return True
    return False

# ========== 带重试的请求 ==========
def _request_with_retry(session, method: str, url: str, **kwargs) -> requests.Response:
    last_error = None
    for attempt in range(MAX_RETRIES):
        try:
            return session.request(method, url, timeout=REQUEST_TIMEOUT, **kwargs)
        except requests.RequestException as e:
            last_error = e
            if attempt < MAX_RETRIES - 1:
                logger.warning(f"请求重试 {attempt+1}/{MAX_RETRIES}: {url}")
                time.sleep(1)
    raise last_error

# ========== RSA 加密 ==========
def rsa_encrypt_password(password: str, modulus_b64: str, exponent_b64: str) -> str:
    modulus_bytes = base64.b64decode(modulus_b64)
    exponent_bytes = base64.b64decode(exponent_b64)
    modulus_int = int.from_bytes(modulus_bytes, "big")
    exponent_int = int.from_bytes(exponent_bytes, "big")
    rsa_key = RSA.construct((modulus_int, exponent_int))
    cipher = PKCS1_v1_5.new(rsa_key)
    encrypted_bytes = cipher.encrypt(password.encode("utf-8"))
    return base64.b64encode(encrypted_bytes).decode("utf-8")

# ========== AES 接口加密 ==========
def aes_encrypt_data(data) -> dict:
    """AES-256-CBC加密数据，返回{iv, data}的base64编码"""
    plaintext = json.dumps(data, ensure_ascii=False).encode("utf-8")
    iv = secrets.token_bytes(API_ENCRYPT_IV_LEN)
    cipher = AES.new(API_ENCRYPT_KEY, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    return {
        "iv": base64.b64encode(iv).decode("utf-8"),
        "data": base64.b64encode(ciphertext).decode("utf-8"),
        "encrypted": True
    }

def encrypted_response(data, **kwargs):
    """返回加密后的JSON响应"""
    return jsonify(aes_encrypt_data(data), **kwargs)

# ========== 登录 ==========
def login_to_edu_system(xh: str, pwd: str) -> requests.Session:
    session = requests.Session()
    session.headers.update(HEADERS)

    resp = _request_with_retry(session, "GET", LOGIN_URL)
    csrf_match = re.search(r'name="csrftoken"\s+value="([^"]*)"', resp.text)
    if not csrf_match:
        csrf_match = re.search(r'id="csrftoken"\s+value="([^"]*)"', resp.text)
    csrftoken = csrf_match.group(1) if csrf_match else ""

    pub_resp = _request_with_retry(
        session, "GET", f"{PUBLIC_KEY_URL}?time={int(time.time() * 1000)}"
    )
    pub_data = pub_resp.json()
    encrypted_pwd = rsa_encrypt_password(pwd, pub_data["modulus"], pub_data["exponent"])

    login_data = {
        "csrftoken": csrftoken, "language": "zh_CN", "ydType": "",
        "yhm": xh, "mm": encrypted_pwd,
    }
    resp = _request_with_retry(
        session, "POST", f"{LOGIN_URL}?time={int(time.time() * 1000)}",
        data=login_data, allow_redirects=True
    )

    if "用户名或密码不正确" in resp.text:
        raise ValueError("用户名或密码错误")
    if "login_slogin" in resp.url:
        raise ValueError("登录失败，请检查学号和密码")

    logger.info(f"用户登录成功: {xh}")
    return session

# ========== 课表查询 ==========
def fetch_schedule(session: requests.Session, xnm: str, xqm: str) -> dict:
    session.headers.update({
        "Referer": f"{BASE_URL}/kbcx/xskbcx_cxXskbcxIndex.html?gnmkdm=N2151&layout=default",
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
    })
    resp = _request_with_retry(
        session, "POST", SCHEDULE_URL,
        data={"xnm": xnm, "xqm": xqm, "kzlx": "ck", "xsdm": "", "kclbdm": "", "kclxdm": ""}
    )
    resp.raise_for_status()
    return resp.json()

def parse_courses(raw_data: dict) -> dict:
    result = {"student": {}, "courses": [], "practice": []}
    xsxx = raw_data.get("xsxx", {})
    result["student"] = {
        "name": xsxx.get("XM", ""), "xh": xsxx.get("XH", ""),
        "class": xsxx.get("BJMC", ""), "major": xsxx.get("ZYMC", ""),
        "college": xsxx.get("YXMC", ""), "year": xsxx.get("XNMC", ""),
        "term": xsxx.get("XQMMC", ""),
    }
    for item in raw_data.get("kbList", []):
        course = {
            "name": item.get("kcmc", ""), "teacher": item.get("xm", ""),
            "room": item.get("cdmc", ""), "weekday": item.get("xqj", ""),
            "weekday_name": item.get("xqjmc", ""), "section": item.get("jc", ""),
            "section_start": "", "section_end": "",
            "weeks": item.get("zcd", ""), "credit": item.get("xf", ""),
            "exam_type": item.get("khfsmc", ""), "course_type": item.get("kclb", ""),
            "class_name": item.get("jxbmc", ""), "campus": item.get("xqmc", ""),
        }
        jc = item.get("jcor", item.get("jc", ""))
        match = re.match(r"(\d+)[-~](\d+)", str(jc))
        if match:
            course["section_start"] = int(match.group(1))
            course["section_end"] = int(match.group(2))
        else:
            course["section_start"] = 1
            course["section_end"] = 2
        result["courses"].append(course)
    for item in raw_data.get("sjkList", []):
        result["practice"].append({
            "name": item.get("kcmc", ""), "teacher": item.get("jsxm", ""),
            "weeks": item.get("qsjsz", ""), "credit": item.get("xf", ""),
            "exam_type": item.get("khfsmc", ""),
        })
    return result

# ========== 成绩查询 ==========
def fetch_scores(session: requests.Session) -> dict:
    _request_with_retry(session, "GET", SCORE_PAGE_URL)
    session.headers.update({
        "Referer": SCORE_PAGE_URL,
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
    })
    resp = _request_with_retry(
        session, "POST", SCORE_URL,
        data={
            "xnm": "", "xqm": "", "_search": "false",
            "nd": str(int(time.time() * 1000)),
            "queryModel.showCount": "200", "queryModel.currentPage": "1",
            "queryModel.sortName": "", "queryModel.sortOrder": "asc", "time": "0",
        }
    )
    resp.raise_for_status()
    return resp.json()

def parse_scores(raw_data: dict) -> dict:
    items = raw_data.get("items", [])
    result = {
        "student": {}, "terms": {},
        "summary": {"total_courses": 0, "total_credits": 0.0, "weighted_gpa": 0.0,
                    "avg_score": 0.0, "passed": 0, "failed": 0}
    }
    total_xfjd = total_xf = total_score = 0.0
    count = 0
    for item in items:
        xnmmc = item.get("xnmmc", "")
        xqmmc = item.get("xqmmc", "")
        term_key = f"{xnmmc}学年第{xqmmc}学期" if xnmmc else "未知学期"
        course = {
            "name": item.get("kcmc", "").strip(),
            "score": item.get("cj", item.get("bfzcj", "")),
            "gpa": item.get("jd", ""), "credit": item.get("xf", ""),
            "xfjd": item.get("xfjd", ""), "course_nature": item.get("kcxzmc", ""),
            "exam_type": item.get("khfsmc", ""), "category": item.get("kclbmc", ""),
            "teacher": item.get("jsxm", ""), "class_name": item.get("jxbmc", ""),
            "college": item.get("kkbmmc", ""), "year": xnmmc, "term": xqmmc,
        }
        result["terms"].setdefault(term_key, []).append(course)
        count += 1
        try:
            sv = float(course["score"]) if course["score"] else 0
            cv = float(course["credit"]) if course["credit"] else 0
            xv = float(course["xfjd"]) if course["xfjd"] else 0
            total_score += sv; total_xf += cv; total_xfjd += xv
            result["summary"]["passed" if sv >= 60 else "failed"] += 1
        except (ValueError, TypeError):
            pass
    if items:
        result["student"] = {
            "name": items[0].get("xm", ""), "xh": items[0].get("xh", ""),
            "class": items[0].get("bj", ""), "major": items[0].get("zymc", ""),
            "college": items[0].get("jgmc", ""),
        }
    result["summary"]["total_courses"] = count
    result["summary"]["total_credits"] = round(total_xf, 2)
    result["summary"]["weighted_gpa"] = round(total_xfjd / total_xf, 2) if total_xf > 0 else 0
    result["summary"]["avg_score"] = round(total_score / count, 2) if count > 0 else 0
    result["terms"] = dict(sorted(result["terms"].items(), key=lambda x: x[0], reverse=True))
    return result

# ========== 学业情况与空教室查询 ==========
class _TableParser(HTMLParser):
    """把教务系统返回的表格转成轻量 rows，避免新增 HTML 解析依赖。"""
    def __init__(self):
        super().__init__()
        self.rows, self.row, self.cell = [], None, None
        self.in_cell = False

    def handle_starttag(self, tag, attrs):
        if tag == "tr": self.row = []
        elif tag in ("td", "th") and self.row is not None:
            self.cell = []
            self.in_cell = True

    def handle_data(self, data):
        if self.in_cell and self.cell is not None:
            self.cell.append(data)

    def handle_endtag(self, tag):
        if tag in ("td", "th") and self.in_cell and self.row is not None:
            value = re.sub(r"\s+", " ", unescape("".join(self.cell))).strip()
            self.row.append(value)
            self.cell, self.in_cell = None, False
        elif tag == "tr" and self.row is not None:
            if any(self.row): self.rows.append(self.row)
            self.row = None

def _parse_tables(text: str):
    parser = _TableParser()
    parser.feed(text)
    return parser.rows

def _is_login_page(resp: requests.Response) -> bool:
    return "login_slogin" in resp.url or "用户登录" in resp.text[:12000]

def _number(value):
    try:
        return float(str(value).replace(",", ""))
    except (TypeError, ValueError):
        return None

def _parse_select_options(html):
    """读取原站下拉框的 value/label，提交时使用原站 value。"""
    result = {"campus": [], "building": [], "category": [], "weeks": [], "weekdays": [], "sections": []}
    for attrs, body in re.findall(r"<select\b([^>]*)>(.*?)</select>", html, re.S | re.I):
        text = attrs.lower()
        if any(token in text for token in ("xqh", "xq_id", "campus", "校区")): key = "campus"
        elif any(token in text for token in ("lh", "jxl", "building", "楼号")): key = "building"
        elif any(token in text for token in ("cdlb", "category", "场地类别")): key = "category"
        elif any(token in text for token in ("zc", "weeks", "周次")): key = "weeks"
        elif any(token in text for token in ("xqj", "weekday", "星期")): key = "weekdays"
        elif any(token in text for token in ("jcd", "section", "节次")): key = "sections"
        else: continue
        for option_attrs, option_body in re.findall(r"<option\b([^>]*)>(.*?)</option>", body, re.S | re.I):
            value_match = re.search(r"\bvalue\s*=\s*['\"]([^'\"]*)", option_attrs, re.I)
            value = value_match.group(1).strip() if value_match else re.sub(r"<[^>]+>", "", option_body).strip()
            label = re.sub(r"<[^>]+>", "", unescape(option_body))
            label = re.sub(r"\s+", " ", label).strip()
            if label and not any(item["value"] == value for item in result[key]):
                result[key].append({"value": value, "label": label})
    return result

def _pick(item, *keys):
    """从正方接口常见的大小写/中文字段中取第一个非空值。"""
    if not isinstance(item, dict):
        return ""
    for key in keys:
        value = item.get(key)
        if value not in (None, ""):
            return str(value).strip()
    return ""

def _course_items(value):
    """递归提取详情接口中嵌套在 list/data/rows 里的课程对象。"""
    found = []
    if isinstance(value, list):
        for child in value:
            found.extend(_course_items(child))
    elif isinstance(value, dict):
        course_keys = {"KCMC", "kcmc", "课程名称", "KCH", "kch", "课程代码"}
        if any(key in value for key in course_keys):
            found.append(value)
        else:
            for child in value.values():
                found.extend(_course_items(child))
    return found

def _course_from_item(item):
    status = _pick(item, "XDZTMC", "XKZTMC", "XKZT", "修读状态", "状态", "xkztmc", "xkzt")
    raw_status = _pick(item, "XDZT", "xdzt")
    status = status or {"1": "未修", "2": "在修", "3": "未过", "4": "已修", "5": "学分已满", "6": "学分超出", "7": "学分未满", "8": "课程替代", "9": "节点未过"}.get(raw_status, raw_status)
    category = _pick(item, "KCLBMC", "KCLB", "课程类别", "KCXZMC", "KCXZ", "kclbmc", "kcxzmc")
    return {
        "course_id": _pick(item, "KCH", "kch", "课程代码"),
        "title": _pick(item, "KCMC", "kcmc", "课程名称"),
        "status": status or "未知",
        "category": category,
        "term": _pick(item, "JYXDXQMC", "XQMM", "xqmmc", "学期"),
        "credit": _pick(item, "XF", "xf", "学分"),
        "nature": _pick(item, "KCXZMC", "kcxzmc", "课程性质"),
        "grade": _pick(item, "MAXCJ", "CJ", "cj", "成绩"),
        "gpa": _pick(item, "JD", "jd", "绩点"),
    }

def _academia_type_stats(html):
    """从页面HTML属性和JS字符串中提取课程组名称、学分和详情id。
    正方教务的学业情况页面结构：
    <li ... xfyqjd_id='XXX' ...><p ... yxxf='148.5' yqzdxf='177.5' ...> "主修&nbsp;" + ...
    """
    result = []
    seen_ids = set()

    # 找到所有 xfyqjd_id 的位置
    for m in re.finditer(r"xfyqjd_id\s*=\s*['\"]([^'\"]+)['\"]", html, re.I):
        ident = m.group(1).strip()
        if not ident or ident in seen_ids:
            continue
        # 在该位置后 800 字符内查找 yqzdxf、yxxf 和课程组名称
        fragment = html[m.start():m.start() + 800]

        # 查找要求学分 yqzdxf
        req_match = re.search(r"yqzdxf\s*=\s*['\"]([^'\"]*)['\"]", fragment, re.I)
        required = req_match.group(1).strip() if req_match else ""

        # 查找已修学分 yxxf
        earned_match = re.search(r"yxxf\s*=\s*['\"]([^'\"]*)['\"]", fragment, re.I)
        earned = earned_match.group(1).strip() if earned_match else ""

        # 查找课程组名称：直接匹配 "中文&nbsp;" 格式（JS字符串拼接中的课程组名）
        name = ""
        # 在整个 fragment 里找 "中文&nbsp;" 格式
        for name_match in re.finditer(r'"([\u4e00-\u9fa5A-Za-z0-9（）()·]{2,20})&nbsp;"', fragment):
            name = name_match.group(1)
            break

        if not name:
            # 备用：找 p 标签里包含中文的文本
            for p_match in re.finditer(r"<p[^>]*>([^<]+)", fragment):
                candidate = p_match.group(1).replace('&nbsp;', '').replace('&nbsp', '')
                candidate = unescape(candidate)
                candidate = re.sub(r'[\s\xa0]+', '', candidate).strip('"\' +')
                if candidate and re.search(r'[\u4e00-\u9fa5]', candidate) and 2 <= len(candidate) <= 20:
                    name = candidate
                    break

        if not name:
            name = f"课程组{len(result) + 1}"

        # 计算未获得学分
        try:
            missing = str(round(float(required) - float(earned), 1)) if required and earned else ""
        except (ValueError, TypeError):
            missing = ""

        seen_ids.add(ident)
        result.append({
            "id": ident,
            "name": name,
            "required": required,
            "earned": earned,
            "missing": missing,
        })

    return result

def parse_academia(main_html: str, detail_payloads: list[dict], requirements: list[dict] = None) -> dict:
    sid_match = re.search(r'id=["\']xh_id["\'][^>]*value=["\']([^"\']+)', main_html)
    alert_match = re.search(r'<div[^>]+id=["\']alertBox["\'][^>]*>(.*?)</div>', main_html, re.S | re.I)
    alert_text = re.sub(r"<[^>]+>", " ", alert_match.group(1)) if alert_match else ""
    alert_text = re.sub(r"\s+", " ", unescape(alert_text)).strip()
    statistics = []
    for label, value in re.findall(r"([^：:]{2,16})\s*[：:]\s*([0-9]+(?:\.[0-9]+)?)", alert_text):
        statistics.append({"label": label.strip(), "value": value})

    details = []
    for payload in detail_payloads:
        type_name = payload.get("type", "课程要求")
        rows = payload.get("rows", [])
        courses = [_course_from_item(item) for item in _course_items(payload.get("json"))]
        details.append({"type": type_name, "courses": courses, "rows": rows})
    return {
        "student_id": sid_match.group(1) if sid_match else "",
        "statistics": statistics,
        "requirements": requirements or [],
        "details": details,
    }

def fetch_academia(session: requests.Session) -> dict:
    session.headers.update({"Referer": ACADEMIA_PAGE_URL})
    main = _request_with_retry(session, "GET", ACADEMIA_PAGE_URL)
    main.raise_for_status()
    if _is_login_page(main): raise ValueError("教务系统登录已过期，请重新登录")
    type_stats = _academia_type_stats(main.text)
    types = [(item["id"], item["name"]) for item in type_stats]
    id_pattern = re.compile(r"(?:xfyqjd_id|xfyqjdId)[^>]{0,220}", re.I)
    for match in id_pattern.finditer(main.text):
        fragment = match.group(0)
        value_match = re.search(r"(?:value|data-id|id)\s*=\s*['\"]([^'\"]+)", fragment, re.I)
        if not value_match:
            value_match = re.search(r"['\"]([^'\"]+)['\"]", fragment.split("=", 1)[-1])
        ident = value_match.group(1) if value_match else ""
        if ident and ident not in {x[0] for x in types}:
            types.append((ident, f"课程明细 {len(types) + 1}"))
    payloads = []
    for ident, name in types:
        detail = _request_with_retry(session, "POST", ACADEMIA_DETAIL_URL, data={"xfyqjd_id": ident})
        detail.raise_for_status()
        try: parsed = detail.json()
        except ValueError: parsed = None
        payloads.append({"type": name, "json": parsed if isinstance(parsed, list) else None, "rows": _parse_tables(detail.text)})
    result = parse_academia(main.text, payloads, requirements=type_stats)
    if not result["details"]:
        result["details"] = [{"type": "课程明细", "courses": [], "rows": _parse_tables(main.text)}]
    return result

def _to_bitmask(values) -> int:
    """把逗号分隔的数字列表转换成正方教务的位运算值。
    选第n项 = 2^(n-1)，多选相加。
    """
    if not values:
        return 0
    result = 0
    for v in str(values).split(","):
        v = v.strip()
        if v.isdigit() and int(v) > 0:
            result += 2 ** (int(v) - 1)
    return result

def fetch_classrooms(session: requests.Session, query: dict) -> dict:
    session.headers.update({"Referer": CLASSROOM_PAGE_URL, "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"})
    page = _request_with_retry(session, "GET", CLASSROOM_PAGE_URL)
    page.raise_for_status()
    if _is_login_page(page): raise ValueError("教务系统登录已过期，请重新登录")

    # 从页面隐藏字段获取当前学期
    xnm_match = re.search(r'name=["\']xnm["\'][^>]*value=["\']([^"\']+)', page.text)
    xqm_match = re.search(r'name=["\']xqm["\'][^>]*value=["\']([^"\']+)', page.text)
    xnm = xnm_match.group(1) if xnm_match else query.get("xnm", "2026")
    xqm = xqm_match.group(1) if xqm_match else query.get("xqm", "3")

    data = {
        "xqh_id": query.get("campus", ""),
        "xnm": xnm,
        "xqm": xqm,
        "lh": query.get("building", ""),
        "cdlb_id": query.get("category", ""),
        "cdejlb_id": query.get("borrow_type", ""),
        "qszws": query.get("min_seats", ""),
        "jszws": query.get("max_seats", ""),
        "cdmc": query.get("name", ""),
        "cd_id": "",
        "jyfs": "0",  # 按周次
        "cdjylx": "",
        "zcd": str(_to_bitmask(query.get("weeks", ""))),
        "xqj": query.get("weekdays", ""),
        "jcd": str(_to_bitmask(query.get("sections", ""))),
        "_search": "false",
        "queryModel.showCount": str(query.get("show_count", 100)),
        "queryModel.currentPage": "1",
        "queryModel.sortName": "",
        "queryModel.sortOrder": "asc",
        "time": "0",
        "nd": str(int(time.time() * 1000)),
    }
    resp = _request_with_retry(session, "POST", CLASSROOM_URL, data=data)
    resp.raise_for_status()
    if _is_login_page(resp): raise ValueError("教务系统登录已过期，请重新登录")
    try:
        raw = resp.json()
        if isinstance(raw, list):
            items = raw
        elif isinstance(raw, dict):
            items = raw.get("items") or raw.get("rows") or raw.get("data") or []
            if isinstance(items, dict): items = items.get("items") or items.get("rows") or []
        else:
            items = []
    except ValueError:
        raw, items = None, []
    rows = _parse_tables(resp.text) if not items else []
    classrooms = []
    for item in items:
        classrooms.append({
            "code": item.get("cdbh", item.get("cd_id", "")),
            "name": item.get("cdmc", ""),
            "campus": item.get("xqmc", ""),
            "category": item.get("cdlbmc", ""),
            "seats": item.get("zws", ""),
            "building": item.get("jxlmc", item.get("lh", "")),
            "floor": item.get("lc", ""),
            "available": item.get("sfkjy", item.get("sfdkyy", "")),
        })
    total = raw.get("totalResult", len(classrooms)) if isinstance(raw, dict) else len(classrooms)
    return {"query": query, "classrooms": classrooms, "rows": rows, "total": total}

def fetch_classroom_options(session: requests.Session) -> dict:
    session.headers.update({"Referer": CLASSROOM_PAGE_URL})
    page = _request_with_retry(session, "GET", CLASSROOM_PAGE_URL)
    page.raise_for_status()
    if _is_login_page(page): raise ValueError("教务系统登录已过期，请重新登录")
    html = page.text

    def extract_select(name):
        pattern = re.compile(r'<select\b[^>]*name\s*=\s*["\']' + re.escape(name) + r'["\'][^>]*>(.*?)</select>', re.S | re.I)
        m = pattern.search(html)
        if not m:
            return []
        options = []
        for opt in re.finditer(r'<option[^>]*value=["\']([^"\']*)["\'][^>]*>([^<]*)</option>', m.group(1), re.I):
            val, label = opt.group(1), opt.group(2).strip()
            if label:
                options.append({"value": val, "label": label})
        return options

    # 从页面隐藏字段获取当前学期
    xnm_match = re.search(r'name=["\']xnm["\'][^>]*value=["\']([^"\']+)', html)
    xqm_match = re.search(r'name=["\']xqm["\'][^>]*value=["\']([^"\']+)', html)

    return {
        "campus": extract_select("xqh_id"),
        "building": extract_select("lh"),
        "category": extract_select("cdlb_id"),
        "borrow_type": extract_select("cdejlb_id"),
        "current_xnm": xnm_match.group(1) if xnm_match else "2026",
        "current_xqm": xqm_match.group(1) if xqm_match else "3",
        # 周次、星期、节次是网格选择器，手动生成
        "weeks": [{"value": str(i), "label": f"第{i}周"} for i in range(1, 21)],
        "weekdays": [
            {"value": "1", "label": "星期一"}, {"value": "2", "label": "星期二"},
            {"value": "3", "label": "星期三"}, {"value": "4", "label": "星期四"},
            {"value": "5", "label": "星期五"}, {"value": "6", "label": "星期六"},
            {"value": "7", "label": "星期日"},
        ],
        "sections": [{"value": str(i), "label": f"第{i}节"} for i in range(1, 11)],
    }

# ========== 路由 ==========
@app.route("/")
def index():
    record_page_view()
    return render_template("index.html")

@app.route("/api/schedule", methods=["POST"])
def api_schedule():
    client_ip = _client_ip()
    if not check_rate_limit(client_ip):
        logger.warning(f"限流触发: {client_ip}")
        return jsonify({"success": False, "error": "请求过于频繁，请稍后再试"}), 429

    data = request.get_json() or {}
    xh = (data.get("xh") or "").strip()
    pwd = (data.get("pwd") or "").strip()
    xnm = (data.get("xnm") or "2026").strip()
    xqm = (data.get("xqm") or "3").strip()

    if not xh or not pwd:
        return jsonify({"success": False, "error": "学号和密码不能为空"}), 400

    # 检查登录锁定
    allowed, msg = check_login_lock(client_ip, xh)
    if not allowed:
        return jsonify({"success": False, "error": msg}), 429

    try:
        session = login_to_edu_system(xh, pwd)
        raw = fetch_schedule(session, xnm, xqm)
        parsed = parse_courses(raw)
        # 登录成功，重置失败计数
        reset_login_fail(client_ip, xh)
        # 仅记录学号和姓名，不记录密码和课表数据
        student = parsed["student"]
        record_user(xh, student.get("name", ""), student.get("major", ""))
        record_stats_event("login_schedule", xh=xh, student_name=student.get("name", ""), major=student.get("major", ""))
        return jsonify({"success": True, "data": parsed})
    except ValueError as e:
        # 登录失败，记录
        record_login_fail(client_ip, xh)
        return jsonify({"success": False, "error": str(e)}), 401
    except requests.RequestException as e:
        logger.error(f"网络请求失败: {e}")
        return jsonify({"success": False, "error": "教务系统响应超时，请稍后重试"}), 502
    except Exception as e:
        logger.error(f"服务器错误: {e}", exc_info=True)
        return jsonify({"success": False, "error": "服务器内部错误"}), 500

@app.route("/api/scores", methods=["POST"])
def api_scores():
    client_ip = _client_ip()
    if not check_rate_limit(client_ip):
        return jsonify({"success": False, "error": "请求过于频繁，请稍后再试"}), 429

    data = request.get_json() or {}
    xh = (data.get("xh") or "").strip()
    pwd = (data.get("pwd") or "").strip()

    if not xh or not pwd:
        return jsonify({"success": False, "error": "学号和密码不能为空"}), 400

    # 检查登录锁定
    allowed, msg = check_login_lock(client_ip, xh)
    if not allowed:
        return jsonify({"success": False, "error": msg}), 429

    try:
        session = login_to_edu_system(xh, pwd)
        raw = fetch_scores(session)
        parsed = parse_scores(raw)
        # 登录成功，重置失败计数
        reset_login_fail(client_ip, xh)
        # 仅记录学号和姓名，不记录密码和成绩数据
        student = parsed["student"]
        record_user(xh, student.get("name", ""), student.get("major", ""))
        record_stats_event("login_scores", xh=xh, student_name=student.get("name", ""), major=student.get("major", ""))
        return jsonify({"success": True, "data": parsed})
    except ValueError as e:
        record_login_fail(client_ip, xh)
        return jsonify({"success": False, "error": str(e)}), 401
    except requests.RequestException as e:
        logger.error(f"网络请求失败: {e}")
        return jsonify({"success": False, "error": "教务系统响应超时，请稍后重试"}), 502
    except Exception as e:
        logger.error(f"服务器错误: {e}", exc_info=True)
        return jsonify({"success": False, "error": "服务器内部错误"}), 500

@app.route("/api/academia", methods=["POST"])
def api_academia():
    client_ip = _client_ip()
    if not check_rate_limit(client_ip):
        return jsonify({"success": False, "error": "请求过于频繁，请稍后再试"}), 429
    data = request.get_json() or {}
    xh, pwd = (data.get("xh") or "").strip(), (data.get("pwd") or "").strip()
    if not xh or not pwd:
        return jsonify({"success": False, "error": "学号和密码不能为空"}), 400
    # 检查登录锁定
    allowed, msg = check_login_lock(client_ip, xh)
    if not allowed:
        return jsonify({"success": False, "error": msg}), 429
    try:
        result = fetch_academia(login_to_edu_system(xh, pwd))
        reset_login_fail(client_ip, xh)
        record_user(xh, "")
        return jsonify({"success": True, "data": result})
    except ValueError as e:
        record_login_fail(client_ip, xh)
        return jsonify({"success": False, "error": str(e)}), 401
    except requests.RequestException:
        logger.exception("学业情况请求失败")
        return jsonify({"success": False, "error": "学业情况查询超时，请稍后重试"}), 502
    except Exception:
        logger.exception("学业情况解析失败")
        return jsonify({"success": False, "error": "学业情况数据解析失败"}), 502

@app.route("/api/classrooms", methods=["POST"])
def api_classrooms():
    client_ip = _client_ip()
    if not check_rate_limit(client_ip):
        return jsonify({"success": False, "error": "请求过于频繁，请稍后再试"}), 429
    data = request.get_json() or {}
    xh, pwd = (data.get("xh") or "").strip(), (data.get("pwd") or "").strip()
    if not xh or not pwd:
        return jsonify({"success": False, "error": "学号和密码不能为空"}), 400
    # 检查登录锁定
    allowed, msg = check_login_lock(client_ip, xh)
    if not allowed:
        return jsonify({"success": False, "error": msg}), 429
    try:
        result = fetch_classrooms(login_to_edu_system(xh, pwd), data)
        reset_login_fail(client_ip, xh)
        return jsonify({"success": True, "data": result})
    except ValueError as e:
        record_login_fail(client_ip, xh)
        return jsonify({"success": False, "error": str(e)}), 401
    except requests.RequestException:
        logger.exception("空教室请求失败")
        return jsonify({"success": False, "error": "空教室查询超时，请稍后重试"}), 502
    except Exception:
        logger.exception("空教室解析失败")
        return jsonify({"success": False, "error": "空教室数据解析失败"}), 502

@app.route("/api/classroom-options", methods=["POST"])
def api_classroom_options():
    client_ip = _client_ip()
    if not check_rate_limit(client_ip):
        return jsonify({"success": False, "error": "请求过于频繁，请稍后再试"}), 429
    data = request.get_json() or {}
    xh, pwd = (data.get("xh") or "").strip(), (data.get("pwd") or "").strip()
    if not xh or not pwd:
        return jsonify({"success": False, "error": "学号和密码不能为空"}), 400
    # 检查登录锁定
    allowed, msg = check_login_lock(client_ip, xh)
    if not allowed:
        return jsonify({"success": False, "error": msg}), 429
    try:
        options = fetch_classroom_options(login_to_edu_system(xh, pwd))
        reset_login_fail(client_ip, xh)
        return jsonify({"success": True, "data": options})
    except ValueError as e:
        record_login_fail(client_ip, xh)
        return jsonify({"success": False, "error": str(e)}), 401
    except requests.RequestException:
        logger.exception("空教室选项请求失败")
        return jsonify({"success": False, "error": "空教室选项读取超时，请稍后重试"}), 502
    except Exception:
        logger.exception("空教室选项解析失败")
        return jsonify({"success": False, "error": "空教室选项读取失败"}), 502

# ========== 空教室公共查询（免登录 + 数据库缓存） ==========
@app.route("/api/classrooms-public", methods=["POST"])
def api_classrooms_public():
    client_ip = _client_ip()
    if not check_rate_limit(client_ip):
        return jsonify({"success": False, "error": "请求过于频繁，请稍后再试"}), 429
    data = request.get_json() or {}
    campus = (data.get("campus") or "").strip()
    building = (data.get("building") or "").strip()
    category = (data.get("category") or "").strip()
    weeks = (data.get("weeks") or "").strip()
    weekdays = (data.get("weekdays") or "").strip()
    sections = (data.get("sections") or "").strip()
    show_count = int(data.get("show_count", 100))

    # 学期固定为当前学期（从公共session页面获取）
    semester = "2026-3"
    key = _cache_key(semester, campus, building, category, weeks, weekdays, sections)

    # 先查缓存
    cached = _get_classroom_cache(key)
    if cached:
        logger.info(f"空教室缓存命中: {key}")
        result = cached["data"]
        # 限制返回数量
        if show_count and len(result.get("classrooms", [])) > show_count:
            result = dict(result)
            result["classrooms"] = result["classrooms"][:show_count]
        return jsonify({"success": True, "data": result, "from_cache": True})

    # 缓存未命中，用公共session查询
    try:
        session = _get_public_session()
        query = {
            "campus": campus, "building": building, "category": category,
            "weeks": weeks, "weekdays": weekdays, "sections": sections,
            "show_count": 200,  # 缓存时多存点
        }
        try:
            result = fetch_classrooms(session, query)
        except ValueError:
            # session过期，刷新后重试
            logger.info("公共session过期，尝试刷新")
            _refresh_public_session()
            session = _get_public_session()
            result = fetch_classrooms(session, query)

        # 写入缓存
        _set_classroom_cache(key, semester, campus, building, category, weeks, weekdays, sections,
                             result, result.get("total", 0))

        # 限制返回数量
        if show_count and len(result.get("classrooms", [])) > show_count:
            result = dict(result)
            result["classrooms"] = result["classrooms"][:show_count]
        record_stats_event("classroom_query")
        return jsonify({"success": True, "data": result, "from_cache": False})
    except Exception as e:
        logger.exception(f"公共空教室查询失败: {e}")
        return jsonify({"success": False, "error": "空教室查询失败，请稍后重试"}), 502

@app.route("/api/classroom-options-public", methods=["GET"])
def api_classroom_options_public():
    """空教室选项公共接口（免登录）"""
    try:
        session = _get_public_session()
        try:
            options = fetch_classroom_options(session)
        except ValueError:
            _refresh_public_session()
            session = _get_public_session()
            options = fetch_classroom_options(session)
        return jsonify({"success": True, "data": options})
    except Exception as e:
        logger.exception(f"公共空教室选项获取失败: {e}")
        return jsonify({"success": False, "error": "选项加载失败，请稍后重试"}), 502

def _normalize_class_search_text(value):
    text = unicodedata.normalize("NFKC", str(value or "")).casefold()
    return re.sub(r"[^0-9a-z\u4e00-\u9fff]+", "", text)


def _class_search_forms(value):
    """返回中文、全拼、拼音首字母三种可搜索形式。"""
    normalized = _normalize_class_search_text(value)
    if not lazy_pinyin:
        return {normalized}
    syllables = [part.casefold() for part in lazy_pinyin(str(value or ""), errors="keep") if part]
    full = "".join(syllables)
    initials = "".join(part[0] for part in syllables if part)
    return {item for item in (normalized, full, initials) if item}


def _ordered_chars_match(query, target):
    """允许“智水”匹配“智慧水利”，“zs”匹配“智慧水利”的首字母。"""
    if not query or not target:
        return False
    iterator = iter(target)
    return all(char in iterator for char in query)


def _class_search_score(row, keyword):
    query = _normalize_class_search_text(keyword)
    if not query:
        return 1.0
    fields = [
        ("class", _class_search_forms(row["bjmc"])),
        ("major", _class_search_forms(row["zymc"])),
        ("college", _class_search_forms(row["jgmc"])),
        ("grade", _class_search_forms(row["njdm_id"])),
    ]
    class_forms = fields[0][1]
    combined_forms = set().union(*(forms for _, forms in fields))
    raw_tokens = [_normalize_class_search_text(part) for part in re.split(r"[\s._-]+", keyword) if part.strip()]

    if query in class_forms:
        return 100.0
    if any(form.startswith(query) for form in class_forms):
        return 94.0
    if any(query in form for form in class_forms):
        return 90.0
    if any(query in form for form in fields[1][1]):
        return 84.0
    if any(query in form for form in fields[2][1]):
        return 80.0
    if raw_tokens:
        for field_name, forms in fields:
            if all(any(token in form or _ordered_chars_match(token, form) for form in forms) for token in raw_tokens):
                return {"class": 88.0, "major": 84.0, "college": 80.0}.get(field_name, 76.0)
    if any(query in form for form in combined_forms):
        return 76.0
    if any(_ordered_chars_match(query, form) for form in combined_forms):
        return 72.0
    if raw_tokens and all(
        any(token in form or _ordered_chars_match(token, form) for form in combined_forms)
        for token in raw_tokens
    ):
        return 70.0
    if len(query) < 2:
        return 0.0
    ratio = max(
        *(SequenceMatcher(None, query, form).ratio() for form in combined_forms),
    )
    return ratio * 70 if ratio >= 0.72 else 0.0


@app.route("/api/class-schedule/search", methods=["GET"])
def api_class_schedule_search():
    """搜索专业/班级课表"""
    keyword = request.args.get("keyword", "").strip()
    grade = request.args.get("grade", "").strip()
    semester = request.args.get("semester", "2026-3").strip()

    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            sql = """
                SELECT id, semester, njdm_id, jgmc, zymc, bjmc, pyccmc,
                       course_count, status, updated_at
                FROM class_schedule
                WHERE semester = ? AND status = 'success'
            """
            params = [semester]
            if grade:
                sql += " AND njdm_id = ?"
                params.append(grade)
            sql += " ORDER BY njdm_id DESC, zymc, bjmc"
            rows = conn.execute(sql, params).fetchall()

        if keyword:
            scored_rows = [(_class_search_score(row, keyword), row) for row in rows]
            rows = [row for score, row in sorted(
                (item for item in scored_rows if item[0] > 0),
                key=lambda item: (-item[0], -int(item[1]["njdm_id"] or 0), item[1]["bjmc"] or ""),
            )[:200]]
        else:
            rows = rows[:80]

        results = []
        for r in rows:
            results.append({
                "id": r["id"],
                "semester": r["semester"],
                "grade": r["njdm_id"],
                "college": r["jgmc"],
                "major": r["zymc"],
                "className": r["bjmc"],
                "level": r["pyccmc"],
                "courseCount": r["course_count"],
                "updatedAt": r["updated_at"],
            })
        return encrypted_response({"success": True, "data": results, "total": len(results)})
    except Exception as e:
        logger.exception(f"班级课表搜索失败: {e}")
        return jsonify({"success": False, "error": "搜索失败"}), 500

@app.route("/api/stats/class-bind", methods=["POST"])
def api_stats_class_bind():
    data = request.get_json(silent=True) or {}
    try:
        class_id = int(data.get("id")) if data.get("id") is not None else None
    except (TypeError, ValueError):
        class_id = None
    record_stats_event(
        "class_bind",
        xh=str(data.get("xh") or "")[:32],
        student_name=str(data.get("studentName") or "")[:80],
        major=str(data.get("studentMajor") or "")[:120],
        class_id=class_id,
        class_name=str(data.get("className") or "")[:120],
        class_major=str(data.get("major") or "")[:120],
    )
    return jsonify({"success": True})


@app.route("/api/class-schedule/detail", methods=["GET"])
def api_class_schedule_detail():
    """获取班级课表详情"""
    class_id = request.args.get("id", "").strip()
    if not class_id:
        return jsonify({"success": False, "error": "缺少班级ID"}), 400

    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT * FROM class_schedule WHERE id = ? AND status = 'success'",
                (class_id,)
            ).fetchone()

        if not row:
            return jsonify({"success": False, "error": "课表不存在或尚未爬取"}), 404

        course_data = json.loads(row["course_data"]) if row["course_data"] else []
        week_data = json.loads(row["week_data"]) if row["week_data"] else []

        return encrypted_response({
            "success": True,
            "data": {
                "id": row["id"],
                "semester": row["semester"],
                "grade": row["njdm_id"],
                "college": row["jgmc"],
                "major": row["zymc"],
                "className": row["bjmc"],
                "level": row["pyccmc"],
                "courseCount": row["course_count"],
                "courses": course_data,
                "weeks": week_data,
                "updatedAt": row["updated_at"],
            }
        })
    except Exception as e:
        logger.exception(f"班级课表详情获取失败: {e}")
        return jsonify({"success": False, "error": "获取失败"}), 500


@app.route("/api/class-schedule/stats", methods=["GET"])
def api_class_schedule_stats():
    """获取班级课表爬取进度统计"""
    try:
        with sqlite3.connect(DB_PATH) as conn:
            semester = request.args.get("semester", "2026-3").strip()
            rows = conn.execute(
                "SELECT status, COUNT(*) as cnt FROM class_schedule WHERE semester = ? GROUP BY status",
                (semester,)
            ).fetchall()

        stats = {"total": 0, "success": 0, "failed": 0, "pending": 0}
        for status, cnt in rows:
            stats[status] = cnt
            stats["total"] += cnt
        return jsonify({"success": True, "data": stats})
    except Exception as e:
        logger.exception(f"班级课表统计失败: {e}")
        return jsonify({"success": False, "error": "统计失败"}), 500


@app.route("/api/classrooms-cached", methods=["GET"])
def api_classrooms_cached():
    """从数据库查询空教室（免登录，已爬取的数据）"""
    try:
        week = request.args.get("week", "2").strip()
        weekdays = request.args.get("weekdays", "").strip()
        sections = request.args.get("sections", "").strip() or ",".join(str(i) for i in range(1, 11))
        campus = request.args.get("campus", "").strip()
        building = request.args.get("building", "").strip()
        floor = request.args.get("floor", "").strip()
        category = request.args.get("category", "").strip()
        seats = request.args.get("seats", "").strip()
        name = request.args.get("name", "").strip()

        if not weekdays:
            return jsonify({"success": False, "error": "请选择星期"}), 400

        weekday_list = [w.strip() for w in weekdays.split(",") if w.strip()]
        section_list = [s.strip() for s in sections.split(",") if s.strip()]

        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            # 多时间段取交集：所有选中时间段都空闲的教室
            base_sql = """
                SELECT DISTINCT room_id, room_name, category, building, floor, seats, campus
                FROM classroom_free
                WHERE week = ? AND weekday = ? AND section = ?
            """
            params = [week, weekday_list[0], section_list[0]]

            # 用INTERSECT处理多个时间段的交集
            if len(weekday_list) > 1 or len(section_list) > 1:
                all_conditions = []
                for wd in weekday_list:
                    for sec in section_list:
                        all_conditions.append((wd, sec))
                # 第一个已经在base_sql里了
                sql_parts = [base_sql]
                for wd, sec in all_conditions[1:]:
                    sql_parts.append(f"""
                        SELECT DISTINCT room_id, room_name, category, building, floor, seats, campus
                        FROM classroom_free
                        WHERE week = ? AND weekday = ? AND section = ?
                    """)
                    params.extend([week, wd, sec])
                sql = " INTERSECT ".join(sql_parts)
            else:
                sql = base_sql

            # 筛选条件
            filters = []
            if campus:
                filters.append("campus = ?")
                params.append(campus)
            if building:
                filters.append("building = ?")
                params.append(building)
            if category:
                filters.append("category = ?")
                params.append(category)
            if floor:
                filters.append("floor = ?")
                params.append(floor)
            if seats == "0-60":
                filters.append("CAST(seats AS INTEGER) BETWEEN 0 AND 60")
            elif seats == "61-120":
                filters.append("CAST(seats AS INTEGER) BETWEEN 61 AND 120")
            elif seats == "121+":
                filters.append("CAST(seats AS INTEGER) >= 121")
            if name:
                filters.append("room_name LIKE ?")
                params.append(f"%{name}%")
            if filters:
                sql = f"SELECT * FROM ({sql}) WHERE {' AND '.join(filters)}"

            sql += " ORDER BY room_name LIMIT 1000"
            rows = conn.execute(sql, params).fetchall()

        classrooms = []
        for r in rows:
            classrooms.append({
                "code": r["room_id"],
                "name": r["room_name"],
                "campus": r["campus"] or "新校区",
                "category": r["category"],
                "seats": r["seats"],
                "building": r["building"],
                "floor": r["floor"] or "",
            })

        record_stats_event("classroom_query")
        return jsonify({
            "success": True,
            "data": {"classrooms": classrooms, "total": len(classrooms)},
            "source": "cached"
        })
    except Exception as e:
        logger.exception(f"缓存空教室查询失败: {e}")
        return jsonify({"success": False, "error": "查询失败"}), 500

@app.route("/api/classroom-options-cached", methods=["GET"])
def api_classroom_options_cached():
    """从已入库的空教室数据生成筛选标签，避免前端手填。"""
    try:
        with sqlite3.connect(DB_PATH) as conn:
            def options(column, numeric=False, suffix=""):
                order = f"CAST({column} AS INTEGER), {column}" if numeric else column
                rows = conn.execute(
                    f"SELECT DISTINCT {column} FROM classroom_free WHERE {column} IS NOT NULL AND TRIM({column}) <> '' ORDER BY {order}"
                ).fetchall()
                return [{"value": str(row[0]), "label": f"{row[0]}{suffix}"} for row in rows]
            return jsonify({"success": True, "data": {
                "campus": options("campus"), "building": options("building"),
                "floor": options("floor"), "category": options("category"),
                "seats": [
                    {"value": "0-60", "label": "60座及以下"},
                    {"value": "61-120", "label": "61–120座"},
                    {"value": "121+", "label": "121座及以上"},
                ],
                "weeks": [{"value": str(i), "label": f"第{i}周"} for i in range(1, 21)],
                "weekdays": [{"value": str(i), "label": f"星期{['一','二','三','四','五','六','日'][i-1]}"} for i in range(1, 8)],
                "sections": [{"value": str(i), "label": f"第{i}节"} for i in range(1, 11)],
            }})
    except Exception:
        logger.exception("缓存空教室选项读取失败")
        return jsonify({"success": False, "error": "筛选选项读取失败"}), 500


@app.route("/health")
def health():
    return jsonify({"status": "ok"})

@app.route("/api/map-track", methods=["GET", "POST"])
def map_track():
    """接收 map.suyu.ink 的访问统计，跨域调用。"""
    # 允许 map.suyu.ink 跨域
    origin = request.headers.get("Origin", "")
    if "map.suyu.ink" in origin or "suyu.ink" in origin:
        pass  # 合法来源
    # 简单限流：每IP每分钟最多30次
    ip = _client_ip()
    now = time.time()
    if not hasattr(app, "_map_track_rate"):
        app._map_track_rate = {}
    rate_list = app._map_track_rate.setdefault(ip, [])
    rate_list = [t for t in rate_list if now - t < 60]
    if len(rate_list) >= 30:
        resp = jsonify({"success": False, "error": "too many requests"})
        resp.headers["Access-Control-Allow-Origin"] = origin or "*"
        return resp, 429
    rate_list.append(now)
    app._map_track_rate[ip] = rate_list

    ip_hash = hmac.new(STATS_IP_SALT, ip.encode(), hashlib.sha256).hexdigest()
    device = _device_summary(request.headers.get("User-Agent", ""))
    page = (request.args.get("page") or request.form.get("page") or "").strip()[:200]
    referrer = (request.args.get("ref") or request.form.get("ref") or request.headers.get("Referer", "")).strip()[:500]
    try:
        with _db_lock, sqlite3.connect(DB_PATH) as conn:
            conn.execute("""
                INSERT INTO map_views (ip_hash, device_type, device_model, os_name, browser, referrer, page)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (ip_hash, device["device_type"], device["device_model"], device["os_name"], device["browser"], referrer, page))
            conn.commit()
    except Exception as exc:
        logger.warning(f"map访问记录失败: {exc}")
    resp = jsonify({"success": True})
    resp.headers["Access-Control-Allow-Origin"] = origin or "*"
    resp.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    return resp

@app.route("/api/map-track", methods=["OPTIONS"])
def map_track_options():
    resp = Response("", 204)
    resp.headers["Access-Control-Allow-Origin"] = request.headers.get("Origin", "*")
    resp.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type"
    return resp

@app.route("/map-stats")
def map_stats():
    """map.suyu.ink 公开统计页面，无需登录。"""
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            summary = conn.execute("""
                SELECT COUNT(*) AS total_opens, COUNT(DISTINCT ip_hash) AS unique_visitors,
                       MAX(created_at) AS latest
                FROM map_views
            """).fetchone()
            devices = conn.execute("""
                SELECT device_type, device_model, os_name, browser, COUNT(*) AS count
                FROM map_views GROUP BY device_type, device_model, os_name, browser
                ORDER BY count DESC LIMIT 20
            """).fetchall()
            views = conn.execute("SELECT created_at, substr(ip_hash, 1, 10) AS visitor, device_type, device_model, os_name, browser, referrer, page FROM map_views ORDER BY id DESC LIMIT 200").fetchall()
            visitors = conn.execute("SELECT substr(ip_hash, 1, 10) AS visitor, COUNT(*) AS count, MIN(created_at) AS first_seen, MAX(created_at) AS latest, MAX(device_model) AS device_model, MAX(os_name) AS os_name, MAX(browser) AS browser FROM map_views GROUP BY ip_hash ORDER BY latest DESC LIMIT 500").fetchall()
        return render_template("map_stats.html", summary=dict(summary), devices=[dict(r) for r in devices], views=[dict(r) for r in views], visitors=[dict(r) for r in visitors])
    except Exception:
        logger.exception("map统计页面读取失败")
        return Response("统计数据读取失败", 500)

@app.route("/admin/stats")
def admin_stats():
    """HTTP Basic Auth 保护的只读统计页面。"""
    auth = request.authorization
    if not ADMIN_PASSWORD or not auth or not secrets.compare_digest(auth.username or "", ADMIN_USER) or not secrets.compare_digest(auth.password or "", ADMIN_PASSWORD):
        response = Response("需要管理员认证", 401)
        response.headers["WWW-Authenticate"] = 'Basic realm="HebEU Stats"'
        return response
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            summary = conn.execute("""
                SELECT COUNT(*) AS total_opens, COUNT(DISTINCT ip_hash) AS unique_visitors,
                       MAX(created_at) AS latest
                FROM page_views
            """).fetchone()
            devices = conn.execute("""
                SELECT device_type, device_model, os_name, browser, COUNT(*) AS count
                FROM page_views GROUP BY device_type, device_model, os_name, browser
                ORDER BY count DESC LIMIT 20
            """).fetchall()
            events = conn.execute("""
                SELECT event_type, COUNT(*) AS count, COUNT(DISTINCT ip_hash) AS visitors, MAX(created_at) AS latest
                FROM stats_events GROUP BY event_type ORDER BY count DESC
            """).fetchall()
            users = conn.execute("SELECT COUNT(*) AS count, MAX(last_used_at) AS latest FROM users").fetchone()
            user_list = conn.execute("""
                SELECT u.xh, u.name, u.major, u.use_count, u.created_at, u.last_used_at,
                       COALESCE((SELECT device_model FROM stats_events WHERE xh = u.xh ORDER BY id DESC LIMIT 1), '') AS device_model,
                       COALESCE((SELECT os_name FROM stats_events WHERE xh = u.xh ORDER BY id DESC LIMIT 1), '') AS os_name,
                       COALESCE((SELECT browser FROM stats_events WHERE xh = u.xh ORDER BY id DESC LIMIT 1), '') AS browser
                FROM users u
                ORDER BY u.last_used_at DESC LIMIT 500
            """).fetchall()
            views = conn.execute("SELECT created_at, substr(ip_hash, 1, 10) AS visitor, device_type, device_model, os_name, browser, referrer FROM page_views ORDER BY id DESC LIMIT 200").fetchall()
            visitors = conn.execute("SELECT substr(ip_hash, 1, 10) AS visitor, COUNT(*) AS count, MIN(created_at) AS first_seen, MAX(created_at) AS latest, MAX(device_model) AS device_model, MAX(os_name) AS os_name, MAX(browser) AS browser FROM page_views GROUP BY ip_hash ORDER BY latest DESC LIMIT 500").fetchall()
            bindings = conn.execute("SELECT created_at, substr(ip_hash, 1, 10) AS visitor, xh, student_name, major, class_name, class_major FROM stats_events WHERE event_type = 'class_bind' ORDER BY id DESC LIMIT 200").fetchall()
        return render_template("admin_stats.html", summary=dict(summary), devices=[dict(r) for r in devices], events=[dict(r) for r in events], users=dict(users), user_list=[dict(r) for r in user_list], views=[dict(r) for r in views], visitors=[dict(r) for r in visitors], bindings=[dict(r) for r in bindings])
    except Exception:
        logger.exception("统计后台读取失败")
        return Response("统计数据读取失败", 500)

# 初始化数据库
init_db()

if __name__ == "__main__":
    logger.info("服务启动: http://0.0.0.0:5001")
    app.run(host="0.0.0.0", port=5001, debug=False)
