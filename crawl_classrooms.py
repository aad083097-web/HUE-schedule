#!/usr/bin/env python3
"""
空教室批量爬虫
- 爬取新校区一周（周一到周日）所有节次的空闲教室
- 每个请求间隔3-5秒
- 存储到SQLite数据库
"""
import sys
import os
import json
import time
import random
import sqlite3
import logging
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from app import login_to_edu_system, BASE_URL, DB_PATH, _to_bitmask, _request_with_retry, _is_login_page, _derive_floor

# 配置
CRAWLER_ACCOUNT = "222020729"
CRAWLER_PASSWORD = "040908Ch!"
XNM = "2026"
XQM = "3"
XQH_ID = "108"  # 新校区
CURRENT_WEEK = 2  # 当前周次（学期从2026-08-31开始）
WEEKDAYS = [1, 2, 3, 4, 5, 6, 7]  # 周一到周日
SECTIONS = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]  # 10小节
DELAY_MIN = 3
DELAY_MAX = 5
MAX_RETRY = 3

CLASSROOM_PAGE_URL = f"{BASE_URL}/cdjy/cdjy_cxKxcdlb.html?gnmkdm=N2155&layout=default"
CLASSROOM_URL = f"{BASE_URL}/cdjy/cdjy_cxKxcdlb.html?doType=query&gnmkdm=N2155"

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler('/opt/hebeu-schedule/classroom_crawler.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


def init_db():
    """初始化空教室表"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS classroom_free (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            semester TEXT NOT NULL,
            week INTEGER NOT NULL,
            weekday INTEGER NOT NULL,
            section INTEGER NOT NULL,
            campus TEXT,
            room_id TEXT,
            room_name TEXT,
            category TEXT,
            building TEXT,
            floor TEXT,
            seats TEXT,
            created_at TEXT,
            UNIQUE(semester, week, weekday, section, room_id)
        )
    ''')
    try:
        c.execute("ALTER TABLE classroom_free ADD COLUMN floor TEXT")
    except sqlite3.OperationalError:
        pass
    c.execute('CREATE INDEX IF NOT EXISTS idx_classroom_free_query ON classroom_free(semester, week, weekday, section)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_classroom_free_room ON classroom_free(room_name)')
    conn.commit()
    conn.close()
    logger.info("空教室表初始化完成")


def fetch_free_classrooms(session, week, weekday, section):
    """获取指定时间段的空闲教室，处理分页"""
    session.headers.update({"Referer": CLASSROOM_PAGE_URL, "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"})
    page = _request_with_retry(session, "GET", CLASSROOM_PAGE_URL)
    page.raise_for_status()
    if _is_login_page(page):
        raise ValueError("登录已过期")

    all_items = []
    page_num = 1
    page_size = 500

    while True:
        data = {
            "xqh_id": XQH_ID,
            "xnm": XNM,
            "xqm": XQM,
            "lh": "",
            "cdlb_id": "",
            "cdejlb_id": "",
            "qszws": "",
            "jszws": "",
            "cdmc": "",
            "cd_id": "",
            "jyfs": "0",
            "cdjylx": "",
            "zcd": str(_to_bitmask(str(week))),
            "xqj": str(weekday),
            "jcd": str(_to_bitmask(str(section))),
            "_search": "false",
            "queryModel.showCount": str(page_size),
            "queryModel.currentPage": str(page_num),
            "queryModel.sortName": "",
            "queryModel.sortOrder": "asc",
            "time": "0",
            "nd": str(int(time.time() * 1000)),
        }
        resp = _request_with_retry(session, "POST", CLASSROOM_URL, data=data)
        resp.raise_for_status()
        if _is_login_page(resp):
            raise ValueError("登录已过期")

        raw = resp.json()
        if isinstance(raw, dict):
            items = raw.get("items") or raw.get("rows") or []
            total = int(raw.get("totalResult", 0))
        else:
            items = raw if isinstance(raw, list) else []
            total = len(items)

        all_items.extend(items)

        if len(all_items) >= total or not items:
            break
        page_num += 1
        time.sleep(random.uniform(1, 2))

    return all_items


def save_classrooms(week, weekday, section, items):
    """保存空闲教室到数据库"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    semester = f"{XNM}-{XQM}"

    for item in items:
        room_id = item.get("cdbh", item.get("cd_id", ""))
        room_name = item.get("cdmc", "")
        if not room_name:
            continue
        c.execute('''
            INSERT OR IGNORE INTO classroom_free
            (semester, week, weekday, section, campus, room_id, room_name, category, building, floor, seats, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            semester, week, weekday, section,
            item.get("xqmc", ""),
            room_id, room_name,
            item.get("cdlbmc", ""),
            item.get("jxlmc", item.get("lh", "")),
            item.get("lc", item.get("floor", "")) or _derive_floor(room_name),
            item.get("zws", ""),
            now
        ))

    conn.commit()
    conn.close()


def get_progress():
    """获取爬取进度"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    semester = f"{XNM}-{XQM}"
    c.execute('''
        SELECT COUNT(DISTINCT weekday || '-' || section) as completed_slots,
               COUNT(*) as total_records
        FROM classroom_free WHERE semester=? AND week=?
    ''', (semester, CURRENT_WEEK))
    row = c.fetchone()
    conn.close()
    return {
        'completed_slots': row[0] or 0,
        'total_slots': len(WEEKDAYS) * len(SECTIONS),
        'total_records': row[1] or 0,
    }


def main():
    logger.info("=" * 60)
    logger.info("空教室批量爬虫启动")
    logger.info(f"目标: 新校区 第{CURRENT_WEEK}周 周一到周日 所有节次")
    logger.info("=" * 60)

    init_db()

    # 登录
    logger.info(f"使用账号 {CRAWLER_ACCOUNT} 登录...")
    session = login_to_edu_system(CRAWLER_ACCOUNT, CRAWLER_PASSWORD)
    logger.info("登录成功")

    total_slots = len(WEEKDAYS) * len(SECTIONS)
    current = 0
    success_count = 0

    for weekday in WEEKDAYS:
        for section in SECTIONS:
            current += 1
            weekday_names = ['', '周一', '周二', '周三', '周四', '周五', '周六', '周日']
            logger.info(f"[{current}/{total_slots}] 爬取 第{CURRENT_WEEK}周 {weekday_names[weekday]} 第{section}节...")

            try:
                items = fetch_free_classrooms(session, CURRENT_WEEK, weekday, section)
                save_classrooms(CURRENT_WEEK, weekday, section, items)
                success_count += 1
                logger.info(f"  ✅ 成功, {len(items)}个空闲教室")
            except Exception as e:
                logger.error(f"  ❌ 失败: {e}")
                # 登录过期则重新登录
                if "登录已过期" in str(e):
                    logger.info("重新登录...")
                    try:
                        session = login_to_edu_system(CRAWLER_ACCOUNT, CRAWLER_PASSWORD)
                        items = fetch_free_classrooms(session, CURRENT_WEEK, weekday, section)
                        save_classrooms(CURRENT_WEEK, weekday, section, items)
                        success_count += 1
                        logger.info(f"  ✅ 重登后成功, {len(items)}个空闲教室")
                    except Exception as e2:
                        logger.error(f"  ❌ 重登后仍失败: {e2}")

            # 延时
            if current < total_slots:
                time.sleep(random.uniform(DELAY_MIN, DELAY_MAX))

    progress = get_progress()
    logger.info("=" * 60)
    logger.info(f"爬取完成! 成功{success_count}/{total_slots}个时间段")
    logger.info(f"数据库记录: {progress['total_records']}条")
    logger.info("=" * 60)


if __name__ == "__main__":
    main()
