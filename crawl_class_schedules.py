#!/usr/bin/env python3
"""
班级课表批量爬虫
- 使用公共账号登录
- 爬取新校区所有本科班级课表
- 每个请求间隔3-5秒
- 支持断点续传
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
from app import login_to_edu_system, BASE_URL, DB_PATH

# 配置
CRAWLER_ACCOUNT = "222020729"
CRAWLER_PASSWORD = "040908Ch!"
XNM = "2026"
XQM = "3"
XQH_ID = "108"  # 新校区
PYCCDM = "3"    # 本科
GRADES = ["2022", "2023", "2024", "2025", "2026"]
DELAY_MIN = 3
DELAY_MAX = 5
MAX_RETRY = 3

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler('/opt/hebeu-schedule/crawler.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


def init_db():
    """初始化数据库表"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
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
            created_at TEXT,
            updated_at TEXT,
            UNIQUE(semester, xqh_id, njdm_id, zyh_id, bh_id)
        )
    ''')
    c.execute('CREATE INDEX IF NOT EXISTS idx_class_search ON class_schedule(zymc, bjmc, njdm_id)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_class_status ON class_schedule(status)')
    conn.commit()
    conn.close()
    logger.info("数据库表初始化完成")


def get_all_classes(session):
    """获取所有班级列表"""
    page_url = f"{BASE_URL}/kbdy/bjkbdy_cxBjkbdyIndex.html?gnmkdm=N214505&layout=default"
    session.headers.update({"Referer": page_url, "X-Requested-With": "XMLHttpRequest"})
    session.get(page_url, timeout=20)

    query_url = f"{BASE_URL}/kbdy/bjkbdy_cxBjkbdyTjkbList.html"
    all_classes = []

    for grade in GRADES:
        page_num = 1
        grade_count = 0
        grade_total = None
        while True:
            data = {
                "xnm": XNM, "xqm": XQM, "xqh_id": XQH_ID, "njdm_id": grade,
                "jg_id": "", "zyh_id": "", "bh_id": "", "pyccdm": PYCCDM,
                "_search": "false", "queryModel.showCount": "100",
                "queryModel.currentPage": str(page_num),
                "queryModel.sortName": "", "queryModel.sortOrder": "asc", "time": "0",
            }
            success = False
            for attempt in range(MAX_RETRY):
                try:
                    resp = session.post(query_url, data=data, timeout=30)
                    j = resp.json()
                    items = j.get('items', [])
                    total = int(j.get('totalResult', 0))
                    if grade_total is None:
                        grade_total = total
                    logger.info(f"  {grade}级 第{page_num}页: 获取{len(items)}个班级, 总计{total}")

                    for item in items:
                        all_classes.append({
                            'njdm_id': grade,
                            'jg_id': item.get('jgdm', ''),
                            'jgmc': item.get('jgmc', ''),
                            'zyh_id': item.get('zyh_id', ''),
                            'zymc': item.get('zymc', ''),
                            'bh_id': item.get('bh_id', ''),
                            'bjmc': item.get('bjmc', ''),
                            'pyccmc': item.get('pyccmc', '本科'),
                            'tjkbzdm': item.get('tjkbzdm', ''),
                            'tjkbzxsdm': item.get('tjkbzxsdm', ''),
                        })
                    grade_count += len(items)
                    success = True
                    break
                except Exception as e:
                    logger.warning(f"  获取{grade}级第{page_num}页失败(尝试{attempt+1}): {e}")
                    if attempt < MAX_RETRY - 1:
                        time.sleep(5)
                    else:
                        logger.error(f"  获取{grade}级第{page_num}页最终失败")

            if not success:
                break
            # 判断是否还有下一页
            if grade_count >= grade_total or len(items) < 100:
                break
            page_num += 1
            time.sleep(random.uniform(DELAY_MIN, DELAY_MAX))

        logger.info(f"  {grade}级完成: 共获取{grade_count}个班级")
        time.sleep(random.uniform(DELAY_MIN, DELAY_MAX))

    logger.info(f"共获取 {len(all_classes)} 个班级")
    return all_classes


def save_class_list(classes):
    """保存班级列表到数据库（pending状态）"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    semester = f"{XNM}-{XQM}"

    for cls in classes:
        c.execute('''
            INSERT OR IGNORE INTO class_schedule
            (semester, xqh_id, njdm_id, jg_id, jgmc, zyh_id, zymc, bh_id, bjmc, pyccmc, status, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?)
        ''', (semester, XQH_ID, cls['njdm_id'], cls['jg_id'], cls['jgmc'],
              cls['zyh_id'], cls['zymc'], cls['bh_id'], cls['bjmc'], cls['pyccmc'], now))

    conn.commit()
    conn.close()
    logger.info(f"班级列表已保存到数据库")


def crawl_class_schedule(session, cls):
    """爬取单个班级课表"""
    kb_url = f"{BASE_URL}/kbdy/bjkbdy_cxBjKb.html?gnmkdm=N214505"
    data = {
        "xnm": XNM, "xqm": XQM, "xqh_id": XQH_ID,
        "njdm_id": cls['njdm_id'],
        "zyh_id": cls['zyh_id'],
        "bh_id": cls['bh_id'],
        "tjkbzdm": cls.get('tjkbzdm', ''),
        "tjkbzxsdm": cls.get('tjkbzxsdm', ''),
        "kzlx": "ck",
    }

    resp = session.post(kb_url, data=data, timeout=30)
    if 'json' not in resp.headers.get('Content-Type', ''):
        raise Exception(f"非JSON响应: {resp.text[:200]}")

    j = resp.json()
    kb_list = j.get('kbList', [])
    week_num = j.get('weekNum', [])

    return {
        'kbList': kb_list,
        'weekNum': week_num,
        'course_count': len(kb_list),
    }


def update_class_result(cls, result, error=None):
    """更新班级课表结果到数据库"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    semester = f"{XNM}-{XQM}"

    if error:
        c.execute('''
            UPDATE class_schedule SET status='failed', error_msg=?, updated_at=?
            WHERE semester=? AND xqh_id=? AND njdm_id=? AND zyh_id=? AND bh_id=?
        ''', (str(error)[:500], now, semester, XQH_ID, cls['njdm_id'], cls['zyh_id'], cls['bh_id']))
    else:
        c.execute('''
            UPDATE class_schedule
            SET status='success', course_count=?, course_data=?, week_data=?, error_msg=NULL, updated_at=?
            WHERE semester=? AND xqh_id=? AND njdm_id=? AND zyh_id=? AND bh_id=?
        ''', (result['course_count'], json.dumps(result['kbList'], ensure_ascii=False),
              json.dumps(result['weekNum'], ensure_ascii=False), now,
              semester, XQH_ID, cls['njdm_id'], cls['zyh_id'], cls['bh_id']))

    conn.commit()
    conn.close()


def get_pending_classes():
    """获取待爬取的班级列表"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    semester = f"{XNM}-{XQM}"
    c.execute('''
        SELECT njdm_id, jg_id, jgmc, zyh_id, zymc, bh_id, bjmc, pyccmc
        FROM class_schedule
        WHERE semester=? AND status IN ('pending', 'failed')
        ORDER BY njdm_id, zymc, bjmc
    ''', (semester,))
    rows = c.fetchall()
    conn.close()

    classes = []
    for r in rows:
        classes.append({
            'njdm_id': r[0], 'jg_id': r[1], 'jgmc': r[2],
            'zyh_id': r[3], 'zymc': r[4], 'bh_id': r[5],
            'bjmc': r[6], 'pyccmc': r[7],
            'tjkbzdm': '1', 'tjkbzxsdm': '0',
        })
    return classes


def get_progress():
    """获取爬取进度"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    semester = f"{XNM}-{XQM}"
    c.execute('''
        SELECT status, COUNT(*) FROM class_schedule
        WHERE semester=? GROUP BY status
    ''', (semester,))
    rows = c.fetchall()
    conn.close()

    stats = {'total': 0, 'success': 0, 'failed': 0, 'pending': 0}
    for status, count in rows:
        stats[status] = count
        stats['total'] += count
    return stats


def main():
    logger.info("=" * 60)
    logger.info("班级课表批量爬虫启动")
    logger.info("=" * 60)

    init_db()

    # 检查是否已有班级列表
    stats = get_progress()
    if stats['total'] == 0:
        logger.info("首次运行，开始获取班级列表...")
        session = login_to_edu_system(CRAWLER_ACCOUNT, CRAWLER_PASSWORD)
        classes = get_all_classes(session)
        save_class_list(classes)
        stats = get_progress()
    else:
        logger.info(f"已有班级列表: 总计{stats['total']}个, 待爬取{stats['pending']}个, 失败{stats['failed']}个")

    # 登录
    logger.info(f"使用账号 {CRAWLER_ACCOUNT} 登录...")
    session = login_to_edu_system(CRAWLER_ACCOUNT, CRAWLER_PASSWORD)
    logger.info("登录成功")

    # 获取待爬取班级
    classes = get_pending_classes()
    logger.info(f"待爬取班级: {len(classes)}个")

    if not classes:
        logger.info("没有待爬取的班级，退出")
        return

    # 开始爬取
    success_count = 0
    fail_count = 0
    total = len(classes)

    for i, cls in enumerate(classes):
        bjmc = cls['bjmc']
        zymc = cls['zymc']
        logger.info(f"[{i+1}/{total}] 爬取 {cls['njdm_id']}级 {zymc} {bjmc}...")

        try:
            result = crawl_class_schedule(session, cls)
            update_class_result(cls, result)
            success_count += 1
            logger.info(f"  ✅ 成功, {result['course_count']}门课程")
        except Exception as e:
            update_class_result(cls, None, error=str(e))
            fail_count += 1
            logger.error(f"  ❌ 失败: {e}")

        # 每爬10个输出一次进度
        if (i + 1) % 10 == 0:
            stats = get_progress()
            logger.info(f"--- 进度: 成功{stats['success']}, 失败{stats['failed']}, 待爬{stats['pending']}, 总计{stats['total']} ---")

        # 延时
        if i < total - 1:
            delay = random.uniform(DELAY_MIN, DELAY_MAX)
            time.sleep(delay)

    logger.info("=" * 60)
    logger.info(f"爬取完成! 成功{success_count}, 失败{fail_count}")
    stats = get_progress()
    logger.info(f"最终统计: 总计{stats['total']}, 成功{stats['success']}, 失败{stats['failed']}, 待爬{stats['pending']}")
    logger.info("=" * 60)


if __name__ == "__main__":
    main()
