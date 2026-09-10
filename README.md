# 河北工程大学课表查询

面向手机 H5 的河北工程大学课程表工具：登录教务系统后查看个人课表、成绩和学业情况，也支持未登录用户选择班级查看全校课表、查询空教室。

## 示例网站

在线体验：[grades.suyu.ink](https://grades.suyu.ink/)

## 功能

- 个人课表：周次切换、周课表、课程详情和实践课程
- 全校班级课表：班级搜索、拼音/首字母模糊搜索、班级课表预览
- 成绩与学业情况：成绩筛选、学分和修读状态展示
- 空教室：校区、楼号、楼层、场地类别、座位范围和时间筛选
- 手机优先的响应式界面，支持左右滑动切换周次和减少动画偏好
- 浏览器端加密缓存个人查询结果，不在服务器保存密码和个人课表成绩

## 安全说明

本仓库不包含生产数据库、账号密码、统计数据、服务器配置或备份文件。部署时请通过环境变量配置教务系统公共账号、统计盐值和后台密码；生产环境应使用 HTTPS，并限制数据库文件权限。

## 本地运行

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

访问 `http://127.0.0.1:5000/`。首次运行会自动创建本地 SQLite 数据库；公开班级课表和空教室数据需要先导入相应缓存。

一个基于 Flask 的网页版课表查询工具，输入学号密码即可一键导出课表。

## 功能特点

- 🔐 模拟登录教务系统（无需验证码）
- 📅 可视化课表展示（按星期/节次排列）
- 🎨 课程颜色自动区分
- 📝 点击课程查看详细信息
- 🛠️ 实践课程单独展示
- 📱 响应式设计，手机电脑都能用

## 快速开始

### 1. 安装依赖

```bash
cd hebeu-schedule
pip install -r requirements.txt
```

### 2. 启动服务

```bash
python app.py
```

### 3. 访问

打开浏览器访问：http://127.0.0.1:5000

输入学号和教务系统密码，点击查询即可。

## 项目结构

```
hebeu-schedule/
├── app.py              # Flask 后端（登录+课表查询API）
├── requirements.txt    # Python 依赖
├── templates/
│   └── index.html      # 前端页面（登录+课表展示）
└── README.md           # 说明文档
```

## API 接口

### 查询课表

```
POST /api/schedule
Content-Type: application/json

{
  "xh": "学号",
  "pwd": "密码",
  "xnm": "2026",    // 可选，学年，默认2026
  "xqm": "3"        // 可选，学期，3=第一学期，12=第二学期，默认3
}
```

**响应示例：**

```json
{
  "success": true,
  "data": {
    "student": {
      "name": "张三",
      "xh": "230480209",
      "class": "智水2302",
      "major": "智慧水利",
      "year": "2026-2027",
      "term": "1"
    },
    "courses": [
      {
        "name": "知识图谱",
        "teacher": "王东",
        "room": "J02东311",
        "weekday": "1",
        "weekday_name": "星期一",
        "section": "1-2节",
        "section_start": 1,
        "section_end": 2,
        "weeks": "3-10周",
        "credit": "2",
        "exam_type": "考查",
        "course_type": "专业教育"
      }
    ],
    "practice": [
      {
        "name": "工程实训",
        "teacher": "邵楠,张景洲",
        "weeks": "17周",
        "credit": "1",
        "exam_type": "考查"
      }
    ]
  }
}
```

## 部署到服务器

### 使用 Gunicorn（生产环境）

```bash
pip install gunicorn
gunicorn -w 4 -b 0.0.0.0:5000 app:app
```

### 使用 Nginx 反向代理

```nginx
server {
    listen 80;
    server_name your-domain.com;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

### 部署到云服务器

1. 购买云服务器（阿里云/腾讯云轻量应用服务器即可）
2. 安装 Python 3.8+
3. 上传项目文件
4. 安装依赖并启动
5. 配置 Nginx 和域名（可选）
6. 配置 HTTPS（推荐）

## 技术说明

### 教务系统接口

- **登录接口**: `POST /xtgl/login_slogin.html?time=时间戳`
  - 参数: `yhm`（学号）, `mm`（RSA加密后的密码）, `csrftoken`, `language`
  - 密码使用 RSA PKCS#1 v1.5 加密，公钥从 `/xtgl/login_getPublicKey.html` 获取
- **课表接口**: `POST /kbcx/xskbcx_cxXsgrkb.html?gnmkdm=N2151`
  - 参数: `xnm`（学年）, `xqm`（学期）, `kzlx=ck`
  - 返回: JSON 格式

### 登录流程

1. GET 登录页，提取 `csrftoken` 隐藏字段和 Cookie
2. GET `/xtgl/login_getPublicKey.html` 获取 RSA 公钥（modulus + exponent，base64编码）
3. 用 RSA 公钥加密密码（PKCS#1 v1.5 padding），结果转 base64
4. POST 登录表单（学号 + 加密密码 + csrftoken）

### 学期编码

正方教务系统的学期编码比较特殊：
- `3` = 第一学期（秋季学期）
- `12` = 第二学期（春季学期）

## 注意事项

1. **密码安全**: 本项目仅在本地/服务器内存中处理密码，不存储任何用户数据。部署到公网时建议启用 HTTPS。
2. **会话时效**: 教务系统 Session 一般 15-30 分钟过期，每次查询都会重新登录。
3. **请求频率**: 请勿高频请求，避免对教务系统造成压力。
4. **适用范围**: 本项目针对河北工程大学正方教务系统 V9.0 开发，其他学校可能需要调整接口地址。

## 免责声明

本项目仅供学习交流使用，请勿用于商业用途。使用本工具所产生的一切后果由使用者自行承担。
