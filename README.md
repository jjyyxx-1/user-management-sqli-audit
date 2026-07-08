# 用户管理系统 — SQL注入漏洞审计项目

## 项目概述

本项目是一个基于 Flask 的用户管理系统，包含**漏洞版**和**安全修复版**两个版本，重点演示和修复 **SQL 注入漏洞**。

## 目录结构

```
user-management-sqli-audit/
├── README.md
├── vulnerable/                ← 漏洞版（f-string拼接SQL）
│   ├── app.py
│   ├── templates/
│   │   ├── base.html
│   │   ├── login.html
│   │   ├── register.html
│   │   └── index.html
│   └── static/css/
│       └── style.css
├── fixed/                     ← 修复版（参数化查询）
│   ├── app.py
│   ├── templates/...
│   └── static/css/...
└── docs/
    ├── sqli-report.md         ← 完整SQL注入漏洞报告
    └── sqli-report.pdf        ← PDF版本
```

## 漏洞概况

| 漏洞 | 位置 | 严重性 |
|------|------|:------:|
| 搜索SQL注入 | `keyword`参数 → f-string拼接LIKE查询 | 🔴 严重 |
| 注册SQL注入 | `username/password/email/phone` → f-string拼接INSERT | 🔴 严重 |
| 登录密码明文存储 | SQLite中password字段 | 🟡 中危 |

## 快速使用

```bash
# 启动漏洞版
cd vulnerable && pip install flask werkzeug && python app.py

# 启动修复版
cd fixed && pip install flask werkzeug && python app.py
```
