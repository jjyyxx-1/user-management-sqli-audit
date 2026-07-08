#!/usr/bin/env python3
"""生成SQL注入漏洞报告PDF"""
import markdown
from weasyprint import HTML

MD_PATH = "/workspace/user-management-sqli-audit/docs/sqli-report.md"
PDF_PATH = "/workspace/user-management-sqli-audit/docs/sqli-report.pdf"

with open(MD_PATH, "r", encoding="utf-8") as f:
    md_content = f.read()

html_body = markdown.markdown(
    md_content,
    extensions=["tables", "fenced_code", "codehilite", "toc"],
)

html_full = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<title>SQL注入漏洞检测与修复报告</title>
<style>
@page {{
    size: A4;
    margin: 2cm 2.2cm;
    @bottom-center {{
        content: "第 " counter(page) " 页";
        font-size: 9pt;
        color: #888;
    }}
}}
body {{
    font-family: "Noto Sans SC", "Source Han Sans SC", "Microsoft YaHei", sans-serif;
    font-size: 10.5pt;
    line-height: 1.8;
    color: #222;
}}
h1 {{
    font-size: 22pt;
    color: #1a1a2e;
    border-bottom: 3px solid #e74c3c;
    padding-bottom: 10px;
    margin-top: 30px;
}}
h2 {{
    font-size: 16pt;
    color: #c0392b;
    border-bottom: 1px solid #ddd;
    padding-bottom: 6px;
    margin-top: 28px;
}}
h3 {{
    font-size: 13pt;
    color: #0f3460;
    margin-top: 22px;
}}
table {{
    width: 100%;
    border-collapse: collapse;
    margin: 12px 0;
    font-size: 9.5pt;
}}
th, td {{
    border: 1px solid #ccc;
    padding: 6px 10px;
    text-align: left;
}}
th {{
    background: #e74c3c;
    color: #fff;
    font-weight: 600;
}}
tr:nth-child(even) {{
    background: #f8f9fc;
}}
code {{
    background: #f0f0f0;
    padding: 2px 6px;
    border-radius: 3px;
    font-size: 9pt;
    font-family: "Fira Code", "Consolas", monospace;
}}
pre {{
    background: #f5f5f5;
    border: 1px solid #ddd;
    border-left: 4px solid #e74c3c;
    padding: 10px 14px;
    border-radius: 4px;
    font-size: 9pt;
    overflow-x: auto;
    line-height: 1.5;
}}
pre code {{
    background: none;
    padding: 0;
}}
blockquote {{
    border-left: 4px solid #e74c3c;
    margin: 12px 0;
    padding: 8px 16px;
    background: #f8f9fc;
}}
hr {{
    border: none;
    border-top: 2px solid #e74c3c;
    margin: 20px 0;
}}
</style>
</head>
<body>
{html_body}
</body>
</html>"""

HTML(string=html_full).write_pdf(PDF_PATH)
print(f"✅ PDF生成成功: {PDF_PATH}")

import os
size = os.path.getsize(PDF_PATH)
print(f"   文件大小: {size:,} 字节 ({size/1024:.1f} KB)")
