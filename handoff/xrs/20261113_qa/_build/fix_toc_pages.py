# -*- coding: utf-8 -*-
"""按实际渲染页码校正已生成 TOC 条目的页码。

用法：python3 fix_toc_pages.py XRS_QA.docx --pages 1,1,4,5,7,9,11
顺序对应：文档说明、最小权限、路径规范化、六项指标、哈希审计、一分钟口径、附录。
页码取法：把 docx 转成 PDF 后，逐页查找各级标题首次出现的位置，再换算成正文页码。
"""
import argparse
from docx import Document
from docx.oxml.ns import qn

KEYS = ["文档说明", "最小权限", "路径规范化", "六项指标", "哈希审计", "一分钟口径", "代码位置与证据索引"]

ap = argparse.ArgumentParser()
ap.add_argument("docx")
ap.add_argument("--pages", required=True, help="逗号分隔的页码，按 KEYS 顺序")
args = ap.parse_args()
pages = [p.strip() for p in args.pages.split(",")]
assert len(pages) == len(KEYS), "页码个数应为 %d" % len(KEYS)

d = Document(args.docx)
fixed = 0
for para in d.paragraphs:
    if "\t" not in para.text:
        continue
    for key, page in zip(KEYS, pages):
        if para.text.startswith(("1　", "2　", "3　", "4　", "5　", "6　", "附录　")) and key in para.text:
            ts = [t for t in para._p.iter(qn("w:t")) if (t.text or "").strip().isdigit()]
            if ts and ts[-1].text != page:
                ts[-1].text = page
                fixed += 1
            break
d.save(args.docx)
print("校正页码条目：%d" % fixed)
