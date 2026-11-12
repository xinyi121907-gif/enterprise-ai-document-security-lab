#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""11-12 复测：重建逐轮校验明细，并输出与 11-08 交付的逐字段差异表。

用法（在仓库根目录执行）：
    python3 handoff/xrs/20261112_retest/_build/rebuild_retest_outputs.py

产物（写入 handoff/xrs/20261112_retest/）：
    security_validation_rounds_retest.csv       120 行复测明细，md5 5d90a4e4054ac0297450673f73feb273
    security_validation_rounds_retest_diff.csv  与 11-08 交付逐字段差异（120 条，均为 data_source 列）

不重跑模型：数据来自 handoff/zl/2026_11_8/ 已入库的正式 CSV 与 JSONL。
2026-11-12 已实际运行验证：明细 120 行、md5 与复测时一致、非标注列差异 0。
"""
import csv
import hashlib
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
OUT = ROOT / 'handoff/xrs/20261112_retest'
BASE = ROOT / 'handoff/xrs/20261108_rounds123/security_validation_rounds.csv'
CSV = ROOT / 'handoff/zl/2026_11_8/raw_runs_all.csv'
LOG = ROOT / 'handoff/zl/2026_11_8/raw_runs_all_log_120.jsonl'
RETEST = OUT / 'security_validation_rounds_retest.csv'

cmd = [sys.executable, 'tests/validate_rounds.py',
       '--input', str(CSV), '--log', str(LOG),
       '--output', str(RETEST),
       '--summary', str(OUT / 'validation_summary_retest.txt'),
       '--label', 'zl_rounds123_retest_20261112',
       '--cases', 'tests/test_cases.json', '--rounds', '3']
subprocess.run(cmd, cwd=str(ROOT), check=True)

new = list(csv.DictReader(open(RETEST, encoding='utf-8')))
old = list(csv.DictReader(open(BASE, encoding='utf-8')))
if len(new) != len(old):
    raise SystemExit('行数不一致：%d vs %d' % (len(new), len(old)))

diffs = []
for i, (a, b) in enumerate(zip(new, old), 1):
    for c in a:
        if a.get(c) != b.get(c):
            diffs.append([i, a.get('system_version'), a.get('case_id'), a.get('run_no'), c, b.get(c), a.get(c)])

with open(OUT / 'security_validation_rounds_retest_diff.csv', 'w', encoding='utf-8', newline='') as f:
    w = csv.writer(f, lineterminator='\n')
    w.writerow(['row_no', 'system_version', 'case_id', 'run_no', 'field', 'baseline_value', 'retest_value'])
    w.writerows(diffs)

print('明细行数：%d' % len(new))
print('差异条目：%d（全部为 data_source：%s）' % (len(diffs), all(d[4] == 'data_source' for d in diffs)))
print('md5：%s' % hashlib.md5(RETEST.read_bytes()).hexdigest())
print('期望 md5：5d90a4e4054ac0297450673f73feb273')
