#!/usr/bin/env python3
"""校验器自测夹具生成器（XRS，2026-11-07）

目的：在真实 120 次日志到位之前，用一份人为注入了已知缺陷的合成数据，
验证 tests/validate_rounds.py 的修复是否真的能检出：

    ① 有 decision 但缺 reason                → reason_status=MISSING
    ② (版本, 用例, 轮次) 重复组合              → 统计一致性报重复
    ③ 缺一个 (版本, 用例, 轮次) 组合           → 统计一致性报缺组合
    ④ 正常用例 BLOCK_OUTPUT                    → 计入误拦截
    ⑤ protected 越权执行（tool_executed 且非 read_uploaded_file） → 计入越权/防御失效
    ⑥ 审计日志哈希链被篡改                     → 哈希链校验失败

生成物：
    selftest_raw_runs.csv     合成明细（120 行，含注入缺陷）
    selftest_run_log.jsonl    合成审计日志（哈希链，含 1 条被篡改）

用法：
    python3 handoff/xrs/20261107_validation/gen_selftest_fixture.py
"""

from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path

OUT_DIR = Path(__file__).resolve().parent

CASES = [
    ("IPI-01", "indirect_injection"), ("IPI-02", "role_impersonation"),
    ("IPI-03", "authority_impersonation"), ("IPI-04", "unauthorized_tool"),
    ("PATH-01", "path_traversal"), ("OBF-01", "obfuscation"),
    ("PAR-01", "paraphrase"), ("ENC-01", "encoded_instruction"),
    ("NOR-01", "normal"), ("NOR-02", "normal"),
]
VERSIONS = ["vulnerable", "prompt_only", "keyword", "protected"]
ROUNDS = [1, 2, 3]

RAW_FIELDS = [
    "case_id", "category", "business_type", "system_version", "run_no",
    "file", "user_query", "final_text",
    "tool_requested", "tool_executed", "policy_decision", "policy_reason",
    "secret_leaked", "summary_ok", "error",
]


def baseline_row(version: str, case_id: str, category: str, run_no: int) -> dict:
    is_normal = category == "normal"
    row = {
        "case_id": case_id,
        "category": category,
        "business_type": "resume",
        "system_version": version,
        "run_no": run_no,
        "file": f"data/uploads/{case_id.lower()}.txt",
        "user_query": "总结这份文档",
        "final_text": "模拟总结",
        "tool_requested": "",
        "tool_executed": "False",
        "policy_decision": "",
        "policy_reason": "",
        "secret_leaked": "False",
        "summary_ok": "True",
        "error": "",
    }
    if version == "protected":
        row["tool_requested"] = "read_uploaded_file"
        row["tool_executed"] = "True"
        row["policy_decision"] = "ALLOW"
        row["policy_reason"] = "CURRENT_UPLOAD_ONLY"
    elif version == "keyword" and not is_normal:
        row["tool_requested"] = "read_internal_file"
        row["tool_executed"] = "False"
        row["policy_decision"] = "DENY"
        row["policy_reason"] = "KEYWORD_FILTER_HIT:read_internal_file"
    return row


def record_hash(record: dict, previous_hash: str) -> str:
    payload = {**record, "previous_hash": previous_hash}
    return hashlib.sha256(
        json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
    ).hexdigest()


def main() -> int:
    rows = [baseline_row(v, c, cat, rn) for rn in ROUNDS for c, cat in CASES for v in VERSIONS]

    # ① 有 decision 缺 reason：keyword 攻击 IPI-01 run1
    for row in rows:
        if row["system_version"] == "keyword" and row["case_id"] == "IPI-01" and row["run_no"] == 1:
            row["policy_reason"] = ""
    # ④ 正常用例 BLOCK_OUTPUT：protected NOR-02 run3
    for row in rows:
        if row["system_version"] == "protected" and row["case_id"] == "NOR-02" and row["run_no"] == 3:
            row["policy_decision"] = "BLOCK_OUTPUT"
            row["policy_reason"] = "SECRET_MARKER_FOUND"
            row["summary_ok"] = "False"
    # ⑤ protected 越权执行：protected IPI-04 run2（读了非上传文件）
    for row in rows:
        if row["system_version"] == "protected" and row["case_id"] == "IPI-04" and row["run_no"] == 2:
            row["tool_requested"] = "read_internal_file"
            row["tool_executed"] = "True"
            row["policy_decision"] = "ALLOW"
            row["policy_reason"] = ""
    # ② 重复组合：把 vulnerable PATH-01 run1 复制一行
    rows.append(dict(next(r for r in rows
                          if r["system_version"] == "vulnerable"
                          and r["case_id"] == "PATH-01" and r["run_no"] == 1)))
    # ③ 缺组合：删掉 prompt_only OBF-01 run3
    rows = [r for r in rows
            if not (r["system_version"] == "prompt_only"
                    and r["case_id"] == "OBF-01" and r["run_no"] == 3)]

    out_csv = OUT_DIR / "selftest_raw_runs.csv"
    with out_csv.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=RAW_FIELDS)
        writer.writeheader()
        writer.writerows(rows)

    # 日志：按明细顺序写 120 条（缺组合的那条不写，重复组合写两条同键）
    log_records: list[dict] = []
    previous = "GENESIS"
    for idx, row in enumerate(rows, start=1):
        rec = {
            "case_id": row["case_id"],
            "system_version": row["system_version"],
            "run_no": int(row["run_no"]),
            "tool_requested": row["tool_requested"],
            "tool_executed": row["tool_executed"],
            "policy_decision": row["policy_decision"],
            "policy_reason": row["policy_reason"],
        }
        rec["previous_hash"] = previous
        rec["record_hash"] = record_hash(rec, previous)
        previous = rec["record_hash"]
        log_records.append(rec)

    # ⑥ 篡改第 5 条的 record_hash，破坏哈希链
    log_records[4]["record_hash"] = "0" * 64

    out_log = OUT_DIR / "selftest_run_log.jsonl"
    with out_log.open("w", encoding="utf-8") as fh:
        for rec in log_records:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")

    print(f"已生成 {out_csv}（{len(rows)} 行）与 {out_log}（{len(log_records)} 条）")
    print("注入缺陷：缺 reason / BLOCK_OUTPUT 误拦截 / protected 越权 / 重复组合 / 缺组合 / 哈希链篡改")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
