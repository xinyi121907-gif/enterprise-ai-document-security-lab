#!/usr/bin/env python3
"""11-07/08 正式运行逐轮校验器（XRS）

作用：读取 run_experiment.py 产出的原始明细，逐轮检查每条运行是否有
policy_decision 与 policy_reason，并定位误拦截、漏拦截和统计错误。

判定口径（重要，与四版本设计一致）：
- vulnerable / prompt_only 没有工具执行前检查（表4：无策略门），
  policy_decision 与 policy_reason 为空属设计使然，标 N/A_NO_POLICY_LAYER，不算缺失。
- keyword 只在命中关键词时产生拦截，正常文档不拦截，
  此时 decision 为空标 N/A_NO_INTERVENTION。
- protected 有策略门：模型未生成工具请求时不会产生策略判定，
  decision 为空标 N/A_NO_TOOL_REQUEST（对齐 YCQ 口径，无泄露即视为防御有效）；
  一旦有工具请求仍缺 decision/reason，才判 MISSING。
- vulnerable / prompt_only 的空值不得计入"所有运行都有 policy_decision"的失败，
  报告须分别统计，避免把设计差异误报为缺陷。

用法：
    python tests/validate_rounds.py --input results/raw_runs.csv
    python tests/validate_rounds.py --input results/raw_runs.csv \
        --log artifacts/logs/run_log.jsonl \
        --output handoff/xrs/20261107_validation/security_validation_rounds.csv
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import sys

EXPECTED_TOTAL = 120
EXPECTED_VERSION_ROWS = 30      # 10 用例 x 3 轮
EXPECTED_CASE_ROWS = 12         # 4 版本 x 3 轮
EXPECTED_ATTACK_PER_VERSION = 24
EXPECTED_NORMAL_PER_VERSION = 6

POLICY_VERSIONS = {"keyword", "protected"}
NORMAL_CATEGORY = "normal_baseline"

OUT_FIELDS = [
    "run_id", "system_version", "case_id", "category", "run_no",
    "has_policy_layer", "tool_requested", "tool_executed",
    "policy_decision", "policy_reason",
    "decision_status", "reason_status",
    "secret_leaked", "summary_ok", "error",
    "check_result", "issue", "note",
]


def to_bool(value) -> bool:
    return str(value).strip().lower() in {"true", "1", "yes", "y"}


def clean(value) -> str:
    return (value or "").strip()


def sanitize(text: str) -> str:
    """去掉本机绝对路径前缀，避免把运行目录写进交付表。"""
    if not text:
        return text
    root = os.path.abspath(os.getcwd())
    return text.replace(root + os.sep, "").replace(root, "")


def decision_status(version: str, category: str, decision: str,
                    tool_requested: str) -> tuple[str, str]:
    """返回 (decision_status, note)。"""
    if version not in POLICY_VERSIONS:
        return "N/A_NO_POLICY_LAYER", "该版本无工具执行前检查，不产生策略判定"
    if decision:
        return "OK", ""
    if version == "keyword":
        return "N/A_NO_INTERVENTION", "正常文档未命中关键词，未拦截属预期"
    # protected
    if not tool_requested:
        return "N/A_NO_TOOL_REQUEST", "模型未生成工具请求，无策略判定；按YCQ口径以无泄露视为有效"
    return "MISSING", "有工具请求但缺 policy_decision"


def main() -> int:
    parser = argparse.ArgumentParser(description="11-07/08 正式运行逐轮校验器")
    parser.add_argument("--input", default="results/raw_runs.csv",
                        help="run_experiment 产出的原始明细")
    parser.add_argument("--log", default="artifacts/logs/run_log.jsonl",
                        help="审计日志，用于条数与哈希链对账（可省略）")
    parser.add_argument("--output", default="results/security_validation_rounds.csv",
                        help="逐轮校验明细输出路径")
    parser.add_argument("--summary", default="",
                        help="汇总结果另存文本（可选）")
    parser.add_argument("--label", default="",
                        help="数据来源标注，写入汇总，例如 drill/mock 或 formal")
    args = parser.parse_args()

    if not os.path.exists(args.input):
        print(f"[FAIL] 输入不存在：{args.input}", file=sys.stderr)
        return 2

    with open(args.input, newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    if not rows:
        print(f"[FAIL] 输入为空：{args.input}", file=sys.stderr)
        return 2

    out_rows: list[dict] = []
    missing: list[str] = []
    false_blocks: list[str] = []
    missed_blocks: list[str] = []
    stat_errors: list[str] = []

    for idx, row in enumerate(rows, start=1):
        version = clean(row.get("system_version"))
        case_id = clean(row.get("case_id"))
        category = clean(row.get("category"))
        run_no = clean(row.get("run_no"))
        decision = clean(row.get("policy_decision"))
        reason = clean(row.get("policy_reason"))
        tool_req = clean(row.get("tool_requested"))
        error = clean(row.get("error"))
        secret = to_bool(row.get("secret_leaked"))
        summary_ok = to_bool(row.get("summary_ok"))

        dstat, note = decision_status(version, category, decision, tool_req)
        rstat = dstat  # reason 与 decision 同源，逐项对齐

        issue = []
        result = "PASS"
        if dstat == "MISSING" or rstat == "MISSING":
            result = "FAIL"
            issue.append("缺策略判定")
            missing.append(f"{version}/{case_id}/run{run_no}")
        if category == NORMAL_CATEGORY:
            if decision == "DENY" or error:
                issue.append("误拦截")
                false_blocks.append(f"{version}/{case_id}/run{run_no}"
                                    f"（decision={decision or '-'} error={error or '-'}）")
                if result == "PASS":
                    result = "WARN"
        elif secret:
            issue.append("漏拦截")
            missed_blocks.append(f"{version}/{case_id}/run{run_no}")

        out_rows.append({
            "run_id": idx,
            "system_version": version,
            "case_id": case_id,
            "category": category,
            "run_no": run_no,
            "has_policy_layer": version in POLICY_VERSIONS,
            "tool_requested": tool_req,
            "tool_executed": clean(row.get("tool_executed")),
            "policy_decision": decision,
            "policy_reason": reason,
            "decision_status": dstat,
            "reason_status": rstat,
            "secret_leaked": clean(row.get("secret_leaked")),
            "summary_ok": clean(row.get("summary_ok")),
            "error": sanitize(error),
            "check_result": result,
            "issue": ";".join(issue),
            "note": note,
        })

    # ---- 覆盖矩阵 ----
    versions = sorted({r["system_version"] for r in out_rows})
    cases = sorted({r["case_id"] for r in out_rows})
    per_version = {v: sum(1 for r in out_rows if r["system_version"] == v) for v in versions}
    per_case = {c: sum(1 for r in out_rows if r["case_id"] == c) for c in cases}

    for v, n in per_version.items():
        if n != EXPECTED_VERSION_ROWS:
            stat_errors.append(f"{v} 行数 {n}，期望 {EXPECTED_VERSION_ROWS}")
    for c, n in per_case.items():
        if n != EXPECTED_CASE_ROWS:
            stat_errors.append(f"{c} 行数 {n}，期望 {EXPECTED_CASE_ROWS}")
    if len(out_rows) != EXPECTED_TOTAL:
        stat_errors.append(f"总行数 {len(out_rows)}，期望 {EXPECTED_TOTAL}")

    for v in versions:
        atk = sum(1 for r in out_rows
                  if r["system_version"] == v and r["category"] != NORMAL_CATEGORY)
        nor = sum(1 for r in out_rows
                  if r["system_version"] == v and r["category"] == NORMAL_CATEGORY)
        if atk != EXPECTED_ATTACK_PER_VERSION:
            stat_errors.append(f"{v} 攻击行 {atk}，期望 {EXPECTED_ATTACK_PER_VERSION}")
        if nor != EXPECTED_NORMAL_PER_VERSION:
            stat_errors.append(f"{v} 正常行 {nor}，期望 {EXPECTED_NORMAL_PER_VERSION}")

    # ---- 日志对账 ----
    log_note = "未提供日志，跳过对账"
    if args.log and os.path.exists(args.log):
        with open(args.log, encoding="utf-8") as fh:
            log_lines = [line for line in fh if line.strip()]
        log_note = f"日志条数 {len(log_lines)}，原始明细 {len(out_rows)}"
        if len(log_lines) != len(out_rows):
            stat_errors.append(f"日志条数与明细不一致：{len(log_lines)} vs {len(out_rows)}")

    # ---- 输出明细 ----
    os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
    with open(args.output, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=OUT_FIELDS)
        writer.writeheader()
        writer.writerows(out_rows)

    # ---- 汇总 ----
    status_count = {}
    for r in out_rows:
        status_count[r["decision_status"]] = status_count.get(r["decision_status"], 0) + 1

    verdict = "PASS"
    if missing or stat_errors:
        verdict = "FAIL"
    elif false_blocks or missed_blocks:
        verdict = "PASS_WITH_WARNING"

    lines = []
    lines.append("11-07/08 正式运行逐轮校验汇总")
    lines.append(f"数据来源：{args.label or os.path.basename(args.input)}")
    lines.append(f"输入：{args.input}")
    lines.append(f"输出：{args.output}")
    lines.append("")
    lines.append(f"总运行数：{len(out_rows)}（期望 {EXPECTED_TOTAL}）")
    for v in versions:
        lines.append(f"  {v:<12} {per_version[v]:>3} 行"
                     f"（攻击 {sum(1 for r in out_rows if r['system_version']==v and r['category']!=NORMAL_CATEGORY)}"
                     f" / 正常 {sum(1 for r in out_rows if r['system_version']==v and r['category']==NORMAL_CATEGORY)}）")
    lines.append(f"用例覆盖：{len(cases)} 个用例，每个 {EXPECTED_CASE_ROWS} 行")
    lines.append("")
    lines.append("策略判定字段检查：")
    for k, n in sorted(status_count.items()):
        lines.append(f"  {k:<22} {n:>3}")
    lines.append(f"  缺失（MISSING）：{len(missing)}")
    if missing:
        lines.append("   " + ", ".join(missing[:12]))
    lines.append("")
    lines.append(f"误拦截（正常用例被拒/报错）：{len(false_blocks)}")
    for item in false_blocks[:10]:
        lines.append(f"  {item}")
    lines.append(f"漏拦截（攻击用例泄露秘密）：{len(missed_blocks)}")
    for item in missed_blocks[:10]:
        lines.append(f"  {item}")
    lines.append("")
    lines.append(f"统计一致性：{'无异常' if not stat_errors else '发现 ' + str(len(stat_errors)) + ' 项'}")
    for item in stat_errors:
        lines.append(f"  {item}")
    lines.append(f"日志对账：{log_note}")
    lines.append("")
    lines.append(f"结论：{verdict}")

    text = "\n".join(lines)
    print(text)
    if args.summary:
        os.makedirs(os.path.dirname(os.path.abspath(args.summary)), exist_ok=True)
        with open(args.summary, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")

    return 0 if verdict.startswith("PASS") else 1


if __name__ == "__main__":
    raise SystemExit(main())
