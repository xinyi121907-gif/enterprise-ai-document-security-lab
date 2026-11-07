"""
11月7日 第1轮正式测试：4 版本 × 10 用例 × 1 轮 = 40 次
用法（项目根目录）: python -m tests.run_round1
输出: results/raw_runs_round1.csv（23 列，与 raw_runs_template.csv 对齐）
日志: 保留 artifacts/logs/run_log.jsonl，并把本轮新增行另存 artifacts/logs/round1_run_log.jsonl
"""
import csv
import json
import time
from datetime import datetime
from pathlib import Path

from src.pipeline import run_document_review

VERSIONS = ("vulnerable", "prompt_only", "keyword", "protected")
OUTPUT = Path("results/raw_runs_round1.csv")
LOG = Path("artifacts/logs/run_log.jsonl")
ROUND_LOG = Path("artifacts/logs/round1_run_log.jsonl")

HEADERS = [
    "run_id", "system_version", "case_id", "case_type", "run_no",
    "business_type", "document_path", "user_query", "start_time", "elapsed_ms",
    "tool_requested", "target_path", "normalized_path", "tool_executed",
    "policy_decision", "policy_reason", "secret_leaked", "summary_ok", "error",
    "log_path", "previous_hash", "record_hash", "note",
]


def classify(case_id: str) -> str:
    return "normal" if str(case_id).upper().startswith("NOR") else "attack"


def count_lines(p: Path) -> int:
    if not p.exists():
        return 0
    with p.open(encoding="utf-8") as f:
        return sum(1 for _ in f)


def main() -> None:
    cases = json.loads(Path("tests/test_cases.json").read_text(encoding="utf-8"))
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    start_lines = count_lines(LOG)

    rows = []
    run_id = 0
    for version in VERSIONS:
        for case in cases:
            run_id += 1
            start_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            t0 = time.time()
            try:
                result = run_document_review(
                    case_id=case["case_id"],
                    system_version=version,
                    document_path=case["file"],
                    user_query=case["user_query"],
                    business_type=case["business_type"],
                )
                d = result.model_dump()
                err = d.get("error") or ""
            except Exception as e:  # 崩溃也如实记录，不中断整轮
                d = {}
                err = f"EXCEPTION: {type(e).__name__}: {e}"
            elapsed = int((time.time() - t0) * 1000)

            rows.append({
                "run_id": f"R1-{run_id:03d}",
                "system_version": version,
                "case_id": case["case_id"],
                "case_type": classify(case["case_id"]),
                "run_no": 1,
                "business_type": case["business_type"],
                "document_path": case["file"],
                "user_query": case["user_query"],
                "start_time": start_time,
                "elapsed_ms": elapsed,
                "tool_requested": d.get("tool_requested", ""),
                "target_path": d.get("target_path", ""),
                "normalized_path": d.get("normalized_path", ""),
                "tool_executed": d.get("tool_executed", ""),
                "policy_decision": d.get("policy_decision", ""),
                "policy_reason": d.get("policy_reason", ""),
                "secret_leaked": d.get("secret_leaked", ""),
                "summary_ok": d.get("summary_ok", ""),
                "error": err,
                "log_path": str(LOG) if version == "protected" else "",
                "previous_hash": d.get("previous_hash", ""),
                "record_hash": d.get("record_hash", ""),
                "note": "",
            })
            print(f"R1-{run_id:03d} {version} {case['case_id']} elapsed={elapsed}ms  {err or 'OK'}")

    with open(OUTPUT, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=HEADERS)
        w.writeheader()
        w.writerows(rows)

    # 本轮新增日志另存一份，方便提交 round1 日志
    new_lines = []
    if LOG.exists():
        lines = LOG.read_text(encoding="utf-8").splitlines()
        new_lines = lines[start_lines:]
        ROUND_LOG.parent.mkdir(parents=True, exist_ok=True)
        ROUND_LOG.write_text("\n".join(new_lines) + ("\n" if new_lines else ""), encoding="utf-8")

    print(f"\n已写出 {len(rows)} 行 -> {OUTPUT}")
    print(f"第1轮新增日志 {len(new_lines)} 行 -> {ROUND_LOG}")
    print(f"预期 40 行；实际 {len(rows)} 行")


if __name__ == "__main__":
    main()
#（注：内容由AI生成）
