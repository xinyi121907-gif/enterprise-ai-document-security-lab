"""
ZL 冒烟测试脚本：对 test_cases.json 中 10 个用例各运行一次（不计入最终指标）
固定入口（由 CXY 冻结，勿改）:
    from src.pipeline import run_document_review
    run_document_review(case_id, system_version, document_path, user_query, business_type)
    -> RunResult；记录字段用 result.model_dump()
用法（在本机仓库根目录、已激活 venv 下运行）:
    python tests/smoke_test_10cases.py
    可选: --version keyword / prompt_only / protected ; --cases 指定用例文件
交付:
    results/smoke_test_10cases.csv   （10 行记录）
    校验: 所有 case_id 均被识别；artifacts/logs/run_log.jsonl 无日志字段缺失
"""
import argparse
import csv
import json
import sys
import time
from pathlib import Path

# 关键修复：先把项目根目录加入 sys.path，否则找不到 src 包
PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from src.pipeline import run_document_review   # 冻结入口，勿改函数名和参数

# RunResult / 日志应包含的字段（对应 src/contracts.py）
REQUIRED_LOG_FIELDS = [
    "case_id", "system_version", "final_text", "tool_requested",
    "tool_executed", "policy_decision", "policy_reason", "secret_leaked",
    "summary_ok", "error", "timestamp", "previous_hash", "record_hash",
]


def load_cases(path: str):
    """读取 test_cases.json，兼容顶层直接是列表或包了一层 {"cases":[...]} 的结构。"""
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(raw, dict):
        for key in ("cases", "test_cases", "data"):
            if key in raw:
                return raw[key]
        raise ValueError(
            "test_cases.json 顶层结构无法识别，实际 keys=" + str(list(raw.keys()))
        )
    return raw


def map_case(raw: dict, system_version: str) -> dict:
    """字段映射：把 test_cases.json 的字段映射到 run_document_review 需要的 5 个参数。"""
    document_path = (
        raw.get("document_path") or raw.get("file")
        or raw.get("path") or raw.get("doc_path") or raw.get("file_path")
    )
    user_query = raw.get("user_query") or "请审阅这份文档"
    business_type = (
        raw.get("business_type") or raw.get("business")
        or raw.get("type") or "resume_review"
    )
    case_id = raw.get("case_id") or raw.get("id") or raw.get("test_id")
    return {
        "case_id": case_id,
        "system_version": system_version,
        "document_path": document_path,
        "user_query": user_query,
        "business_type": business_type,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cases", default="tests/test_cases.json")
    ap.add_argument("--version", default="vulnerable",
                    choices=["vulnerable", "prompt_only", "keyword", "protected"])
    ap.add_argument("--out", default="results/smoke_test_10cases.csv")
    ap.add_argument("--log", default="artifacts/logs/run_log.jsonl")
    args = ap.parse_args()

    cases = load_cases(str(PROJECT_ROOT / args.cases))
    print(f"[INFO] 读取到 {len(cases)} 个用例，来源 {args.cases}，版本 {args.version}")

    rows = []
    for idx, raw in enumerate(cases, 1):
        row = dict(raw)
        try:
            params = map_case(raw, args.version)
            if not params["case_id"] or not params["document_path"]:
                raise ValueError(
                    f"缺少 case_id 或 document_path，原始记录={json.dumps(raw, ensure_ascii=False)}"
                )
            t0 = time.time()
            result = run_document_review(**params)
            d = result.model_dump() if hasattr(result, "model_dump") else dict(result)
            row.update(d)
            row["recognized"] = "YES"
            row["elapsed_ms"] = int((time.time() - t0) * 1000)
        except Exception as e:
            row["recognized"] = "NO"
            row["tool_executed"] = False
            row["secret_leaked"] = False
            row["summary_ok"] = False
            row["error"] = f"{type(e).__name__}: {e}"
            row["elapsed_ms"] = -1
        rows.append(row)
        print(f"[{idx}/{len(cases)}] {row.get('case_id', '?')} "
              f"recognized={row.get('recognized')} error={row.get('error')}")

    out = PROJECT_ROOT / args.out
    out.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = list(rows[0].keys()) if rows else []
    with out.open("w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(rows)
    print(f"[INFO] 已写出 {out}，共 {len(rows)} 行")

    log = PROJECT_ROOT / args.log
    missing = {}
    if log.exists():
        for i, line in enumerate(log.read_text(encoding="utf-8").splitlines()):
            if not line.strip():
                continue
            rec = json.loads(line)
            m = [k for k in REQUIRED_LOG_FIELDS if k not in rec]
            if m:
                missing[rec.get("case_id", f"line{i}")] = m
    print("[CHECK] 日志字段缺失:", missing if missing else "无，字段齐全")

    all_recognized = all(r["recognized"] == "YES" for r in rows)
    print(f"[RESULT] 全部 case_id 被识别: {all_recognized}；日志字段缺失: {len(missing)} 条")
    return 0 if all_recognized and not missing else 1


if __name__ == "__main__":
    sys.exit(main())
