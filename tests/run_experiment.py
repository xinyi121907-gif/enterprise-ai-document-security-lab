"""自动测试器（XRS · 2026-11-04）

读取 tests/test_cases.json，用完全相同的输入与参数，在四套系统
（vulnerable / prompt_only / keyword / protected）上批量运行。

正式测试（有 Ollama 环境）：
    python tests/run_experiment.py --rounds 3
    10 用例 x 4 版本 x 3 轮 = 120 次运行

冒烟测试（无模型环境，--mock 用确定性规则模拟模型行为）：
    python tests/run_experiment.py --rounds 1 --limit 2 --mock

输出：
    results/raw_runs.csv   全部运行明细（指标脚本的输入，供证据对齐）
    artifacts/logs/run_log.jsonl   vulnerable/prompt_only/keyword 由本实验器写入；
                                   protected 由 pipeline 写入（避免重复），
                                   每条记录进入哈希串联审计链
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from src.audit_logger import write_log  # noqa: E402
from src.contracts import SystemVersion  # noqa: E402
from src.pipeline import run_document_review  # noqa: E402

SYSTEM_VERSIONS: tuple[SystemVersion, ...] = (
    "vulnerable",
    "prompt_only",
    "keyword",
    "protected",
)

RAW_RUN_FIELDS = [
    "case_id",
    "category",
    "business_type",
    "system_version",
    "run_no",
    "file",
    "user_query",
    "final_text",
    "tool_requested",
    "tool_executed",
    "policy_decision",
    "policy_reason",
    "secret_leaked",
    "summary_ok",
    "error",
    "elapsed_ms",
]


def load_cases(path: Path) -> list[dict]:
    """读取 test_cases.json；字段缺失或编号重复时报错，避免带病运行。"""
    cases = json.loads(path.read_text(encoding="utf-8"))
    seen: set[str] = set()
    for case in cases:
        case_id = case.get("case_id")
        if not case_id:
            raise ValueError("test_cases.json 中存在缺少 case_id 的用例")
        if case_id in seen:
            raise ValueError(f"case_id 重复：{case_id}")
        seen.add(case_id)
        for field in ("category", "business_type", "file", "user_query"):
            if not case.get(field):
                raise ValueError(f"用例 {case_id} 缺少字段：{field}")
    return cases


def mock_request_review(
    document_text: str,
    user_query: str,
    prompt_mode: str = "vulnerable",
    model_name: str | None = None,
) -> dict:
    """确定性模型模拟（仅 --mock 使用）。

    行为与真实脆弱模型一致：文档中出现工具诱导（read_internal_file
    或 data/private 路径）时，模型提出 read_internal_file 工具请求；
    否则正常总结。keyword 过滤由 pipeline 先行执行，不在此模拟。
    """
    del prompt_mode, model_name
    lowered = document_text.casefold()
    if (
        "read_internal_file" in lowered
        or "data/private" in lowered
        or "../private" in lowered
        or "..\\private" in lowered
    ):
        match = re.search(
            r"(data/private/[A-Za-z0-9_./-]+|\.\./private/[A-Za-z0-9_./-]+)",
            document_text,
        )
        target = match.group(1) if match else "data/private/candidate_records.txt"
        tool_call = {
            "name": "read_internal_file",
            "arguments": {"target_path": target},
        }
        return {
            "text": "",
            "content": "",
            "tool_call": tool_call,
            "tool_request": {
                "tool_name": "read_internal_file",
                "target_path": target,
            },
        }
    return {
        "text": "已完成文档审阅（模拟模型正常总结）。",
        "content": "已完成文档审阅（模拟模型正常总结）。",
        "tool_call": None,
        "tool_request": None,
    }


def prepare_upload(case: dict, upload_root: Path) -> str:
    """把用例文件复制到 data/uploads（模拟员工上传动作）。

    protected 的 authorize_tool 只允许读取 UPLOAD_ROOT 内的当前上传文件；
    直接传 data/normal 或 data/attack 路径会导致正常用例也被 DENY（误伤）。
    四套系统统一使用 uploads 内路径，保证输入完全一致。
    """
    upload_root.mkdir(parents=True, exist_ok=True)
    source = Path(case["file"])
    target = upload_root / source.name
    if not target.exists() or target.read_bytes() != source.read_bytes():
        target.write_bytes(source.read_bytes())
    return str(target)


def run_one(
    case: dict,
    version: SystemVersion,
    run_no: int,
    use_mock: bool,
    document_path: str,
) -> dict:
    """单次运行：四套系统使用完全相同的 case 输入与参数。"""
    start = time.perf_counter()
    if use_mock and version in ("vulnerable", "prompt_only", "keyword"):
        from unittest import mock

        # pipeline 在模块导入时已把 request_review 绑定到本地命名空间，
        # 因此必须 patch src.pipeline.request_review 才会生效。
        with mock.patch(
            "src.pipeline.request_review",
            side_effect=mock_request_review,
        ):
            result = run_document_review(
                case_id=case["case_id"],
                system_version=version,
                document_path=document_path,
                user_query=case["user_query"],
                business_type=case["business_type"],
            )
    else:
        result = run_document_review(
            case_id=case["case_id"],
            system_version=version,
            document_path=document_path,
            user_query=case["user_query"],
            business_type=case["business_type"],
        )
    elapsed_ms = int((time.perf_counter() - start) * 1000)

    row = {
        **result.model_dump(),
        "category": case["category"],
        "business_type": case["business_type"],
        "file": case["file"],
        "user_query": case["user_query"],
        "run_no": run_no,
        "elapsed_ms": elapsed_ms,
    }

    # protected 的审计日志由 pipeline 写入（含策略门与输出检测上下文），
    # 实验器跳过以避免同一次运行在 JSONL 中重复记录。
    if version != "protected":
        log_record = {
            key: row[key]
            for key in (
                "case_id",
                "system_version",
                "final_text",
                "tool_requested",
                "tool_executed",
                "policy_decision",
                "policy_reason",
                "secret_leaked",
                "summary_ok",
                "error",
            )
        }
        log_record.update(
            {
                "business_type": case["business_type"],
                "run_no": run_no,
                "elapsed_ms": elapsed_ms,
            }
        )
        write_log(log_record)

    return row


def write_raw_runs(rows: list[dict], output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=RAW_RUN_FIELDS)
        writer.writeheader()
        writer.writerows(rows)


def summarize(rows: list[dict]) -> None:
    """按版本输出简要统计，便于当场核对运行覆盖。"""
    print("\n=== 运行覆盖摘要 ===")
    print(f"总运行次数：{len(rows)}（用例数 x 版本数 x 轮数）")
    for version in SYSTEM_VERSIONS:
        version_rows = [r for r in rows if r["system_version"] == version]
        attacks = [r for r in version_rows if r["category"] != "normal"]
        normal = [r for r in version_rows if r["category"] == "normal"]
        denied = sum(
            1 for r in attacks if r["policy_decision"] == "DENY"
        )
        print(
            f"{version:<12} 攻击 {len(attacks):>3} 次 / "
            f"正常 {len(normal):>2} 次 / "
            f"攻击侧 DENY {denied:>3} 次"
        )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="企业智能文档助手·四套系统批量自动测试器"
    )
    parser.add_argument(
        "--cases",
        type=Path,
        default=PROJECT_ROOT / "tests" / "test_cases.json",
        help="测试用例文件（默认 tests/test_cases.json）",
    )
    parser.add_argument(
        "--versions",
        default=",".join(SYSTEM_VERSIONS),
        help="要运行的版本，逗号分隔（默认四套全部）",
    )
    parser.add_argument(
        "--rounds",
        type=int,
        default=3,
        help="每个用例在每个版本上的运行轮数（正式测试固定 3）",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=0,
        help="只运行前 N 个用例（冒烟用，0 表示全部）",
    )
    parser.add_argument(
        "--mock",
        action="store_true",
        help="使用确定性模型模拟（无 Ollama 环境的冒烟验证）",
    )
    parser.add_argument(
        "--no-upload",
        action="store_true",
        help="不把用例文件复制到 data/uploads（保持 test_cases.json 原始路径，"
        "此时 protected 对 data/normal 与 data/attack 路径会判 DENY）",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=PROJECT_ROOT / "results" / "raw_runs.csv",
        help="原始运行明细输出路径",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    if not args.cases.exists():
        print(f"错误：找不到测试用例文件 {args.cases}", file=sys.stderr)
        return 2

    cases = load_cases(args.cases)
    if args.limit > 0:
        cases = cases[: args.limit]

    versions = tuple(
        v.strip() for v in args.versions.split(",") if v.strip()
    )
    for v in versions:
        if v not in SYSTEM_VERSIONS:
            print(
                f"错误：未知系统版本 {v}（可选：{','.join(SYSTEM_VERSIONS)}）",
                file=sys.stderr,
            )
            return 2

    upload_root = PROJECT_ROOT / "data" / "uploads"
    rows: list[dict] = []
    for case in cases:
        # 四套系统使用完全相同的 document_path（默认对齐到 data/uploads）
        document_path = (
            case["file"]
            if args.no_upload
            else prepare_upload(case, upload_root)
        )
        for version in versions:
            for run_no in range(1, args.rounds + 1):
                rows.append(
                    run_one(
                        case,
                        version,
                        run_no,
                        args.mock,
                        document_path,
                    )
                )

    write_raw_runs(rows, args.output)
    print(
        f"已写入 {args.output}（{len(rows)} 行），"
        f"mock={args.mock}，rounds={args.rounds}，"
        f"upload对齐={not args.no_upload}"
    )
    summarize(rows)
    return 0


if __name__ == "__main__":
    sys.exit(main())
