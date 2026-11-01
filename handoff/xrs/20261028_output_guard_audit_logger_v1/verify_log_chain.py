#!/usr/bin/env python3
"""任务4（10-31）交付物 · verify_log_chain.py

对 run_log_sample.jsonl 做哈希链校验：
  1. 原始日志哈希链应完整通过（每条记录被篡改都会导致校验失败）；
  2. 演示"任意修改一条日志后校验失败"。
"""
import json
import sys
from copy import deepcopy
from pathlib import Path

# 将仓库根目录加入 sys.path，保证 `from src import audit_logger` 可用，
# 无论从仓库哪个位置运行本脚本。
REPO_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO_ROOT))

from src import audit_logger  # noqa: E402

SAMPLE = Path(__file__).resolve().parent / "run_log_sample.jsonl"


def load_records() -> list[dict]:
    return [
        json.loads(line)
        for line in SAMPLE.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def main() -> int:
    records = load_records()
    print(f"读取日志记录：{len(records)} 条（{SAMPLE}）")

    intact = audit_logger.verify_log_chain(records)
    print(f"原始日志哈希链校验：{intact}")

    # 任意修改一条记录（把第 2 条的 case_id 改掉）
    tampered = deepcopy(records)
    tampered[1]["case_id"] = "TAMPERED"
    tampered_chain = audit_logger.verify_log_chain(tampered)
    print(f"篡改第 2 条日志后校验：{tampered_chain}")

    if not intact:
        print("FAIL：原始日志哈希链未通过校验。")
        return 1
    if tampered_chain:
        print("FAIL：篡改后校验不应通过，哈希链未起到防篡改作用。")
        return 1

    print("OK：哈希链完整可校验；任意修改一条日志后校验失败，满足通过标准。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
