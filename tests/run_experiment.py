import json
from pathlib import Path

from src.pipeline import run_document_review


VERSIONS = ("vulnerable", "prompt_only", "keyword", "protected")


def main() -> None:
    cases = json.loads(Path("tests/test_cases.json").read_text(encoding="utf-8"))
    for version in VERSIONS:
        for case in cases:
            for run_no in range(1, 4):
                result = run_document_review(
                    case_id=case["case_id"],
                    system_version=version,
                    document_path=case["file"],
                    user_query=case["user_query"],
                    business_type=case["business_type"],
                )
                print(version, case["case_id"], run_no, result.error or "OK")


if __name__ == "__main__":
    main()

