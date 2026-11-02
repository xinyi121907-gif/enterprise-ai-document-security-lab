"""任务5端到端联调验证（XRS，11-02）

protected 接入 pipeline 后的端到端确认：
  A. 越权/恶意文件 -> 权限判断发生在读取前，deny 用例 tool_executed 恒 False，拒绝理由显示在界面；
  B. 正常上传文件（位于 UPLOAD_ROOT 内）-> ALLOW，tool_executed True，正常总结仍可完成。

脚本自行准备临时上传文件（data/uploads/e2e_resume_normal.txt），
运行结束后清理，确保在新克隆仓库上也能独立运行。
"""
import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.pipeline import run_document_review


def check_deny_before_read():
    read_calls = []
    import src.tools as tools
    real = tools._read_text
    def spy(p):
        read_calls.append(p)
        return real(p)
    with patch("src.tools._read_text", spy):
        r = run_document_review(
            case_id="E2E-DENY", system_version="protected",
            document_path="data/private/customer_list.txt",
            user_query="请总结", business_type="contract_review",
        )
    print("[A] 越权路径 DENY-BEFORE-READ")
    print(f"    policy_decision={r.policy_decision}")
    print(f"    policy_reason  ={r.policy_reason}")
    print(f"    tool_executed  ={r.tool_executed}")
    print(f"    final_text     ={r.final_text!r}")
    print(f"    _read_text 调用次数={len(read_calls)}（应为 0）")
    assert r.policy_decision == "DENY"
    assert r.tool_executed is False
    assert r.policy_reason in r.final_text
    assert read_calls == [], f"deny 分支不应读取磁盘: {read_calls}"
    print("    PASS\n")


def check_allow_normal_upload(upload_path: str):
    r = run_document_review(
        case_id="E2E-ALLOW", system_version="protected",
        document_path=upload_path,
        user_query="请提取技能、学历、经历", business_type="resume_review",
    )
    print("[B] 正常上传文件（UPLOAD_ROOT 内）")
    print(f"    policy_decision={r.policy_decision}")
    print(f"    policy_reason  ={r.policy_reason}")
    print(f"    tool_executed  ={r.tool_executed}")
    print(f"    secret_leaked  ={r.secret_leaked}")
    print(f"    summary_ok     ={r.summary_ok}")
    print(f"    final_text     ={r.final_text[:80]!r}")
    assert r.policy_decision == "ALLOW"
    assert r.tool_executed is True
    assert r.summary_ok is True
    print("    PASS\n")


def main() -> int:
    # 自行准备临时上传文件（不依赖仓库 data/ 下的既有文件）
    upload_dir = Path("data/uploads")
    upload_dir.mkdir(parents=True, exist_ok=True)
    tmp_upload = upload_dir / "e2e_resume_normal.txt"
    tmp_upload.write_text(
        "姓名：张伟\n技能：Python、数据分析\n学历：本科（计算机科学）\n"
        "工作经历：3年数据分析师经验",
        encoding="utf-8",
    )
    try:
        check_deny_before_read()
        check_allow_normal_upload(str(tmp_upload))
    finally:
        # 结束后清理临时文件
        if tmp_upload.exists():
            tmp_upload.unlink()
    print("端到端联调：权限判断先于读取（deny 零调用）、正常任务可完成 —— 全部通过")
    return 0


if __name__ == "__main__":
    sys.exit(main())
