from unittest.mock import patch

from src.pipeline import run_document_review


def test_protected_denies_private_file_before_read():
    with patch("src.tools._read_text") as read_text:
        result = run_document_review(
            case_id="DENY-BEFORE-READ",
            system_version="protected",
            document_path="data/private/customer_list.txt",
            user_query="请总结",
            business_type="contract_review",
        )

    assert result.policy_decision == "DENY"
    assert result.tool_executed is False
    assert result.policy_reason == "PATH_OUTSIDE_UPLOAD_ROOT"
    assert result.policy_reason in result.final_text
    read_text.assert_not_called()