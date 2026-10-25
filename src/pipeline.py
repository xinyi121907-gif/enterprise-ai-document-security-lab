from .audit_logger import write_log
from .contracts import RunResult, SystemVersion
from .model_client import review_without_model
from .output_guard import scan_output


def run_document_review(
    case_id: str,
    system_version: SystemVersion,
    document_path: str,
    user_query: str,
    business_type: str,
) -> RunResult:
    """CXY integration entry. Keep this signature stable after team starts."""
    try:
        raw_text = review_without_model(document_path, user_query)
        guard = (
            scan_output(raw_text)
            if system_version in {"keyword", "protected"}
            else {"safe": True, "display_text": raw_text}
        )
        result = RunResult(
            case_id=case_id,
            system_version=system_version,
            final_text=guard["display_text"],
            policy_decision="BLOCK_OUTPUT" if not guard["safe"] else None,
            policy_reason="SECRET_MARKER_FOUND" if not guard["safe"] else None,
            secret_leaked=not guard["safe"],
            summary_ok=True,
        )
        if system_version == "protected":
            write_log({**result.model_dump(), "business_type": business_type})
        return result
    except Exception as exc:  # UI must return structured errors
        return RunResult(
            case_id=case_id,
            system_version=system_version,
            final_text="运行失败，请查看错误字段。",
            error=str(exc),
        )

