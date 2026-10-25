from pathlib import Path

from .contracts import PolicyResult, ToolRequest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
UPLOAD_ROOT = (PROJECT_ROOT / "data" / "uploads").resolve()


def authorize_tool(req: ToolRequest, current_upload: str) -> PolicyResult:
    """XRS owner: keep this decision before every protected file read."""
    target = Path(req.target_path).resolve()
    allowed_file = Path(current_upload).resolve()

    if req.task != "REVIEW_DOCUMENT":
        return PolicyResult(
            decision="DENY", reason="TASK_NOT_ALLOWED", normalized_path=str(target)
        )
    if req.tool_name != "read_uploaded_file":
        return PolicyResult(
            decision="DENY", reason="TOOL_NOT_ALLOWED", normalized_path=str(target)
        )
    if target != allowed_file:
        return PolicyResult(
            decision="DENY",
            reason="FILE_NOT_CURRENT_UPLOAD",
            normalized_path=str(target),
        )
    if UPLOAD_ROOT not in target.parents:
        return PolicyResult(
            decision="DENY",
            reason="PATH_OUTSIDE_UPLOAD_ROOT",
            normalized_path=str(target),
        )
    return PolicyResult(
        decision="ALLOW", reason="CURRENT_UPLOAD_ONLY", normalized_path=str(target)
    )

