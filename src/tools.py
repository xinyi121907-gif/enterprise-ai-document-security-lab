from pathlib import Path

from .contracts import ToolRequest
from .policy_gate import authorize_tool


def _read_text(path: str) -> str:
    return Path(path).read_text(encoding="utf-8")


def execute_tool_protected(req: ToolRequest, current_upload: str) -> dict:
    policy = authorize_tool(req, current_upload)
    if policy.decision != "ALLOW":
        return {"executed": False, "policy": policy, "content": None}
    return {
        "executed": True,
        "policy": policy,
        "content": _read_text(policy.normalized_path),
    }


def execute_tool_vulnerable(tool_name: str, target_path: str) -> dict:
    """Intentionally unsafe; local fictional demonstration only."""
    if tool_name in {"read_uploaded_file", "read_internal_file"}:
        return {"executed": True, "content": _read_text(target_path)}
    return {"executed": False, "content": None}

