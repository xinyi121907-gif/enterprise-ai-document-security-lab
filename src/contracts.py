from typing import Literal, Optional

from pydantic import BaseModel


Decision = Literal["ALLOW", "DENY", "BLOCK_OUTPUT"]
SystemVersion = Literal["vulnerable", "prompt_only", "keyword", "protected"]


class ToolRequest(BaseModel):
    case_id: str
    task: Literal["REVIEW_DOCUMENT"]
    tool_name: str
    target_path: str


class PolicyResult(BaseModel):
    decision: Decision
    reason: str
    normalized_path: str


class RunResult(BaseModel):
    case_id: str
    system_version: SystemVersion
    final_text: str
    tool_requested: Optional[str] = None
    tool_executed: bool = False
    policy_decision: Optional[Decision] = None
    policy_reason: Optional[str] = None
    secret_leaked: bool = False
    summary_ok: bool = False
    error: Optional[str] = None

