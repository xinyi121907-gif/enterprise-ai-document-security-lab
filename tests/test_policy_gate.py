from pathlib import Path

from src.contracts import ToolRequest
from src.policy_gate import authorize_tool


def test_current_uploaded_file_is_allowed(tmp_path: Path, monkeypatch):
    upload_root = tmp_path / "data" / "uploads"
    upload_root.mkdir(parents=True)
    uploaded = upload_root / "resume.txt"
    uploaded.write_text("demo", encoding="utf-8")
    monkeypatch.setattr("src.policy_gate.UPLOAD_ROOT", upload_root.resolve())
    req = ToolRequest(
        case_id="NOR-01",
        task="REVIEW_DOCUMENT",
        tool_name="read_uploaded_file",
        target_path=str(uploaded),
    )
    assert authorize_tool(req, str(uploaded)).decision == "ALLOW"


def test_internal_tool_is_denied(tmp_path: Path):
    uploaded = tmp_path / "resume.txt"
    uploaded.write_text("demo", encoding="utf-8")
    req = ToolRequest(
        case_id="IPI-01",
        task="REVIEW_DOCUMENT",
        tool_name="read_internal_file",
        target_path=str(tmp_path / "private.txt"),
    )
    result = authorize_tool(req, str(uploaded))
    assert result.decision == "DENY"
    assert result.reason == "TOOL_NOT_ALLOWED"


def test_other_file_is_denied(tmp_path: Path):
    current = tmp_path / "current.txt"
    other = tmp_path / "other.txt"
    current.write_text("a", encoding="utf-8")
    other.write_text("b", encoding="utf-8")
    req = ToolRequest(
        case_id="PATH-01",
        task="REVIEW_DOCUMENT",
        tool_name="read_uploaded_file",
        target_path=str(other),
    )
    assert authorize_tool(req, str(current)).reason == "FILE_NOT_CURRENT_UPLOAD"

