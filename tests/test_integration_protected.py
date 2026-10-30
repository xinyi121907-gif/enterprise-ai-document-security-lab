import pytest

from src.contracts import ToolRequest
from src.tools import execute_tool_protected


@pytest.fixture
def env(tmp_path, monkeypatch):
    up = tmp_path / "data" / "uploads"
    up.mkdir(parents=True, exist_ok=True)
    private = tmp_path / "data" / "private"
    private.mkdir(parents=True, exist_ok=True)

    doc = up / "resume.txt"
    doc.write_text("resume-demo", encoding="utf-8")
    secret = private / "secret.txt"
    secret.write_text("DEMO_SECRET=FLAG{LOCAL_AI_ACCESS_CONTROL}", encoding="utf-8")

    monkeypatch.setattr("src.policy_gate.UPLOAD_ROOT", up.resolve())

    read_calls = []

    import src.tools as tools

    real_read = tools._read_text

    def spy(path: str) -> str:
        read_calls.append(path)
        return real_read(path)

    monkeypatch.setattr("src.tools._read_text", spy)
    return {"up": up, "private": private, "doc": doc, "secret": secret, "_read_calls": read_calls}


def _req(case_id, tool_name, target, task="REVIEW_DOCUMENT"):
    return ToolRequest(
        case_id=case_id,
        task=task,
        tool_name=tool_name,
        target_path=target,
    )


def test_deny_tool_not_allowed_never_reads(env):
    # IPI: malicious file asks for read_internal_file -> DENY before any read
    result = execute_tool_protected(
        _req("IPI-01", "read_internal_file", str(env["secret"])),
        str(env["doc"]),
    )
    assert result["executed"] is False
    assert result["policy"].decision == "DENY"
    assert result["policy"].reason == "TOOL_NOT_ALLOWED"
    assert result["content"] is None
    assert env["_read_calls"] == []  # file never touched


def test_deny_not_current_upload_never_reads(env):
    result = execute_tool_protected(
        _req("PATH-01", "read_uploaded_file", str(env["secret"])),
        str(env["doc"]),
    )
    assert result["executed"] is False
    assert result["policy"].reason == "FILE_NOT_CURRENT_UPLOAD"
    assert result["content"] is None
    assert env["_read_calls"] == []


def test_deny_outside_upload_root_never_reads(env):
    # even if target == current, path outside UPLOAD_ROOT must be denied pre-read
    result = execute_tool_protected(
        _req("IPI-02", "read_uploaded_file", str(env["secret"])),
        str(env["secret"]),
    )
    assert result["executed"] is False
    assert result["policy"].reason == "PATH_OUTSIDE_UPLOAD_ROOT"
    assert result["content"] is None
    assert env["_read_calls"] == []


def test_task_literal_locks_whitelist_at_model_layer(env):
    # TASK_NOT_ALLOWED branch is enforced at the data model: an attacker
    # cannot even construct a request whose task is not REVIEW_DOCUMENT.
    import pytest as _pytest
    from pydantic import ValidationError

    with _pytest.raises(ValidationError):
        ToolRequest(case_id="IPI-03", task="CHAT", tool_name="read_uploaded_file", target_path=str(env["doc"]))
    assert env["_read_calls"] == []


def test_allow_current_upload_reads_file(env):
    result = execute_tool_protected(
        _req("NOR-01", "read_uploaded_file", str(env["doc"])),
        str(env["doc"]),
    )
    assert result["executed"] is True
    assert result["policy"].decision == "ALLOW"
    assert result["content"] == "resume-demo"
    assert env["_read_calls"] == [str(env["doc"].resolve())]


def test_deny_cases_all_have_tool_executed_false(env):
    """Task-5 acceptance: deny cases => tool_executed stays False, always."""
    cases = [
        ("IPI-01", "read_internal_file", str(env["secret"]), "REVIEW_DOCUMENT"),
        ("IPI-04", "read_anything", str(env["doc"]), "REVIEW_DOCUMENT"),
        ("PATH-01", "read_uploaded_file", str(env["secret"]), "REVIEW_DOCUMENT"),
        ("IPI-02", "read_uploaded_file", str(env["secret"]), "REVIEW_DOCUMENT"),
    ]
    for case_id, tool, target, task in cases:
        result = execute_tool_protected(_req(case_id, tool, target, task), str(env["doc"]))
        assert result["executed"] is False, case_id
        assert result["policy"].decision == "DENY", case_id
    assert env["_read_calls"] == []  # none of the deny paths touched the disk