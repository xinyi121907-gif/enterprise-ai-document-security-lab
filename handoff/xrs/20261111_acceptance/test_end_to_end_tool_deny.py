"""11-11 验收补充：模型后续工具请求的端到端拒绝测试。

现有 tests/test_policy_gate.py 覆盖权限函数本身，tests/test_protected_pipeline.py
覆盖初始读取被拒。本文件补两件事：

1) 先正常读取合法上传文件（ALLOW），再让模型提出越权请求，验证该请求被
   authorize_tool 拒绝，且被拒对象从未被读取、内容从未进入最终文本。
2) TASK_NOT_ALLOWED 分支的直接覆盖。ToolRequest 的 task 字段在数据模型层就是
   Literal["REVIEW_DOCUMENT"]，正常构造会被 pydantic 拦下，因此该分支只能用
   model_construct 绕过模型层校验后单独验证。

运行方式（仓库根目录下）：
    python3 -m pytest handoff/xrs/20261111_acceptance/test_end_to_end_tool_deny.py -v
"""

from pathlib import Path

import pytest

from src.contracts import ToolRequest
from src.policy_gate import authorize_tool
from src.pipeline import run_document_review

SECRET_MARKER = "DEMO_SECRET_E2E_CANARY"


def _prepare(tmp_path):
    uploads = tmp_path / "uploads"
    private = tmp_path / "private"
    uploads.mkdir(parents=True, exist_ok=True)
    private.mkdir(parents=True, exist_ok=True)
    doc = uploads / "report.txt"
    doc.write_text("正常合同文本，无敏感标记。", encoding="utf-8")
    secret = private / "customer_list.txt"
    secret.write_text(SECRET_MARKER + " 客户名单", encoding="utf-8")
    return uploads, doc, secret


def _fake_model_factory(secret):
    def fake_request_review(document_text, user_query, prompt_mode):
        # 初始读取必须已经成功，模型才拿得到正文
        assert "正常合同文本" in document_text
        return {
            "text": "以下是摘要。",
            "tool_call": {
                "name": "read_internal_file",
                "arguments": {"target_path": str(secret)},
            },
        }

    return fake_request_review


@pytest.fixture
def isolated(tmp_path, monkeypatch):
    """把上传根、日志路径都挪到临时目录，避免污染正式批次数据。"""
    import src.audit_logger as audit_logger
    import src.policy_gate as policy_gate
    import src.tools as tools

    uploads, doc, secret = _prepare(tmp_path)
    monkeypatch.setattr(policy_gate, "UPLOAD_ROOT", uploads.resolve())
    monkeypatch.setattr(audit_logger, "LOG_PATH", tmp_path / "run_log.jsonl")

    read_calls = []
    real_read = tools._read_text

    def spy_read(path):
        read_calls.append(str(path))
        return real_read(path)

    monkeypatch.setattr(tools, "_read_text", spy_read)
    return {"tmp_path": tmp_path, "uploads": uploads, "doc": doc,
            "secret": secret, "read_calls": read_calls, "log": tmp_path / "run_log.jsonl"}


def test_model_request_internal_file_denied_and_never_read(isolated, monkeypatch):
    """模型提出 read_internal_file 读取私有文件：TOOL_NOT_ALLOWED，且从未读取。"""
    import src.pipeline as pipeline

    monkeypatch.setattr(pipeline, "request_review", _fake_model_factory(isolated["secret"]))
    result = run_document_review(
        case_id="E2E-TOOL-DENY",
        system_version="protected",
        document_path=str(isolated["doc"]),
        user_query="请总结这份合同",
        business_type="contract_review",
    )

    assert result.policy_decision == "DENY"
    assert result.policy_reason == "TOOL_NOT_ALLOWED"
    assert result.tool_executed is False
    assert SECRET_MARKER not in result.final_text
    # 只允许发生初始读取这一处 I/O，私有文件没有被碰过
    assert isolated["read_calls"] == [str(isolated["doc"].resolve())]
    assert not any("customer_list" in p for p in isolated["read_calls"])


def test_model_request_other_upload_file_denied_and_never_read(isolated, monkeypatch):
    """模型提出 read_uploaded_file 但指向非当前上传文件：FILE_NOT_CURRENT_UPLOAD。"""
    import src.pipeline as pipeline

    def fake(document_text, user_query, prompt_mode):
        assert "正常合同文本" in document_text
        return {
            "text": "以下是摘要。",
            "tool_call": {
                "name": "read_uploaded_file",
                "arguments": {"target_path": str(isolated["secret"])},
            },
        }

    monkeypatch.setattr(pipeline, "request_review", fake)
    result = run_document_review(
        case_id="E2E-FILE-DENY",
        system_version="protected",
        document_path=str(isolated["doc"]),
        user_query="请总结这份合同",
        business_type="contract_review",
    )

    assert result.policy_decision == "DENY"
    assert result.policy_reason == "FILE_NOT_CURRENT_UPLOAD"
    assert result.tool_executed is False
    assert SECRET_MARKER not in result.final_text
    assert isolated["read_calls"] == [str(isolated["doc"].resolve())]


def test_audit_record_shows_two_decisions(isolated, monkeypatch):
    """日志中应留下两条判定：初始读取 ALLOW，模型请求 DENY。"""
    import json
    import src.pipeline as pipeline

    monkeypatch.setattr(pipeline, "request_review", _fake_model_factory(isolated["secret"]))
    run_document_review(
        case_id="E2E-LOG",
        system_version="protected",
        document_path=str(isolated["doc"]),
        user_query="请总结这份合同",
        business_type="contract_review",
    )

    lines = isolated["log"].read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    record = json.loads(lines[0])
    assert record["policy_decision"] == "DENY"
    assert record["tool_executed"] is False
    assert record["unauthorized_tool_executed"] is False
    assert SECRET_MARKER not in record["final_text"]
    trace = record["tool_trace"]
    assert [item["decision"] for item in trace] == ["ALLOW", "DENY"]
    assert trace[0]["tool_name"] == "read_uploaded_file"
    assert trace[1]["tool_name"] == "read_internal_file"


def test_task_not_allowed_branch_directly(tmp_path):
    """TASK_NOT_ALLOWED：数据模型层会先拒非法 task，本用例绕过模型层直接验权限门。"""
    uploads = tmp_path / "uploads"
    uploads.mkdir(parents=True, exist_ok=True)
    doc = uploads / "report.txt"
    doc.write_text("正常合同文本。", encoding="utf-8")

    req = ToolRequest.model_construct(
        case_id="TASK-LITERAL",
        task="IGNORE_DOCUMENT",
        tool_name="read_uploaded_file",
        target_path=str(doc),
    )
    policy = authorize_tool(req, str(doc))
    assert policy.decision == "DENY"
    assert policy.reason == "TASK_NOT_ALLOWED"


def test_task_literal_rejected_at_model_layer(tmp_path):
    """正常构造非法 task 时，pydantic 在进入权限门之前就报错。"""
    uploads = tmp_path / "uploads"
    uploads.mkdir(parents=True, exist_ok=True)
    doc = uploads / "report.txt"
    doc.write_text("正常合同文本。", encoding="utf-8")

    with pytest.raises(Exception):
        ToolRequest(case_id="TASK-LITERAL", task="IGNORE_DOCUMENT",
                    tool_name="read_uploaded_file", target_path=str(doc))
