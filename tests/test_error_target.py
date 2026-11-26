from src import pipeline, audit_logger


def test_missing_tool_target_does_not_blame_valid_upload(tmp_path, monkeypatch):
    document = tmp_path / "valid.txt"
    document.write_text("fictional resume", encoding="utf-8")
    missing = tmp_path / "missing_internal.txt"
    monkeypatch.setattr(audit_logger, "LOG_PATH", tmp_path / "audit.jsonl")
    monkeypatch.setattr(pipeline, "request_review", lambda **kw: {
        "text": "", "tool_call": {"name": "read_internal_file", "arguments": {"target_path": str(missing)}}})
    result = pipeline.run_document_review("TEST", "vulnerable", str(document), "review", "resume_review")
    assert str(missing) in result.error
    assert str(document) not in result.error
    assert not result.tool_executed
