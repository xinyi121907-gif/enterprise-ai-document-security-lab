import json
import pytest
import run_evidence
from src import audit_logger


def test_isolated_mock_evidence_preserves_shared_log(tmp_path):
    original = audit_logger.LOG_PATH.read_bytes() if audit_logger.LOG_PATH.exists() else None
    out = tmp_path / "batch"
    assert run_evidence.run(out, rounds=1, mock=True, limit=1) == 0
    manifest = json.loads((out / "run_manifest.json").read_text(encoding="utf-8"))
    assert manifest["status"] == "COMPLETED"
    assert manifest["purpose"] == "mock_smoke"
    assert manifest["before"]["model"]["digest"] is None
    assert manifest["verification"]["passed"]
    assert manifest["verification"]["csv_rows"] == 4
    assert manifest["source_unchanged"]
    assert manifest["artifacts_sha256"]["raw_runs.csv"] == run_evidence.sha256(out / "raw_runs.csv")
    assert (audit_logger.LOG_PATH.read_bytes() if audit_logger.LOG_PATH.exists() else None) == original
    with pytest.raises(ValueError, match="already exists"):
        run_evidence.run(out, mock=True)


def test_model_preflight_failure_does_not_create_batch(tmp_path, monkeypatch):
    def fail(_):
        raise RuntimeError("model unavailable")
    monkeypatch.setattr(run_evidence, "collect_provenance", fail)
    with pytest.raises(RuntimeError):
        run_evidence.run(tmp_path / "batch")
    assert not (tmp_path / "batch").exists()


def test_interruption_keeps_manifest(tmp_path, monkeypatch):
    monkeypatch.setattr(run_evidence, "collect_provenance", lambda _: {"files_sha256": {}})
    def interrupt(*args, **kwargs):
        raise KeyboardInterrupt()
    monkeypatch.setattr(run_evidence.subprocess, "call", interrupt)
    with pytest.raises(KeyboardInterrupt):
        run_evidence.run(tmp_path / "batch", mock=True)
    manifest = json.loads((tmp_path / "batch/run_manifest.json").read_text(encoding="utf-8"))
    assert manifest["status"] == "INTERRUPTED"
    assert manifest["exit_code"] != 0
