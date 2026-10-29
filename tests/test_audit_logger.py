import json

import src.audit_logger as audit_logger
from src.audit_logger import calculate_record_hash, verify_log_chain


def test_hash_chain_detects_tampering():
    first = {"case_id": "NOR-01", "previous_hash": "GENESIS"}
    first["record_hash"] = calculate_record_hash({"case_id": "NOR-01"}, "GENESIS")
    assert verify_log_chain([first]) is True
    first["case_id"] = "CHANGED"
    assert verify_log_chain([first]) is False


def test_write_log_appends_jsonl(tmp_path, monkeypatch):
    log_path = tmp_path / "run_log.jsonl"
    monkeypatch.setattr(audit_logger, "LOG_PATH", log_path)
    rec = audit_logger.write_log({"case_id": "NOR-01", "decision": "ALLOW"})
    lines = log_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    saved = json.loads(lines[0])
    assert saved["case_id"] == "NOR-01"
    assert saved["decision"] == "ALLOW"
    assert saved["previous_hash"] == "GENESIS"
    assert saved["record_hash"]
    assert saved["timestamp"]


def test_auto_chain_uses_last_hash(tmp_path, monkeypatch):
    log_path = tmp_path / "run_log.jsonl"
    monkeypatch.setattr(audit_logger, "LOG_PATH", log_path)
    r1 = audit_logger.write_log({"case_id": "A"})
    r2 = audit_logger.write_log({"case_id": "B"})
    assert r2["previous_hash"] == r1["record_hash"]


def test_multi_record_clean_chain_passes(tmp_path, monkeypatch):
    log_path = tmp_path / "run_log.jsonl"
    monkeypatch.setattr(audit_logger, "LOG_PATH", log_path)
    recs = [audit_logger.write_log({"case_id": str(i)}) for i in range(3)]
    assert audit_logger.verify_log_chain(recs) is True


def test_tamper_any_record_fails(tmp_path, monkeypatch):
    log_path = tmp_path / "run_log.jsonl"
    monkeypatch.setattr(audit_logger, "LOG_PATH", log_path)
    r1 = audit_logger.write_log({"case_id": "A"})
    r2 = audit_logger.write_log({"case_id": "B"})
    r2["case_id"] = "X"
    assert audit_logger.verify_log_chain([r1, r2]) is False


def test_explicit_previous_hash_respected(tmp_path, monkeypatch):
    log_path = tmp_path / "run_log.jsonl"
    monkeypatch.setattr(audit_logger, "LOG_PATH", log_path)
    r = audit_logger.write_log({"case_id": "A"}, previous_hash="CUSTOM")
    assert r["previous_hash"] == "CUSTOM"
