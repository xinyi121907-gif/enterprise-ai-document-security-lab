import sys
import json
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import audit_logger


def _setup_logger(tmp_path):
    audit_logger.LOG_PATH = tmp_path / "run_log.jsonl"
    return audit_logger.LOG_PATH


def test_write_log_appends_jsonl(tmp_path):
    log_path = _setup_logger(tmp_path)
    rec = audit_logger.write_log({"case_id": "NOR-01", "decision": "ALLOW"})
    lines = log_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    saved = json.loads(lines[0])
    assert saved["case_id"] == "NOR-01"
    assert saved["decision"] == "ALLOW"
    assert saved["previous_hash"] == "GENESIS"
    assert saved["record_hash"]
    assert saved["timestamp"]


def test_auto_chain_uses_last_hash(tmp_path):
    _setup_logger(tmp_path)
    r1 = audit_logger.write_log({"case_id": "A"})
    r2 = audit_logger.write_log({"case_id": "B"})
    assert r2["previous_hash"] == r1["record_hash"]


def test_verify_clean_chain_passes(tmp_path):
    _setup_logger(tmp_path)
    r1 = audit_logger.write_log({"case_id": "A"})
    r2 = audit_logger.write_log({"case_id": "B"})
    r3 = audit_logger.write_log({"case_id": "C"})
    assert audit_logger.verify_log_chain([r1, r2, r3]) is True


def test_tamper_any_record_fails(tmp_path):
    _setup_logger(tmp_path)
    r1 = audit_logger.write_log({"case_id": "A"})
    r2 = audit_logger.write_log({"case_id": "B"})
    r2["case_id"] = "X"  # 篡改任意一条
    assert audit_logger.verify_log_chain([r1, r2]) is False


def test_tamper_previous_hash_fails(tmp_path):
    _setup_logger(tmp_path)
    r1 = audit_logger.write_log({"case_id": "A"})
    r2 = audit_logger.write_log({"case_id": "B"})
    r2["previous_hash"] = "DEADBEEF"
    assert audit_logger.verify_log_chain([r1, r2]) is False


def test_explicit_previous_hash_respected(tmp_path):
    _setup_logger(tmp_path)
    r = audit_logger.write_log({"case_id": "A"}, previous_hash="CUSTOM")
    assert r["previous_hash"] == "CUSTOM"
    assert r["record_hash"] != ""
