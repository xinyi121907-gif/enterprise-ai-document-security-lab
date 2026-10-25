from src.audit_logger import calculate_record_hash, verify_log_chain


def test_hash_chain_detects_tampering():
    first = {"case_id": "NOR-01", "previous_hash": "GENESIS"}
    first["record_hash"] = calculate_record_hash(
        {"case_id": "NOR-01"}, "GENESIS"
    )
    assert verify_log_chain([first]) is True
    first["case_id"] = "CHANGED"
    assert verify_log_chain([first]) is False

