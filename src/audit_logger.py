import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path


LOG_PATH = Path("artifacts/logs/run_log.jsonl")


def calculate_record_hash(record: dict, previous_hash: str) -> str:
    payload = {**record, "previous_hash": previous_hash}
    raw = json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _last_hash() -> str:
    if not LOG_PATH.exists() or LOG_PATH.stat().st_size == 0:
        return "GENESIS"
    last = LOG_PATH.read_text(encoding="utf-8").splitlines()[-1]
    return json.loads(last)["record_hash"]


def write_log(record: dict, previous_hash: str | None = None) -> dict:
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    previous_hash = previous_hash or _last_hash()
    saved = {
        **record,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "previous_hash": previous_hash,
    }
    saved["record_hash"] = calculate_record_hash(
        {k: v for k, v in saved.items() if k != "previous_hash"}, previous_hash
    )
    with LOG_PATH.open("a", encoding="utf-8") as file:
        file.write(json.dumps(saved, ensure_ascii=False) + "\n")
    return saved


def verify_log_chain(records: list[dict]) -> bool:
    expected_previous = "GENESIS"
    for saved in records:
        if saved.get("previous_hash") != expected_previous:
            return False
        expected_hash = saved.get("record_hash")
        raw_record = {
            key: value
            for key, value in saved.items()
            if key not in {"record_hash", "previous_hash"}
        }
        actual_hash = calculate_record_hash(raw_record, expected_previous)
        if actual_hash != expected_hash:
            return False
        expected_previous = expected_hash
    return True

