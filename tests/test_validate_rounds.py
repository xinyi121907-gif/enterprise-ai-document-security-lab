"""validate_rounds.py 的回归测试：三个边界（非法 decision / record_hash 缺失 / 四套版本固定）。

纯函数用例不依赖数据文件；端到端用例只在本地存在 ZL 第 1 轮或 mock 演练数据时运行，
数据未入库（避免把运行原始数据进仓库），因此缺数据时按 skip 处理，不算失败。
"""

import csv
import importlib.util
import os
import subprocess
import sys
from pathlib import Path

import pytest

TESTS = Path(__file__).resolve().parent
REPO = TESTS.parent
VR_PATH = TESTS / "validate_rounds.py"


def _load_mod():
    spec = importlib.util.spec_from_file_location("validate_rounds_mod", VR_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


VR = _load_mod()

# 候选数据集：优先 ZL 第 1 轮（40 行 + 官方日志），其次 mock 演练（120 行 + 日志）
DATA_CANDIDATES = [
    (REPO / "results/zl_round1/raw_runs_round1.csv", REPO / "results/zl_round1/round1_run_log.jsonl", 1),
    (REPO / "results/raw_runs_drill.csv", REPO / "artifacts/logs/run_log.jsonl", 3),
]


def _pick_dataset():
    for csv_path, log_path, rounds in DATA_CANDIDATES:
        if csv_path.exists():
            return csv_path, (log_path if log_path.exists() else None), rounds
    return None, None, None


DATA_CSV, DATA_LOG, DATA_ROUNDS = _pick_dataset()


# ---------- 边界 1：非法 decision 一律判错，不能被“无策略层”掩盖 ----------

def test_invalid_decision_rejected_in_all_versions():
    for version in ("vulnerable", "prompt_only", "keyword", "protected"):
        assert VR.decision_status(version, "BANANA", "read_internal_file") == VR.STATUS_MISSING


def test_valid_decisions_and_trigger_states():
    assert VR.decision_status("protected", "ALLOW", "read_uploaded_file") == VR.STATUS_OK
    assert VR.decision_status("protected", "BLOCK_OUTPUT", "") == VR.STATUS_OK
    # 有工具请求、缺 decision：必须是 MISSING，不能因为 to_bool 判成无请求
    assert VR.decision_status("protected", "", "read_internal_file") == VR.STATUS_MISSING
    assert VR.decision_status("keyword", "", "") == VR.N_A_NO_INTERVENTION
    assert VR.decision_status("vulnerable", "", "read_internal_file") == VR.N_A_NO_POLICY_LAYER


# ---------- 边界 2：record_hash 缺失（任一侧）判错 ----------

def _row(**kw):
    base = {
        "record_hash": "abc123",
        "policy_decision": "DENY",
        "policy_reason": "TOOL_NOT_ALLOWED",
        "tool_executed": "False",
        "secret_leaked": "False",
        "summary_ok": "True",
    }
    base.update(kw)
    return base


def test_record_hash_missing_in_detail_is_error():
    differs = VR.content_mismatches(_row(record_hash=""), _row(), False)
    assert any("record_hash 缺失" in d for d in differs), differs


def test_record_hash_missing_in_log_is_error():
    differs = VR.content_mismatches(_row(), _row(record_hash=""), False)
    assert any("record_hash 缺失" in d for d in differs), differs


def test_record_hash_equal_is_not_error():
    differs = VR.content_mismatches(_row(), _row(), False)
    assert not any("record_hash" in d for d in differs), differs


def test_record_hash_value_differs_is_error():
    differs = VR.content_mismatches(_row(record_hash="aaa"), _row(record_hash="bbb"), False)
    assert any("record_hash 不一致" in d for d in differs), differs


# ---------- 边界 3：期望版本固定四套，缺版本不能被“按输入缩减” ----------

def _run_validator(csv_path, out_path, summary_path, log_path=None, rounds=3):
    cmd = [sys.executable, str(VR_PATH), "--input", str(csv_path),
           "--output", str(out_path), "--summary", str(summary_path),
           "--rounds", str(rounds), "--label", "regression"]
    if log_path:
        cmd += ["--log", str(log_path)]
    return subprocess.run(cmd, cwd=str(REPO), capture_output=True, text=True)


@pytest.mark.skipif(DATA_CSV is None, reason="本地无 ZL/mock 运行数据，端到端用例跳过")
def test_missing_version_fails(tmp_path):
    rows = list(csv.DictReader(DATA_CSV.open(encoding="utf-8-sig")))
    dropped = [r for r in rows if r["system_version"] != "protected"]
    csv_path = tmp_path / "no_protected.csv"
    with csv_path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(dropped)
    proc = _run_validator(csv_path, tmp_path / "o.csv", tmp_path / "s.txt",
                          log_path=None, rounds=DATA_ROUNDS)
    assert proc.returncode != 0, proc.stdout
    summary = (tmp_path / "s.txt").read_text(encoding="utf-8")
    assert "缺少版本 protected" in summary, summary


@pytest.mark.skipif(DATA_CSV is None, reason="本地无 ZL/mock 运行数据，端到端用例跳过")
def test_invalid_decision_fails_end_to_end(tmp_path):
    rows = list(csv.DictReader(DATA_CSV.open(encoding="utf-8-sig")))
    target = next(r for r in rows if r["system_version"] in ("keyword", "protected")
                  and r["policy_decision"])
    target["policy_decision"] = "BANANA"
    csv_path = tmp_path / "banana.csv"
    with csv_path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
    proc = _run_validator(csv_path, tmp_path / "o.csv", tmp_path / "s.txt",
                          log_path=DATA_LOG, rounds=DATA_ROUNDS)
    assert proc.returncode != 0, proc.stdout
    out = list(csv.DictReader((tmp_path / "o.csv").open(encoding="utf-8-sig")))
    hit = [r for r in out if r["policy_decision"] == "BANANA"]
    assert hit and hit[0]["decision_status"] == VR.STATUS_MISSING, hit[:1]


@pytest.mark.skipif(DATA_CSV is None or DATA_LOG is None,
                    reason="本地无配套 CSV + 日志，逐条核对用例跳过")
def test_missing_record_hash_fails_end_to_end(tmp_path):
    rows = list(csv.DictReader(DATA_CSV.open(encoding="utf-8-sig")))
    rows[0]["record_hash"] = ""
    csv_path = tmp_path / "no_hash.csv"
    with csv_path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
    proc = _run_validator(csv_path, tmp_path / "o.csv", tmp_path / "s.txt",
                          log_path=DATA_LOG, rounds=DATA_ROUNDS)
    assert proc.returncode != 0, proc.stdout
    summary = (tmp_path / "s.txt").read_text(encoding="utf-8")
    assert "record_hash 缺失" in summary, summary
