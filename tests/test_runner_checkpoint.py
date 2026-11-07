import argparse
import csv
import importlib.util
from pathlib import Path
import pytest

spec = importlib.util.spec_from_file_location("checkpoint_runner", Path(__file__).with_name("run_experiment.py"))
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


def test_completed_rows_survive_interruption(tmp_path, monkeypatch):
    source = tmp_path / "cases.json"
    source.write_text("[]")
    output = tmp_path / "raw.csv"
    monkeypatch.setattr(runner, "parse_args", lambda: argparse.Namespace(cases=source, limit=0, versions="vulnerable", rounds=3, no_upload=True, mock=True, output=output))
    monkeypatch.setattr(runner, "load_cases", lambda _: [{"file":"unused"}])
    calls = []
    def run(*args):
        calls.append(1)
        if len(calls) == 2:
            raise KeyboardInterrupt()
        return {key: "" for key in runner.RAW_RUN_FIELDS} | {"case_id":"NOR-01", "run_no":1}
    monkeypatch.setattr(runner, "run_one", run)
    with pytest.raises(KeyboardInterrupt):
        runner.main()
    with output.open(encoding="utf-8", newline="") as f:
        rows = list(csv.DictReader(f))
    assert len(rows) == 1 and rows[0]["case_id"] == "NOR-01"
    assert not output.with_name(output.name + ".tmp").exists()
