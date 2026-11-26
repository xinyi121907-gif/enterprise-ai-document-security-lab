"""Run a new, isolated experiment with contemporaneous provenance.

This does not backfill evidence for the historical 120 runs.
"""
import argparse
import csv
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parent


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def git_value(*args):
    try:
        return subprocess.check_output(["git", *args], cwd=ROOT, text=True, stderr=subprocess.DEVNULL).strip()
    except (OSError, subprocess.CalledProcessError):
        return None


def collect_provenance(mock):
    import yaml
    config = yaml.safe_load((ROOT / "config.yaml").read_text(encoding="utf-8"))
    model = {"name": config["model"], "digest": None, "status": "NOT_CHECKED_MOCK"}
    if not mock:
        import ollama
        response = ollama.Client(timeout=10).list()
        for entry in response.models:
            if entry.model == config["model"]:
                model.update(digest=entry.digest, status="AVAILABLE")
                break
        if not model["digest"]:
            raise RuntimeError("Configured Ollama model or digest is unavailable; no experiment started")
    files = [ROOT / "app.py", ROOT / "ui.css", ROOT / "config.yaml", ROOT / "requirements.txt", ROOT / "run_evidence.py"]
    files += list((ROOT / "src").glob("*.py")) + list((ROOT / "tests").glob("*.py"))
    files += [ROOT / "tests/test_cases.json"]
    for case in json.loads((ROOT / "tests/test_cases.json").read_text(encoding="utf-8")):
        files.append(ROOT / case["file"])
    files += list((ROOT / "data/private").glob("*.txt"))
    return {
        "captured_at_utc": datetime.now(timezone.utc).isoformat(),
        "git_commit": git_value("rev-parse", "HEAD"),
        "git_status": git_value("status", "--porcelain"),
        "python": sys.version, "platform": platform.platform(),
        "ollama_host": os.environ.get("OLLAMA_HOST", "http://localhost:11434"),
        "model": model, "config": config,
        "files_sha256": {p.relative_to(ROOT).as_posix(): sha256(p) for p in sorted(set(files))},
    }


def run(output, rounds=3, mock=False, limit=0):
    if rounds < 1 or limit < 0:
        raise ValueError("rounds must be positive; limit must be nonnegative")
    output = Path(output).resolve()
    if output.exists():
        raise ValueError("Output directory already exists; use a new directory to preserve evidence")
    provenance = collect_provenance(mock)
    output.mkdir(parents=True, exist_ok=False)
    command = [sys.executable, str(ROOT / "tests/run_experiment.py"), "--rounds", str(rounds),
               "--limit", str(limit), "--output", str(output / "raw_runs.csv"),
               "--log-output", str(output / "run_log.jsonl")]
    if mock:
        command.append("--mock")
    manifest = {"schema_version": 1, "purpose": "mock_smoke" if mock else "new_model_experiment",
                "status": "RUNNING", "historical_120_runs": False, "command": command,
                "before": provenance}
    manifest_path = output / "run_manifest.json"
    def save():
        manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    save()
    code = 1
    try:
        code = subprocess.call(command, cwd=ROOT)
        manifest["exit_code"] = code
        manifest["status"] = "COMPLETED" if code == 0 else "FAILED"
        if code == 0:
            from src.audit_logger import verify_log_chain
            records = [json.loads(line) for line in (output / "run_log.jsonl").read_text(encoding="utf-8").splitlines()]
            with (output / "raw_runs.csv").open(encoding="utf-8", newline="") as f:
                rows = list(csv.DictReader(f))
            cases = json.loads((ROOT / "tests/test_cases.json").read_text(encoding="utf-8"))
            selected = cases[:limit] if limit else cases
            versions = ("vulnerable", "prompt_only", "keyword", "protected")
            expected = {(c["case_id"], v, str(n)) for c in selected for v in versions for n in range(1, rounds + 1)}
            actual = [(r["case_id"], r["system_version"], r["run_no"]) for r in rows]
            valid = (verify_log_chain(records) and len(rows) == len(records) == len(expected)
                     and set(actual) == expected
                     and all(r["record_hash"] == log["record_hash"] for r, log in zip(rows, records)))
            manifest["verification"] = {"passed": valid, "csv_rows": len(rows), "log_rows": len(records),
                                        "runtime_error_rows": sum(bool(r["error"]) for r in rows)}
            if not valid:
                code = 2
                manifest["status"] = "VALIDATION_FAILED"
    except BaseException as exc:
        manifest["status"] = "INTERRUPTED" if isinstance(exc, KeyboardInterrupt) else "FAILED"
        manifest["error"] = str(exc)
        raise
    finally:
        manifest["finished_at_utc"] = datetime.now(timezone.utc).isoformat()
        manifest["artifacts_sha256"] = {p.name: sha256(p) for p in output.iterdir() if p.suffix in {".csv", ".jsonl"}}
        manifest["source_unchanged"] = all((ROOT / p).exists() and sha256(ROOT / p) == digest
                                            for p, digest in provenance["files_sha256"].items())
        if not manifest["source_unchanged"] and manifest["status"] == "COMPLETED":
            manifest["status"] = "SOURCE_CHANGED"
            code = 2
        manifest["exit_code"] = code
        save()
    return code


def main():
    parser = argparse.ArgumentParser(description="Create an isolated experiment and evidence manifest")
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--rounds", type=int, default=3)
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--mock", action="store_true")
    args = parser.parse_args()
    try:
        return run(args.output_dir, args.rounds, args.mock, args.limit)
    except (ValueError, OSError, RuntimeError) as exc:
        print(str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
