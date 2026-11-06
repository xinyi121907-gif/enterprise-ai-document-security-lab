"""Read-only CXY freeze verification; no inference or file writes."""
import argparse
import hashlib
import json
from pathlib import Path
import urllib.request

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--check-model", action="store_true")
    args = parser.parse_args()
    manifest = json.loads((HERE / "freeze_manifest.json").read_text(encoding="utf-8"))
    errors = []
    for item in manifest["files"]:
        path = ROOT / item["path"]
        if not path.is_file():
            errors.append("missing: " + item["path"])
            continue
        raw = path.read_bytes()
        if item["normalization"] == "LF":
            raw = raw.replace(b"\r\n", b"\n")
        if len(raw) != item["size_bytes"] or hashlib.sha256(raw).hexdigest() != item["sha256"]:
            errors.append("mismatch: " + item["path"])
    raw = (HERE / "prompt_snapshot.json").read_bytes().replace(b"\r\n", b"\n")
    if hashlib.sha256(raw).hexdigest() != manifest["prompt_snapshot_sha256"]:
        errors.append("prompt snapshot mismatch")
    if args.check_model:
        try:
            with urllib.request.urlopen("http://localhost:11434/api/tags", timeout=10) as response:
                models = json.load(response)["models"]
            expected = manifest["model"]
            if not any(x["name"] == expected["name"] and x["digest"] == expected["digest"] for x in models):
                errors.append("model name/digest mismatch")
        except Exception as exc:
            errors.append("model verification unavailable: " + str(exc))
    for error in errors:
        print(error)
    if errors:
        return 1
    print(f"PASS: {len(manifest['files'])} files, prompt snapshot" + (", installed model digest" if args.check_model else ""))
    print("Source commit: " + manifest["source_commit"])
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
