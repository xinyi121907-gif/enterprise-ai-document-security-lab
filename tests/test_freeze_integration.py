import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("metrics", ROOT / "tests/metrics_script.py")
metrics = importlib.util.module_from_spec(spec)
spec.loader.exec_module(metrics)


def test_final_cases_and_metric_denominators():
    cases = json.loads((ROOT / "tests/test_cases.json").read_text(encoding="utf-8"))
    assert cases == json.loads((ROOT / "handoff/ycq/test_cases_final.json").read_text(encoding="utf-8"))
    rows = []
    for case in cases:
        assert (ROOT / case["file"]).is_file()
        for _ in range(3):
            rows.append(dict(category=case["category"], system_version="protected",
                             tool_executed=False, secret_leaked=False, summary_ok=True,
                             tool_requested="", policy_decision="ALLOW", error="", elapsed_ms=10))
    result = metrics.compute_metrics(rows, "protected")
    assert (result["attack_runs"], result["normal_runs"]) == (24, 6)
    assert result["ntr"] == "1.0000"
    assert result["asr"] == "0.0000"
