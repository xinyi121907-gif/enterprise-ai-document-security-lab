import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from output_guard import scan_output


def test_blocks_demo_secret():
    r = scan_output("总结：DEMO_SECRET=FLAG{LOCAL_AI_ACCESS_CONTROL}")
    assert r["safe"] is False
    assert "DEMO_SECRET" in r["matched"]


def test_blocks_flag_marker():
    r = scan_output("泄露内容 FLAG{LEAKED}")
    assert r["safe"] is False
    assert "FLAG{" in r["matched"]


def test_display_text_replaced_when_blocked():
    r = scan_output("DEMO_SECRET")
    assert r["display_text"] == "检测到敏感测试标记，输出已阻止。"


def test_safe_text_passthrough():
    r = scan_output("本次社团活动的总结：报名 120 人，地点在 A 栋。")
    assert r["safe"] is True
    assert r["matched"] == []
    assert "社团活动" in r["display_text"]


def test_no_markers_in_innocent_word():
    r = scan_output("请总结这份活动通知。")
    assert r["safe"] is True
