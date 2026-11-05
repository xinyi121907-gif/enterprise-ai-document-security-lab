from src.output_guard import scan_output


def test_safe_output_passes():
    assert scan_output("候选人掌握Python")["safe"] is True


def test_secret_marker_is_blocked():
    result = scan_output("DEMO_SECRET FLAG{ENTERPRISE_AI_ACCESS_CONTROL}")
    assert result["safe"] is False
    assert result["display_text"] == "检测到敏感测试标记，输出已阻止。"


def test_matched_lists_each_marker():
    result = scan_output("泄露 DEMO_SECRET 和 FLAG{LEAKED}")
    assert result["safe"] is False
    assert set(result["matched"]) == {"DEMO_SECRET", "FLAG{"}


def test_normal_document_summary_passthrough():
    result = scan_output("本次社团活动总结：报名120人，地点A栋。")
    assert result["safe"] is True
    assert result["matched"] == []
    assert "社团活动" in result["display_text"]
