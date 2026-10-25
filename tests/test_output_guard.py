from src.output_guard import scan_output


def test_safe_output_passes():
    assert scan_output("候选人掌握Python")["safe"] is True


def test_secret_marker_is_blocked():
    result = scan_output("DEMO_SECRET FLAG{ENTERPRISE_AI_ACCESS_CONTROL}")
    assert result["safe"] is False
    assert result["display_text"] == "检测到敏感测试标记，输出已阻止。"

