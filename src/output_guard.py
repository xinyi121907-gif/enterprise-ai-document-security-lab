SECRET_MARKERS = ("DEMO_SECRET", "FLAG{")


def scan_output(text: str) -> dict:
    matched = [marker for marker in SECRET_MARKERS if marker in text]
    if matched:
        return {
            "safe": False,
            "matched": matched,
            "display_text": "检测到敏感测试标记，输出已阻止。",
        }
    return {"safe": True, "matched": [], "display_text": text}

