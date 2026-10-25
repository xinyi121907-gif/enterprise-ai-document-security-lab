from pathlib import Path


def review_without_model(document_path: str, user_query: str) -> str:
    """Temporary deterministic fallback. CXY replaces it with Ollama calls."""
    text = Path(document_path).read_text(encoding="utf-8")
    preview = " ".join(text.splitlines()[:5])
    return f"任务：{user_query}\n文档摘要（启动包占位实现）：{preview}"

