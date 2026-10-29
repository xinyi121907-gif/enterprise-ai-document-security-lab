"""XRS owner — unit tests for src/policy_gate.py.

Requirement (task 3, 10-29): at least 12 passing unit tests covering
path traversal, relative paths, case variants and symlink escape.

Every test isolates its own upload/private tree under tmp_path and
monkeypatches UPLOAD_ROOT, so tests never touch the real data/ directory.
"""

import os

import pytest

from src.contracts import ToolRequest
from src.policy_gate import authorize_tool


def _req(
    case_id,
    tool_name,
    target,
    task="REVIEW_DOCUMENT",
):
    return ToolRequest(
        case_id=case_id,
        task=task,
        tool_name=tool_name,
        target_path=target,
    )


@pytest.fixture
def env(tmp_path, monkeypatch):
    up = tmp_path / "data" / "uploads"
    up.mkdir(
        parents=True,
        exist_ok=True,
    )

    private = tmp_path / "data" / "private"
    private.mkdir(
        parents=True,
        exist_ok=True,
    )

    doc = up / "resume.txt"
    doc.write_text(
        "resume-demo",
        encoding="utf-8",
    )

    other = up / "other.txt"
    other.write_text(
        "other-demo",
        encoding="utf-8",
    )

    secret = private / "secret.txt"
    secret.write_text(
        "TOP-SECRET",
        encoding="utf-8",
    )

    monkeypatch.setattr(
        "src.policy_gate.UPLOAD_ROOT",
        up.resolve(),
    )
    monkeypatch.chdir(tmp_path)

    return {
        "up": up,
        "private": private,
        "doc": doc,
        "other": other,
        "secret": secret,
    }


# ---- 合法放行 ----


def test_current_uploaded_file_is_allowed(env):
    result = authorize_tool(
        _req(
            "NOR-01",
            "read_uploaded_file",
            str(env["doc"]),
        ),
        str(env["doc"]),
    )

    assert result.decision == "ALLOW"
    assert result.reason == "CURRENT_UPLOAD_ONLY"


def test_relative_path_to_current_upload_is_allowed(env):
    # 相对路径经过resolve规范化后，
    # 应被判定为当前上传文件。
    result = authorize_tool(
        _req(
            "NOR-01",
            "read_uploaded_file",
            "data/uploads/resume.txt",
        ),
        "data/uploads/resume.txt",
    )

    assert result.decision == "ALLOW"


def test_current_dot_slash_is_allowed(env):
    result = authorize_tool(
        _req(
            "NOR-02",
            "read_uploaded_file",
            "./data/uploads/resume.txt",
        ),
        str(env["doc"]),
    )

    assert result.decision == "ALLOW"


def test_normalized_path_is_resolved_absolute(env):
    result = authorize_tool(
        _req(
            "NOR-01",
            "read_uploaded_file",
            str(env["doc"]),
        ),
        str(env["doc"]),
    )

    assert result.normalized_path == str(
        env["doc"].resolve()
    )


# ---- 工具白名单 ----


def test_internal_tool_is_denied(env):
    result = authorize_tool(
        _req(
            "IPI-01",
            "read_internal_file",
            str(env["secret"]),
        ),
        str(env["doc"]),
    )

    assert result.decision == "DENY"
    assert result.reason == "TOOL_NOT_ALLOWED"


def test_unknown_tool_is_denied(env):
    result = authorize_tool(
        _req(
            "IPI-04",
            "read_anything",
            str(env["doc"]),
        ),
        str(env["doc"]),
    )

    assert result.decision == "DENY"
    assert result.reason == "TOOL_NOT_ALLOWED"


# ---- 非当前文件与越权读取 ----


def test_other_upload_file_is_denied(env):
    result = authorize_tool(
        _req(
            "PATH-01",
            "read_uploaded_file",
            str(env["other"]),
        ),
        str(env["doc"]),
    )

    assert result.decision == "DENY"
    assert result.reason == "FILE_NOT_CURRENT_UPLOAD"


def test_absolute_private_path_is_denied(env):
    result = authorize_tool(
        _req(
            "IPI-02",
            "read_uploaded_file",
            str(env["secret"]),
        ),
        str(env["doc"]),
    )

    assert result.decision == "DENY"


# ---- 路径穿越 ----


def test_path_traversal_to_private_is_denied(env):
    traversal = str(
        env["up"]
        / "sub"
        / ".."
        / ".."
        / "private"
        / "secret.txt"
    )

    result = authorize_tool(
        _req(
            "PATH-01",
            "read_uploaded_file",
            traversal,
        ),
        str(env["doc"]),
    )

    assert result.decision == "DENY"


def test_double_dot_escape_is_denied(env):
    result = authorize_tool(
        _req(
            "PATH-01",
            "read_uploaded_file",
            "data/uploads/../private/secret.txt",
        ),
        str(env["doc"]),
    )

    assert result.decision == "DENY"


# ---- 文件名大小写 ----


@pytest.mark.skipif(
    os.name == "nt",
    reason=(
        "Windows路径默认不区分大小写，"
        "此测试只适用于大小写敏感的系统。"
    ),
)
def test_case_variant_is_denied(env):
    # Linux等大小写敏感系统中，
    # RESUME.TXT与resume.txt属于不同路径。
    result = authorize_tool(
        _req(
            "PATH-01",
            "read_uploaded_file",
            str(env["up"] / "RESUME.TXT"),
        ),
        str(env["doc"]),
    )

    assert result.decision == "DENY"
    assert result.reason == "FILE_NOT_CURRENT_UPLOAD"


# ---- 符号链接 ----


def test_symlink_escape_to_private_is_denied(env):
    link = env["up"] / "link.txt"

    try:
        os.symlink(
            env["secret"],
            link,
        )
    except OSError as exc:
        if getattr(exc, "winerror", None) == 1314:
            pytest.skip(
                "当前Windows环境没有创建符号链接的权限"
            )
        raise

    result = authorize_tool(
        _req(
            "PATH-01",
            "read_uploaded_file",
            str(link),
        ),
        str(link),
    )

    # 符号链接的真实目标位于private目录，
    # 因此必须拒绝。
    assert result.decision == "DENY"
    assert result.reason == "PATH_OUTSIDE_UPLOAD_ROOT"


def test_symlink_to_internal_file_allows_real_target(env):
    link = env["up"] / "link2.txt"

    try:
        os.symlink(
            env["other"],
            link,
        )
    except OSError as exc:
        if getattr(exc, "winerror", None) == 1314:
            pytest.skip(
                "当前Windows环境没有创建符号链接的权限"
            )
        raise

    result = authorize_tool(
        _req(
            "NOR-02",
            "read_uploaded_file",
            str(link),
        ),
        str(link),
    )

    # 符号链接的真实目标仍然位于uploads目录，
    # 因此可以放行。
    assert result.decision == "ALLOW"
    assert result.normalized_path == str(
        env["other"].resolve()
    )


# ---- 越过上传根目录 ----


def test_path_outside_upload_root_is_denied(env):
    # 即使current和target相同，
    # 只要文件位于UPLOAD_ROOT之外，也必须拒绝。
    result = authorize_tool(
        _req(
            "IPI-02",
            "read_uploaded_file",
            str(env["secret"]),
        ),
        str(env["secret"]),
    )

    assert result.decision == "DENY"
    assert result.reason == "PATH_OUTSIDE_UPLOAD_ROOT"