from io import BytesIO
from unittest.mock import patch

import pytest
from streamlit.testing.v1 import AppTest

from src.contracts import RunResult


@pytest.mark.parametrize("payload", [b" ", b"\xff", b"x" * (2 * 1024 * 1024 + 1)], ids=["empty", "encoding", "oversize"])
def test_invalid_document_never_calls_pipeline(payload):
    with patch("streamlit.file_uploader", return_value=BytesIO(payload)), patch("src.pipeline.run_document_review") as run:
        app = AppTest.from_file("app.py").run()
        app.button[0].click().run()
        assert app.error and not app.exception
        run.assert_not_called()


def test_persisted_result_retains_original_version_and_does_not_rerun():
    result = RunResult(case_id="MANUAL-01", system_version="protected", final_text="summary",
                       policy_decision="ALLOW", policy_reason="CURRENT_UPLOAD_ONLY")
    with patch("streamlit.file_uploader", return_value=BytesIO(b"document")), patch("src.pipeline.run_document_review", return_value=result) as run:
        app = AppTest.from_file("app.py").run()
        app.button[0].click().run()
        app.sidebar.selectbox[1].select("vulnerable").run()
        assert run.call_count == 1
        assert app.session_state.review_result["result"]["system_version"] == "protected"
        assert any("上一次" in x.value for x in app.info)


def test_running_state_resets_and_missing_audit_is_not_fabricated():
    result = RunResult(case_id="MANUAL-01", system_version="protected", final_text="summary")
    app = AppTest.from_file("app.py")
    def review(**kwargs):
        assert app.session_state.review_pending
        return result
    with patch("streamlit.file_uploader", return_value=BytesIO(b"document")), patch("src.pipeline.run_document_review", side_effect=review):
        app.run()
        app.button[0].click().run()
        assert not app.exception
        assert not app.session_state.review_pending
        # A mocked pipeline writes no matching audit record.
        assert app.session_state.review_result["audit"] is None
