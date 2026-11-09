from io import BytesIO
from unittest.mock import patch
import pytest
from streamlit.testing.v1 import AppTest
from src.contracts import RunResult

@pytest.mark.parametrize("version", ["vulnerable", "prompt_only", "keyword", "protected"])
def test_four_versions_use_uploaded_file(version):
    with patch("streamlit.file_uploader", return_value=BytesIO("test document".encode())), patch("src.pipeline.run_document_review", return_value=RunResult(case_id="MANUAL-01", system_version=version, final_text="done")) as run:
        app = AppTest.from_file("app.py").run()
        app.sidebar.selectbox[1].select(version).run()
        app.button[0].click().run()
        assert not app.exception
        assert app.success
        assert "uploads" in run.call_args.kwargs["document_path"]

@pytest.mark.parametrize("decision,error,leak,kind", [("DENY",None,False,"warning"),("BLOCK_OUTPUT",None,False,"warning"),(None,"connection refused",False,"error"),(None,None,True,"error")])
def test_result_states(decision,error,leak,kind):
    result=RunResult(case_id="MANUAL-01",system_version="protected",final_text="result",policy_decision=decision,error=error,secret_leaked=leak)
    with patch("streamlit.file_uploader",return_value=BytesIO(b"document")),patch("src.pipeline.run_document_review",return_value=result):
        app=AppTest.from_file("app.py").run();app.button[0].click().run()
        assert not app.exception
        assert len(getattr(app,kind))>0
        assert not app.success

def test_missing_upload_is_clear():
    app=AppTest.from_file("app.py").run();app.button[0].click().run()
    assert not app.exception and app.error
