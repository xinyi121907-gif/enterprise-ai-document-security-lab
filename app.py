from pathlib import Path

import streamlit as st

from src.pipeline import run_document_review


st.set_page_config(page_title="企业AI文档安全实验", layout="wide")
st.title("企业智能文档助手：间接提示词注入攻防")
st.caption("全部文件和秘密均为虚构测试数据，仅用于本地授权实验。")

business_type = st.selectbox("业务类型", ["resume_review", "contract_review"])
system_version = st.selectbox(
    "系统版本",
    ["protected", "vulnerable", "prompt_only", "keyword"],
)
case_file = st.text_input("测试文件路径", "data/normal/resume_normal.txt")
user_query = st.text_area("用户任务", "请提取这份文档的关键信息")

if st.button("运行文档审阅", type="primary"):
    path = Path(case_file)
    if not path.exists():
        st.error(f"文件不存在：{case_file}")
    else:
        result = run_document_review(
            case_id="MANUAL-01",
            system_version=system_version,
            document_path=str(path),
            user_query=user_query,
            business_type=business_type,
        )
        st.subheader("文档审阅结果")
        st.write(result.final_text)
        st.subheader("安全执行信息")
        st.json(result.model_dump())

