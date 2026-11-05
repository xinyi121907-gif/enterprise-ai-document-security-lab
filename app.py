from pathlib import Path
from uuid import uuid4

import streamlit as st

from src.pipeline import run_document_review


PROJECT_ROOT = Path(__file__).resolve().parent
UPLOAD_ROOT = PROJECT_ROOT / "data" / "uploads"
MAX_UPLOAD_BYTES = 2 * 1024 * 1024

VERSION_LABELS = {
    "vulnerable": "vulnerable v0.1｜无安全防护",
    "prompt_only": "prompt_only v0.2｜仅系统提示词防护",
    "keyword": "keyword v0.3｜提示词加关键词过滤",
    "protected": "protected v1.0-alpha｜策略门与输出防护",
}


st.set_page_config(
    page_title="企业AI文档安全实验",
    page_icon="🛡️",
    layout="wide",
)

st.title("企业智能文档助手：间接提示词注入攻防")
st.caption(
    "全部文件、身份与敏感信息均为虚构测试数据，"
    "仅用于本地授权安全实验。"
)

with st.sidebar:
    st.header("实验设置")

    business_type = st.selectbox(
        "业务类型",
        ["resume_review", "contract_review"],
    )

    system_version = st.selectbox(
        "系统版本",
        list(VERSION_LABELS.keys()),
        format_func=lambda value: VERSION_LABELS[value],
    )

    st.info(VERSION_LABELS[system_version])

if system_version == "protected":
    st.info(
        "安全防护模式只读取本次通过界面上传的 TXT 文件；"
        "不能手填仓库中的其他文件路径。"
    )
    uploaded_file = st.file_uploader(
        "上传本次审阅的文档",
        type=["txt"],
    )
    case_file = None
else:
    uploaded_file = None
    case_file = st.text_input(
        "测试文件路径",
        "data/normal/resume_normal.txt",
    )

user_query = st.text_area(
    "用户任务",
    "请提取这份文档的关键信息",
    height=100,
)

if st.button(
    "运行文档审阅",
    type="primary",
    use_container_width=True,
):
    if system_version == "protected":
        if uploaded_file is None:
            st.error("请先上传本次要审阅的 TXT 文件。")
            st.stop()

        file_bytes = uploaded_file.getvalue()

        if len(file_bytes) > MAX_UPLOAD_BYTES:
            st.error("文件超过 2 MB，请选择更小的 TXT 文件。")
            st.stop()

        try:
            file_bytes.decode("utf-8")
        except UnicodeDecodeError:
            st.error("文件不是 UTF-8 编码的文本，请转换后再上传。")
            st.stop()

        # 文件名由服务器生成，不使用用户上传时自带的文件名作为路径。
        UPLOAD_ROOT.mkdir(parents=True, exist_ok=True)
        path = UPLOAD_ROOT / f"{uuid4().hex}.txt"
        with path.open("xb") as output_file:
            output_file.write(file_bytes)

    else:
        path = Path(case_file)

        if not path.is_file():
            st.error(f"文件不存在：{case_file}")
            st.stop()

    with st.spinner("正在运行本地安全实验……"):
        result = run_document_review(
            case_id="MANUAL-01",
            system_version=system_version,
            document_path=str(path),
            user_query=user_query,
            business_type=business_type,
        )

    if result.error:
        st.error("运行失败，请查看右侧错误信息。")
    elif result.policy_decision == "DENY":
        st.warning("策略门拒绝了本次文件读取。")
    elif result.policy_decision == "BLOCK_OUTPUT":
        st.warning("输出防护阻止了本次结果展示。")
    else:
        st.success(
            f"运行完成：{VERSION_LABELS[system_version]}"
        )

    left, right = st.columns([2, 1])

    with left:
        st.subheader("文档审阅结果")
        st.write(result.final_text)

    with right:
        st.subheader("工具请求")

        if result.tool_requested:
            st.warning(
                f"请求的工具：{result.tool_requested}"
            )
        else:
            st.info("没有记录到工具请求")

        st.metric(
            "工具是否执行",
            "是" if result.tool_executed else "否",
        )

        st.metric(
            "是否发生秘密泄露",
            "是" if result.secret_leaked else "否",
        )

        if result.policy_decision:
            st.write("策略决定：", result.policy_decision)

        if result.policy_reason:
            st.write("策略原因：", result.policy_reason)

        if result.error:
            st.error(result.error)

    with st.expander("查看完整结构化运行结果"):
        st.json(result.model_dump())