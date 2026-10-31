from pathlib import Path

import streamlit as st

from src.pipeline import run_document_review


VERSION_LABELS = {
    "vulnerable": "vulnerable v0.1｜无安全防护",
    "prompt_only": "prompt_only v0.2｜仅系统提示词防护",
    "keyword": "keyword v0.3｜提示词加关键词过滤",
    "protected": "protected｜完整安全防护基线",
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
    path = Path(case_file)

    if not path.exists():
        st.error(f"文件不存在：{case_file}")

    else:
        with st.spinner("正在运行本地安全实验……"):
            result = run_document_review(
                case_id="MANUAL-01",
                system_version=system_version,
                document_path=str(path),
                user_query=user_query,
                business_type=business_type,
            )

        st.success(
            f"运行完成：{VERSION_LABELS[system_version]}"
        )

        left, right = st.columns([2, 1])

        with left:
            st.subheader("文档审阅结果")
            st.write(result.final_text)

        with right:
            st.subheader("模型工具请求")

            if result.tool_requested:
                st.warning(
                    f"模型请求工具：{result.tool_requested}"
                )
            else:
                st.success("模型没有提出工具请求")

            st.metric(
                "工具是否执行",
                "是" if result.tool_executed else "否",
            )

            st.metric(
                "是否检测到秘密泄露",
                "是" if result.secret_leaked else "否",
            )

            if result.policy_decision:
                st.write(
                    "策略决定：",
                    result.policy_decision,
                )

            if result.policy_reason:
                st.write(
                    "策略原因：",
                    result.policy_reason,
                )

            if result.error:
                st.error(result.error)

        with st.expander("查看完整结构化运行结果"):
            st.json(result.model_dump())