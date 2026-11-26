import hashlib
import json
import os
from datetime import datetime
from pathlib import Path
from urllib.request import urlopen
from uuid import uuid4

import streamlit as st

from src.audit_logger import LOG_PATH
from src.model_client import DEFAULT_MODEL
from src.pipeline import run_document_review

PROJECT_ROOT = Path(__file__).resolve().parent
UPLOAD_ROOT = PROJECT_ROOT / "data" / "uploads"
MAX_UPLOAD_BYTES = 2 * 1024 * 1024
VERSION_LABELS = {
    "vulnerable": "无防护",
    "prompt_only": "提示词约束",
    "keyword": "关键词过滤",
    "protected": "最小权限防护",
}
DESCRIPTIONS = {
    "vulnerable": "直接执行模型工具请求，用于观察注入与泄露风险。",
    "prompt_only": "通过系统提示词约束模型行为。",
    "keyword": "提示词约束结合静态关键词过滤及输出检查。",
    "protected": "每次文件读取前检查权限，并检查最终输出。",
}


@st.cache_data(ttl=15, show_spinner=False)
def model_status():
    host = os.environ.get("OLLAMA_HOST", "http://localhost:11434").rstrip("/")
    if "://" not in host:
        host = "http://" + host
    try:
        with urlopen(host + "/api/tags", timeout=1.5) as response:
            models = json.load(response).get("models", [])
        ready = any(m.get("name") == DEFAULT_MODEL for m in models)
        return ("本地模型已连接" if ready else "模型未安装", datetime.now().strftime("%H:%M:%S"))
    except Exception:
        return ("连接检测失败", datetime.now().strftime("%H:%M:%S"))


def matching_audit(path):
    """Match the unique upload path, so concurrent sessions cannot share evidence."""
    try:
        for line in reversed(LOG_PATH.read_text(encoding="utf-8").splitlines()):
            try:
                record = json.loads(line)
            except ValueError:
                continue
            if record.get("document_path") == str(path):
                return record
    except OSError:
        pass
    return None


def submit_review():
    st.session_state.review_pending = True


st.set_page_config(page_title="企业智能文档助手", page_icon="📄", layout="wide")
st.markdown((PROJECT_ROOT / "ui.css").read_text(encoding="utf-8"), unsafe_allow_html=True)
st.session_state.setdefault("review_pending", False)
pending = st.session_state.review_pending

with st.sidebar:
    st.markdown('<div class="brand-mark">D<span> / </span>GUARD</div>', unsafe_allow_html=True)
    st.caption("企业文档安全实验室")
    st.divider()
    st.markdown("### 审阅设置")
    business_type = st.selectbox("业务类型", ["resume_review", "contract_review"],
                                format_func=lambda x: "简历审阅" if x == "resume_review" else "合同审阅", disabled=pending)
    system_version = st.selectbox("实验版本", list(VERSION_LABELS), index=3,
                                  format_func=lambda x: VERSION_LABELS[x] + " · " + x, disabled=pending)
    st.caption(DESCRIPTIONS[system_version])
    with st.expander("了解四个实验版本"):
        for version, label in VERSION_LABELS.items():
            st.markdown(f"**{label}** · `{version}`")
            st.caption(DESCRIPTIONS[version])
    st.divider()
    st.caption("教学实验 · 全部使用虚构数据")

heading, connection = st.columns([3, 1])
with heading:
    st.title("企业智能文档助手")
    st.caption("文档审阅 · 权限控制 · 审计追踪")
with connection:
    status, checked = model_status()
    st.markdown(f"**{status}**")
    st.caption(DEFAULT_MODEL)
st.divider()
workspace, output = st.columns([1, 1.3], gap="large")
with workspace:
    with st.container(border=True):
        st.subheader("文档工作区")
        uploaded = st.file_uploader("上传 TXT 文档", type=["txt"], disabled=pending,
                                    help="UTF-8 编码，最大 2 MB。")
        file_bytes = uploaded.getvalue() if uploaded is not None else None
        validation = None
        decoded = None
        if file_bytes is not None:
            if not file_bytes.strip():
                validation = "文档为空，请选择有内容的 TXT 文件。"
            elif len(file_bytes) > MAX_UPLOAD_BYTES:
                validation = "文件超过 2 MB，请选择更小的 TXT 文件。"
            else:
                try:
                    decoded = file_bytes.decode("utf-8")
                except UnicodeDecodeError:
                    validation = "文件不是 UTF-8 编码，请转换后重试。"
            if validation:
                st.error(validation)
            else:
                st.caption(f"{getattr(uploaded, 'name', '上传文档.txt')} · {len(file_bytes):,} 字节")
                with st.expander("查看文档内容"):
                    st.text(decoded[:12000])
                    if len(decoded) > 12000:
                        st.caption("预览前 12,000 个字符，审阅使用完整文档。")
        query = st.text_area("审阅要求", "请提取这份文档的关键信息", height=110, disabled=pending)
        fingerprint = (hashlib.sha256(file_bytes or b"").hexdigest(), system_version, business_type, query)
        st.button("审阅中…" if pending else "开始审阅", type="primary", use_container_width=True,
                  disabled=pending, on_click=submit_review)

if pending:
    st.session_state.review_exception = None
    try:
        if uploaded is None:
            st.session_state.review_message = "请先上传本次要审阅的 TXT 文件。"
        elif validation:
            st.session_state.review_message = validation
        else:
            UPLOAD_ROOT.mkdir(parents=True, exist_ok=True)
            path = UPLOAD_ROOT / f"{uuid4().hex}.txt"
            with path.open("xb") as file:
                file.write(file_bytes)
            with output, st.spinner("正在审阅文档，请稍候…"):
                result = run_document_review(case_id="MANUAL-01", system_version=system_version,
                                             document_path=str(path), user_query=query, business_type=business_type)
            st.session_state.review_result = {
                "result": result.model_dump(), "audit": matching_audit(path), "fingerprint": fingerprint,
                "filename": getattr(uploaded, "name", "上传文档.txt"), "time": datetime.now().strftime("%H:%M:%S"),
            }
            st.session_state.review_message = None
    except Exception as exc:
        st.session_state.review_message = "运行未完成，请检查文件权限、模型服务及审计日志写入。"
        st.session_state.review_exception = str(exc)
    finally:
        st.session_state.review_pending = False
    st.rerun()

with output:
    message = st.session_state.get("review_message")
    if message:
        st.error(message)
        if st.session_state.get("review_exception"):
            with st.expander("查看原始错误"):
                st.text(st.session_state.review_exception)
    saved = st.session_state.get("review_result")
    with st.container(border=True):
        st.subheader("审阅结果")
        if not saved:
            st.markdown('<div class="empty-result"><div class="paper-symbol">▤</div><h3>等待第一份文档</h3><p>上传 TXT 文件并开始审阅<br>摘要与安全判定将在这里呈现</p></div>', unsafe_allow_html=True)
        else:
            r, audit = saved["result"], saved["audit"]
            st.caption(f"{saved['filename']} · {VERSION_LABELS[r['system_version']]} · {saved['time']}")
            if saved["fingerprint"] != fingerprint or message:
                st.info("以下保留上一次已完成运行的结果。当前设置或本次提交尚未产生新结果。")
            decision = r["policy_decision"]
            if r["error"]:
                st.error("审阅失败，请检查模型服务或文件访问，展开详情查看原始错误。")
            elif decision == "DENY":
                st.warning("权限或规则检查拒绝了本次操作。")
            elif decision == "BLOCK_OUTPUT":
                st.warning("输出防护已拦截结果展示。")
            elif r["secret_leaked"]:
                st.error("实验检测到数据泄露：输出包含虚构秘密标记。")
            else:
                st.success("文档审阅已完成")
            st.write(r["final_text"])
            st.divider()
            st.markdown("**安全判定**")
            if decision == "ALLOW":
                st.write("已授权读取当前文档" if r["policy_reason"] == "CURRENT_UPLOAD_ONLY" else "本次操作已获授权")
                st.caption("授权结论适用于本次请求。")
            elif not decision:
                st.write("不适用 · 此版本未设置策略门" if r["system_version"] in ("vulnerable", "prompt_only") else "本次未触发干预判定")
            if decision:
                st.code(f"{decision}\n{r['policy_reason'] or '未记录理由'}", language=None)
            st.caption("以上为本次运行结果。")
            with st.expander("工具调用与审计详情"):
                st.write("模型后续工具请求", r["tool_requested"] or "未提出工具请求")
                st.write("模型请求对应的工具执行", "是" if r["tool_executed"] else "否")
                st.caption("此字段不包含程序初始读取。protected 的初始读取也经过权限门。")
                if audit:
                    unauthorized = audit.get("unauthorized_tool_executed")
                    st.write("越权工具执行", "未记录" if unauthorized is None else ("是" if unauthorized else "否"))
                    st.write("耗时", f"{audit.get('elapsed_ms', '未记录')} ms")
                    st.write("工具轨迹（按执行顺序）")
                    st.json(audit.get("tool_trace", []))
                    st.caption("轨迹中的 ALLOW 表示授权判定，读取失败仍需结合 error 判断。")
                else:
                    st.caption("未读取到匹配本次上传路径的审计记录。")
                st.write("秘密标记泄露", "是" if r["secret_leaked"] else "否")
                if r["error"]:
                    st.text(r["error"])
                st.json(r)
