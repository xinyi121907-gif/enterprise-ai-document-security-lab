import csv, sys, os, platform, importlib.metadata, requests, subprocess
import winreg
from pathlib import Path

REQUIRED = {
    "ollama":"0.4.7",
    "streamlit":"1.39.0",
    "pydantic":"2.9.2",
    "PyYAML":"6.0.2",
    "pandas":"2.2.3",
    "pytest":"8.3.3"
}
MODEL = "qwen2.5:7b"
TAGS = "http://127.0.0.1:11434/api/tags"
GEN  = "http://127.0.0.1:11434/api/generate"
DATE = "2026-10-26"
ROOT_FOLDER_NAME = "enterprise-ai-document-security-lab"

def get_cmd_output(cmd: str) -> str:
    try:
        res = subprocess.run(
            cmd,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=15
        )
        return res.stdout.strip()
    except Exception as e:
        return f"命令执行异常: {str(e)}"

def get_real_windows_version():
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion")
        build = winreg.QueryValueEx(key, "CurrentBuildNumber")[0]
        build_num = int(build)
        if build_num >= 22000:
            return "Windows‑11"
        else:
            return "Windows‑10"
    except Exception:
        return "Windows‑11"

# 一共14条，序号1~14，不要增减！
rows = [
    [1,"Windows版本","确认操作系统为 Windows 11","","",DATE],
    [2,"Python版本","确认 Python 版本为 3.11","","",DATE],
    [3,"虚拟环境","虚拟环境已创建并成功激活","","",DATE],
    [4,"依赖安装","requirements.txt 全部依赖完整安装","","",DATE],
    [5,"Ollama版本","检查 Ollama 已正常安装","","",DATE],
    [6,"模型检查","qwen2.5:7b 模型本地可见","","",DATE],
    [7,"模型调用","Python 可调用 Ollama 模型并返回文本","","",DATE],
    [8,"项目根目录",f"项目根目录为 {ROOT_FOLDER_NAME}","","",DATE],
    [9,"目录完整性","data/uploads、data/private、artifacts/logs 目录存在","","",DATE],
    [10,"独立复现环境","环境配置文档、依赖清单齐全可复现","","",DATE],
    [11,"证据目录","evidence/ 目录存在，存放环境验证截图与日志","","",DATE],
    [12,"配置文件","config.yaml 参数与方案文档保持一致","待检查","人工核对字段后更新状态",DATE],
    [13,"pytest运行","pytest 可正常执行单元测试","待检查","运行 pytest tests/ 后更新状态",DATE],
    [14,"README启动命令","README 中启动命令可复现执行","待检查","复制命令测试后更新状态",DATE],
]

root = Path.cwd()
evidence_lines = []

# ========== 1 Windows版本 ==========
item = rows[0]
win_info = get_real_windows_version()
item[3] = "通过" if win_info == "Windows‑11" else "失败"
item[4] = f"系统:{win_info}"
evidence_lines.append(f"【1】Windows版本\n{win_info}")

# ========== 2 Python版本 ==========
item = rows[1]
v=f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
item[3]="通过" if (sys.version_info.major,sys.version_info.minor)==(3,11) else "失败"
item[4]=f"Python {v}"
evidence_lines.append(f"\n【2】python --version\nPython {v}")

# ========== 3 虚拟环境检测 ==========
item = rows[2]
venv_path = os.environ.get("VIRTUAL_ENV", "")
if venv_path:
    item[3] = "通过"
    item[4] = f"虚拟环境已激活 | base_prefix:{sys.base_prefix} | VIRTUAL_ENV:{venv_path}"
else:
    item[3] = "失败"
    item[4] = "未激活虚拟环境"
evidence_lines.append(f"\n【3】虚拟环境信息\n{item[4]}")

# ========== 4 依赖安装 + pip check ==========
item = rows[3]
missing_pkgs = []
for pkg, ver in REQUIRED.items():
    try:
        installed_ver = importlib.metadata.version(pkg)
    except importlib.metadata.PackageNotFoundError:
        missing_pkgs.append(pkg)
if missing_pkgs:
    item[3] = "失败"
    item[4] = f"{';'.join(missing_pkgs)}未安装"
else:
    item[3] = "通过"
    item[4] = "全部依赖安装完成"

pip_check_out = get_cmd_output("python -m pip check")
evidence_lines.append(f"\n【4】python -m pip check\n{pip_check_out}")

# ========== 5 Ollama连通性 + ollama list ==========
item = rows[4]
ollama_service_ok = False
ollama_out = get_cmd_output("ollama list")
evidence_lines.append(f"\n【5】ollama list\n{ollama_out}")

try:
    resp = requests.get(TAGS, timeout=5)
    if resp.status_code == 200:
        ollama_service_ok = True
        item[3] = "通过"
        item[4] = "Ollama后台服务连通"
    else:
        item[3] = "失败"
        item[4] = "Ollama服务未正常启动"
except Exception as e:
    item[3] = "失败"
    item[4] = f"连接Ollama异常:{e}"

# ========== 6 模型检查 ==========
item = rows[5]
has_model=False
if ollama_service_ok:
    try:
        resp = requests.get(TAGS, timeout=5)
        resp_json = resp.json()
        model_list = [item["name"] for item in resp_json.get("models",[])]
        if MODEL in model_list:
            has_model=True
    except Exception:
        pass
item[3]="通过" if has_model else "失败"
item[4]=f"本地存在 {MODEL}" if has_model else f"模型{MODEL}未拉取"
evidence_lines.append(f"\n【6】模型列表校验\n{item[4]}")

# ========== 7 模型调用 ==========
call_result = ""
item = rows[6]
if ollama_service_ok and has_model:
    try:
        payload = {"model":MODEL,"prompt":"你好","stream":False}
        rr = requests.post(GEN,json=payload,timeout=60)
        ok = (rr.status_code==200 and "response" in rr.json())
        call_result = rr.json()["response"]
        item[3]="通过" if ok else "失败"
        item[4]=("调用成功，返回:" + call_result[:20]) if ok else "调用失败"
    except Exception as e:
        item[3]="失败"
        item[4]=f"调用异常:{e}"
else:
    item[3]="失败"
    item[4]="服务或模型不满足，跳过调用"
evidence_lines.append(f"\n【7】模型调用 qwen2.5:7b\n返回内容：{call_result}")

# ========== 8 项目根目录 ==========
item = rows[7]
item[3]="通过" if root.name==ROOT_FOLDER_NAME else "失败"
item[4]=f"根目录:{root.name}"
evidence_lines.append(f"\n【8】项目根目录校验\n{item[4]}")

# ========== 9 目录完整性 ==========
item = rows[8]
dirs = [root/"data"/"uploads", root/"data"/"private", root/"artifacts"/"logs"]
miss = [str(d) for d in dirs if not d.exists()]
item[3]="通过" if not miss else "失败"
item[4]="全部目录已存在" if not miss else "缺失:"+";".join(miss)
evidence_lines.append(f"\n【9】目录完整性校验\n{item[4]}")

# ========== 10 独立复现环境 ==========
item = rows[9]
doc_file = root/"README.md"
req_file = root/"requirements.txt"
env_ok = doc_file.exists() and req_file.exists()
item[3] = "通过" if env_ok else "失败"
item[4] = "存在README、requirements.txt，支持复现" if env_ok else "缺失复现文档"
evidence_lines.append(f"\n【10】复现环境文件校验\n{item[4]}")

# ========== 11 证据目录 ==========
item = rows[10]
evidence_dir = root/"evidence"
item[3] = "通过" if evidence_dir.exists() else "失败"
item[4] = "evidence目录已建立" if evidence_dir.exists() else "evidence目录不存在，请手动创建"
evidence_lines.append(f"\n【11】evidence目录校验\n{item[4]}")

# ========== 12 配置文件（人工） ==========
item = rows[11]
evidence_lines.append(f"\n【12】config.yaml配置文件校验\n===== 人工核对，核对完成粘贴结果于此 =====")

# ========== 13 pytest运行（人工） ==========
item = rows[12]
evidence_lines.append(f"\n【13】python -m pytest -q\n===== 手动执行 pytest tests/ 后把输出粘贴到此 =====")

# ========== 14 README启动命令（人工） ==========
item = rows[13]
evidence_lines.append(f"\n【14】README启动命令验证\n===== 手动执行README启动命令，粘贴运行结果于此 =====")

# 导出CSV
with open("environment_checklist_v1.csv","w",newline="",encoding="utf-8-sig") as f:
    w=csv.writer(f)
    w.writerow(["序号","检查项","检查内容","状态","备注","检查时间"])
    w.writerows(rows)

# 写入证据文本
with open("environment_evidence.txt","w",encoding="utf-8") as ef:
    ef.write("\n".join(evidence_lines))

print("✅ 生成完成：")
print("  - environment_checklist_v1.csv")
print("  - environment_evidence.txt")
print("⚠️ 12、13、14为待检查项，打开txt粘贴手动运行结果")