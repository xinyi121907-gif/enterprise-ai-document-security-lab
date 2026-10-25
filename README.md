# Enterprise AI Document Security Lab

企业智能文档助手的间接提示词注入与越权数据泄露防护实验。

> 安全边界：本仓库只使用虚构数据，只允许在本地授权环境中演示。禁止读取真实个人、学校或企业资料，禁止连接或攻击第三方系统。

## 固定技术栈

- Python 3.11
- Ollama + `qwen2.5:7b`
- Streamlit
- pytest

## 四套系统版本

| 版本 | 控制方式 | 实验目的 |
|---|---|---|
| `vulnerable` | 无权限检查、无输出检查 | 复现越权读取与秘密泄露 |
| `prompt_only` | 只依赖系统提示词 | 验证软约束可能失效 |
| `keyword` | 关键词过滤 + 输出检测 | 验证改写绕过与误拦截 |
| `protected` | 代码级最小权限 + 输出检测 + 哈希日志 | 验证硬性访问控制 |

## 第一次启动

```powershell
py -3.11 -m venv .venv
.venv\Scripts\activate
python -m pip install -r requirements.txt
ollama pull qwen2.5:7b
pytest -q
streamlit run app.py
```

如果尚未安装 Ollama，可先运行测试；测试不调用模型。

## 固定目录

- `src/`：程序与安全模块
- `data/normal/`：2 个正常文档
- `data/attack/`：8 个攻击文档
- `data/private/`：虚构内部资料
- `tests/test_cases.json`：10 个冻结测试用例
- `artifacts/logs/`：JSONL 原始日志，不手工修改
- `results/`：实验汇总结果
- `docs/`：规则、交接说明与最终文档
- `handoff/`：成员按日期提交的中间交付
- `videos/`：最终演示视频（不要提交大文件到 Git）

## 分支命名

- CXY：`feature/cxy-integration`
- XRS：`feature/xrs-security`
- YCQ：`feature/ycq-cases`
- ZL：`feature/zl-evidence`

禁止直接在 `main` 上开发。合并前必须运行 `pytest -q`。

## 当前启动包状态

接口、目录、理由码、测试编号与样例数据已经固定。`pipeline.py` 和 `app.py` 是可启动骨架；各成员按 `docs/TEAM_START_HERE.md` 继续完成自己的正式模块。

