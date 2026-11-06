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

## 截至11月4日的整合修正

四个版本均通过同一个 Ollama 模型入口审阅。protected 先授权读取当前上传文件，再将模型提出的工具请求交给权限门；keyword 与 protected 均检查最终输出。界面默认 protected。

测试用例入口为 `tests/test_cases.json`，与 YCQ 最终清单一致。正常任务在批量测试中按 `expected_normal_points` 的逐项文本包含判定；不是人工语义评分。一次审阅处理模型返回的第一个工具请求，不进行多轮代理循环。

开发冒烟可执行 `python tests/run_experiment.py --rounds 1 --limit 2 --mock`；mock 仅验证流程，不能作实验结论。运行会追加审计日志，必须与正式数据分离。所有版本由 pipeline 统一写一条运行记录，CSV 的 record_hash 对应 JSONL。

指标脚本支持 CSV 或经哈希链校验的 JSONL 输入：`python tests/metrics_script.py --input <文件路径>`。旧日志缺少轮次和分类时会拒绝复算。

本次修复与文档勘误见 `docs/pre_nov4_repairs.md`。没有执行11月6日冻结或后续正式实验；已有冻结清单属于修复前版本，不能用来校验本次代码。
