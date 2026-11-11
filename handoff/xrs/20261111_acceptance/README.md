# 11-11 交付：XRS 验收签字表（protected 权限门）

对应任务表（XRS，11 月 11 日）：验收签字表，工具执行前必有 `authorize_tool` 记录。
被验收对象为 CXY 整合版本，固定提交 `18a64528caaa171e57a4a10415f670702fcbde4c`（Merge pull request #45）。

## 目录约定

本目录保留四个条目：`XRS验收签字表.docx`（签字表）、`deny_branch_test_run.txt`（拒绝分支专项测试输出）、`test_run_log.jsonl`（测试过程产生的日志）、`README.md`（本索引）。
带 `(1)` 后缀的同名文件属于重复件，不保留。签字表由本地 python-docx 脚本生成，脚本不入库。

## 文件与校验值

| 文件 | 大小 | 说明 |
|---|---|---|
| `XRS验收签字表.docx` | 44 936 B | 八节 + 附录，含表 1 四类拒绝情形、表 2 正式 120 次判定统计、表 3 测试清单、表 4 签字栏、表 A.1 文件索引 |
| `deny_branch_test_run.txt` | 562 B | `pytest -v` 完整输出，21 passed |
| `test_run_log.jsonl` | 1 027 B | 测试过程产生的 1 条日志，`DENY` + `tool_executed=false` + trace 内 decision |

`XRS验收签字表.docx` SHA-256：`062e5f7e07c3fc68e9143c17e6af44c25e930f2e7739a2252e7ea4a6af514561`。
`git hash-object handoff/xrs/20261111_acceptance/XRS验收签字表.docx` 应得到 `02f10d83a2f88edc891cc414fde7f367e8a95807`。

## 核对结论

### protected 的两个读取入口

| 入口 | 代码位置 | 行为 |
|---|---|---|
| 初始读取 | `src/pipeline.py` 189–201 → `src/tools.py` 14–25 | 构造 ToolRequest 后调 `execute_tool_protected`，第 15 行 `authorize_tool`，第 19 行判 `decision`，非 ALLOW 直接返回 `executed=False, content=None` |
| 模型后续工具请求 | `src/pipeline.py` 220–231 | 第 224 行同样走 `execute_tool_protected`；第 226–230 行拒绝即 return，第 231 行的 `raw_text` 追加在 return 之后，拒绝时不执行 |
| 真实读取 | `src/tools.py` 24 | 全仓库 protected 唯一一处 `_read_text`，位于第 19 行判定之后，且读的是 `policy.normalized_path` |

### 四类拒绝分支（`src/policy_gate.py` 10–37）

`TASK_NOT_ALLOWED`（15–18）、`TOOL_NOT_ALLOWED`（19–22）、`FILE_NOT_CURRENT_UPLOAD`（23–28）、`PATH_OUTSIDE_UPLOAD_ROOT`（29–34）、`CURRENT_UPLOAD_ONLY`（35–37，ALLOW）。

### 测试结果

| 范围 | 结果 |
|---|---|
| 拒绝分支专项（policy_gate 14 + protected 集成 6 + 读取前置 1） | 21 passed |
| 全量回归（跳过 `test_runtime_ui.py`，本机缺 streamlit） | 48 passed |

`tests/test_protected_pipeline.py` 用 patch 替换 `src.tools._read_text`，断言 DENY 且 `read_text` 从未被调用；`tests/test_integration_protected.py` 有四条 never_reads 用例与一条 ALLOW 正例。

### 正式 120 次判定记录

| 版本 | 条数 | policy_decision | 模型工具请求 | unauthorized |
|---|---|---|---|---|
| vulnerable | 30 | 全空（无权限门） | 有 | 21 条 True |
| prompt_only | 30 | 全空（无权限门） | 无 | 0 |
| keyword | 30 | DENY 24 / 空 6 | 无 | 0 |
| protected | 30 | ALLOW 30（`CURRENT_UPLOAD_ONLY`） | 无 | 0 |

protected 的 30 条 `tool_requested` 为空、`tool_executed=false`、`mock=false`、`error` 为空，说明这批运行中模型未发起后续工具请求，记录的 ALLOW 来自初始读取；**正式批次未触发 DENY**。

## 两条限定（必须与汇报口径一致）

1. protected 在正式 120 次中未出现 DENY，拒绝路径有效性由单独测试证明，不得说成“正式实验拦截了 N 次越权”。
2. 正式批次中模型未发起后续工具请求，“模型请求被拒且内容未进入最终文本”只在测试环境验证过。

vulnerable 与 prompt_only 不调用 `authorize_tool`（`src/tools.py` 28–35、`src/pipeline.py` 52–150），决策字段为空是设计结果，不按 protected 标准判错。

## 日志隔离

拒绝分支测试在固定提交的独立工作目录中执行，执行前清空该目录日志；产生的 1 条写入单独保存为 `test_run_log.jsonl`，文件内的本地绝对路径已脱敏（统一替换为 `<validation-worktree>`），**未**写入正式批次 `artifacts/logs/run_log.jsonl`。正式数据取自 `handoff/zl/2026_11_8/raw_runs_all.csv` 与 `raw_runs_all_log_120.jsonl`，`mock` 全为 False。

## 复现命令

```bash
python3 -m pytest -q tests/test_policy_gate.py tests/test_protected_pipeline.py tests/test_integration_protected.py -v
python3 -m pytest -q --ignore=tests/test_runtime_ui.py
```

## 已知问题

- 本机无 git push 凭据，`.docx` 二进制需在 GitHub 网页上传，上传时确认文件名不带 `(1)` 后缀。
- 全量回归中未包含 `tests/test_runtime_ui.py`，该用例依赖 streamlit，与权限门无关。
- 本分支落后 `main` 41 个提交且无独有提交，合并时以 `main` 的 11-10 目录内容（56 170 B 版）为准，本目录为新增文件不与其冲突。
