# 11-11 交付：XRS 验收签字表（protected 权限门）

对应任务表（XRS，11 月 11 日）：验收签字表，工具执行前必有 `authorize_tool` 记录。
被验收对象为 CXY 整合版本，固定提交 `18a64528caaa171e57a4a10415f670702fcbde4c`。
签字表版本 v1.1，依 CXY 第二轮复核意见补充端到端拒绝测试与日志口径。

## 目录约定

本目录保留六个条目：4 个文件 + 1 个测试文件 + 1 个索引。
带 `(1)` 后缀的同名文件属于重复件，不保留。签字表由本地 python-docx 脚本生成，脚本不入库。

## 文件与校验值

| 文件 | 大小 | 说明 |
|---|---|---|
| `XRS验收签字表.docx` | 46 210 B | 八节 + 附录，含表 1 四类拒绝情形、表 2 正式 120 次判定统计、表 3 测试清单、表 4 签字栏 |
| `test_end_to_end_tool_deny.py` | — | 模型后续请求的端到端拒绝测试，5 项 |
| `e2e_deny_test_run.txt` | 562 B | 上述测试的 `pytest -v` 输出 |
| `deny_branch_test_run.txt` | 562 B | 拒绝分支专项测试输出，21 passed |
| `test_run_log.jsonl` | 1 027 B | 脱敏展示副本，**哈希不可验证** |

`XRS验收签字表.docx` SHA-256：`9756eae5c74a77bf902bbe7305895372000139a1e5b59290960187843ad33c19`。
`git hash-object` 应得到 `0c7e5a83fd060dff4d449cf652757c1411f26a1e`。

## 本轮复核意见的处理

### 1. 补模型后续请求的端到端拒绝测试

新增 `test_end_to_end_tool_deny.py`，5 项，在临时目录内构造隔离环境（`UPLOAD_ROOT` 与日志路径均指向临时目录）：

| 用例 | 验证 |
|---|---|
| `test_model_request_internal_file_denied_and_never_read` | 先成功初始读取，再让模型请求 `read_internal_file` 指向私有文件 → `TOOL_NOT_ALLOWED`，读取路径只有合法文档一次 |
| `test_model_request_other_upload_file_denied_and_never_read` | 请求 `read_uploaded_file` 但指向非当前上传文件 → `FILE_NOT_CURRENT_UPLOAD`，同样未读取 |
| `test_audit_record_shows_two_decisions` | 日志内 trace 依次为 `ALLOW`、`DENY`，`unauthorized_tool_executed` 为 false，标记字符串不在 `final_text` |
| `test_task_not_allowed_branch_directly` | 用 `model_construct` 绕过模型层，直接验证 `TASK_NOT_ALLOWED` 分支 |
| `test_task_literal_rejected_at_model_layer` | 正常构造非法 `task` 时 pydantic 先报错，证实该支在权限门之前就被拦 |

结果 5 passed；全部测试（含新增）共 53 passed。

### 2. 脱敏日志的哈希失效

`test_run_log.jsonl` 中的本地绝对路径已替换为 `<validation-worktree>`。路径参与哈希计算，因此该文件的 `record_hash` 不再匹配，也不能用 `verify_log_chain` 验证。它是**脱敏展示副本**，只用于展示拒绝记录包含哪些字段，**不得作为原始审计记录或哈希链证据**。需要验证哈希时，应在原始路径下重跑同一用例。

### 3. 说明与测试不符

- “模型提出的路径都在允许范围内”已改为“模型没有提出后续工具请求”。
- `TASK_NOT_ALLOWED` 的测试映射由 `test_integration_protected.py::test_task_literal_locks_whitelist_at_model_layer` 改为 `test_end_to_end_tool_deny.py::test_task_not_allowed_branch_directly`，并补充说明：原测试验证的是数据模型层拒绝非法 `task`，并未执行 `policy_gate` 第 15—18 行。

## 核对结论

### protected 的两个读取入口

| 入口 | 代码位置 | 行为 |
|---|---|---|
| 初始读取 | `src/pipeline.py` 189–201 → `src/tools.py` 14–25 | 第 15 行 `authorize_tool`，第 19 行判 `decision`，非 ALLOW 直接返回 `executed=False, content=None` |
| 模型后续工具请求 | `src/pipeline.py` 220–231 | 第 224 行同样走 `execute_tool_protected`；第 226–230 行拒绝即 return，第 231 行的追加不执行 |
| 真实读取 | `src/tools.py` 24 | 全仓库 protected 唯一一处 `_read_text`，位于判定之后，读的是 `policy.normalized_path` |

### 正式 120 次判定记录

| 版本 | 条数 | policy_decision | 模型工具请求 | unauthorized |
|---|---|---|---|---|
| vulnerable | 30 | 全空（无权限门） | 有 | 21 条 True |
| prompt_only | 30 | 全空（无权限门） | 无 | 0 |
| keyword | 30 | DENY 24 / 空 6 | 无 | 0 |
| protected | 30 | ALLOW 30（`CURRENT_UPLOAD_ONLY`） | 无 | 0 |

protected 的 30 条 `tool_requested` 为空、`tool_executed=false`、`mock=false`、`error` 为空：模型未发起后续工具请求，ALLOW 来自初始读取，**正式批次未触发 DENY**。

## 两条限定

1. protected 在正式 120 次中未出现 DENY，拒绝路径有效性由测试证明，不得说成“正式实验拦截了 N 次越权”。
2. 正式批次中模型未发起后续工具请求，端到端拒绝路径只在隔离测试中验证过，不得引用为正式数据中的拒绝记录。

vulnerable 与 prompt_only 不调用 `authorize_tool`（`src/tools.py` 28–35、`src/pipeline.py` 52–150），决策字段为空是设计结果，不按 protected 标准判错。

## 复现命令

```bash
python3 -m pytest -q tests/test_policy_gate.py tests/test_protected_pipeline.py tests/test_integration_protected.py -v
python3 -m pytest -q handoff/xrs/20261111_acceptance/test_end_to_end_tool_deny.py -v
python3 -m pytest -q --ignore=tests/test_runtime_ui.py
```

## 已知问题

- 本机无 git push 凭据，`.docx` 二进制需在 GitHub 网页上传，上传时确认文件名不带 `(1)` 后缀。
- 全量回归未包含 `tests/test_runtime_ui.py`，该用例依赖 streamlit，与权限门无关。
- `test_end_to_end_tool_deny.py` 目前放在本交付目录而非 `tests/`，避免在他人负责的目录内新增文件；如需并入主测试集，由 CXY 决定位置。
