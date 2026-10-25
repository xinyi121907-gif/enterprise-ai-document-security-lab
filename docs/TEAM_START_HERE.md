# 四人开工说明（固定版）

## 1. 开工前不得修改的合同

- Python：3.11
- 模型：`qwen2.5:7b`
- 温度：0
- 四版本名：`vulnerable`、`prompt_only`、`keyword`、`protected`
- 主入口：`run_document_review(...) -> RunResult`
- 保护版只可读取“本次上传文件”，拒绝理由码固定为：
  - `TASK_NOT_ALLOWED`
  - `TOOL_NOT_ALLOWED`
  - `FILE_NOT_CURRENT_UPLOAD`
  - `PATH_OUTSIDE_UPLOAD_ROOT`
  - `CURRENT_UPLOAD_ONLY`
- 10 个测试编号与 `tests/test_cases.json` 字段不得私自改名。
- 11月6日冻结模型、Prompt、参数、样本、成功判定和理由码。

## 2. 每个人从哪里开始

### CXY：整合与模型链路

分支：`feature/cxy-integration`

先完成 `src/model_client.py` 的 Ollama 调用，再把四种版本接入 `src/pipeline.py`，最后完善 `app.py`。不得绕过 XRS 的 `authorize_tool` 直接读取保护版文件。

首个交付：`model_client.py`、`pipeline.py`、`app.py`、一次正常调用记录。

### XRS：安全机制与指标

分支：`feature/xrs-security`

从 `src/policy_gate.py` 开始，补足路径穿越、相对路径、大小写与符号链接测试；然后完善 `output_guard.py`、`audit_logger.py` 和批量指标脚本。

首个交付：至少12个权限单元测试、篡改日志失败样例、理由码清单。

### YCQ：威胁模型与冻结用例

分支：`feature/ycq-cases`

复核 `tests/test_cases.json` 与10个文本样本一一对应，完善威胁模型、课程知识映射和安全声明。样本必须虚构；正式测试后禁止为改善结果替换攻击文本。

首个交付：10个用例复核表、威胁模型初稿、资料来源表。

### ZL：复现与证据

分支：`feature/zl-evidence`

建立环境检查表、原始运行表和证据索引模板；独立按 README 安装并运行。不得手工修改指标，所有数字必须能追溯到 JSONL 日志。

首个交付：环境检查表、首次复现报告、问题清单。

## 3. 统一交付格式

提交目录：`handoff/成员/日期_任务名/`

每次交付必须写一个 `HANDOFF.md`，格式如下：

```markdown
# 交付名称
- 成员：XRS
- 日期：2026-10-29
- 分支：feature/xrs-security
- Commit：填写完整SHA

## 本次文件
- src/policy_gate.py
- tests/test_policy_gate.py

## 运行命令
pytest -q tests/test_policy_gate.py

## 输入与预期输出
- IPI-01 -> DENY / TOOL_NOT_ALLOWED
- NOR-01 -> ALLOW / CURRENT_UPLOAD_ONLY

## 已知问题
- 暂无；或写明具体问题

## 回退方法
git revert <commit-sha>
```

## 4. 合并规则

1. 每人只在自己的 `feature/...` 分支开发。
2. 提交信息格式：`类型(成员): 内容`，例如 `feat(xrs): add path authorization tests`。
3. 推送后发起 Pull Request，不直接修改 `main`。
4. Pull Request 必须写测试命令和结果。
5. CXY检查接口，XRS检查安全调用顺序；`pytest -q` 全绿后才能合并。
6. 预计晚于节点12小时，必须说明未完成项、现有文件、阻塞原因、所需协助和新交付时间。

