# Protected v1.0-alpha 集成记录（2026-11-02）

## 本次集成

- `app.py`：protected 模式改为上传 UTF-8 TXT 文件，由程序在 `data/uploads/` 中生成文件名；其他三个实验模式保留测试路径输入。
- `src/pipeline.py`：protected 模式通过 `execute_tool_protected` 调用 XRS 的 `policy_gate`，策略允许后才读取文件。
- 审阅文本经过 `output_guard.scan_output` 后才展示；运行结果通过 `audit_logger.write_log` 记录。
- 界面展示策略决定、拒绝原因、工具执行情况和最终审阅结果。

## 验证结果

- 正常上传 `resume_normal.txt`：`ALLOW`、`CURRENT_UPLOAD_ONLY`、`tool_executed=True`，审阅摘要正常显示。
- 请求 `data/private/customer_list.txt`：`DENY`、`PATH_OUTSIDE_UPLOAD_ROOT`、`tool_executed=False`，拒绝原因写入界面文本。
- 使用 mock 监视文件读取函数：上述拒绝场景 `read_calls=0`。
- `python -m pytest -q`：28 passed，3 skipped。

## 当前边界

- 本版验证的是 Streamlit 上传入口的文件读取授权、输出检查和日志记录；protected 审阅使用离线 `review_without_model`。
- 目前没有把模型提出的工具请求接入 protected 策略门，不能声称已完成该场景的端到端验证。
- `run_document_review` 若被其他代码绕过界面直接调用，调用者仍可自行传入上传目录内的路径；本版的“当前上传文件”约束依赖界面入口。
- 本次未重新验证日志哈希链遭篡改后的结果，不能仅凭写入日志声称该验收项已通过。