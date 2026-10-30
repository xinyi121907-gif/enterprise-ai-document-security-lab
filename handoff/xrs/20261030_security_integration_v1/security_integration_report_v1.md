# 任务5 · 联调检查报告 v1 — 权限判断先于文件读取

- **负责人**：XRS
- **日期**：2026-10-30（任务计划日 11-02，提前启动联调准备）
- **检查基准**：`main@d1e02863`（PR #10 已合并，task4 output_guard / audit_logger / test 全部进 main）
- **通过标准（分工文档 525 行）**：deny 用例中 `tool_executed` 始终为 `false`

---

## 1. 当前整合状态（联调前的客观盘点）

| 模块 | main 上的状态 | 说明 |
|---|---|---|
| `src/pipeline.py`（vulnerable 分支） | ✅ 已接入 | `_run_vulnerable` 走 Ollama 工具调用 → `execute_tool_vulnerable`，恶意文件可越权读取（攻击演示路径可用） |
| `src/pipeline.py`（protected 分支） | ⚠️ 仍是离线回退 | `review_without_model()`，**尚未调用 `authorize_tool` / `execute_tool_protected`**，需 CXY 在整合 protected v1.0-alpha 时接入 |
| `src/policy_gate.py` | ✅ 已冻结（task2） | 5 个理由码、判定顺序固定，14 项单测在 main |
| `src/output_guard.py` / `src/audit_logger.py` | ✅ 已冻结（task4） | 合并版测试随 PR #10 进 main |

**结论**：XRS 侧的防护组件已全部冻结并进 main；`deny 在读取前`的机制在**工具层已完整验证**（见第 2 节），最终端到端联调需等 CXY 将 policy_gate 接入 pipeline 的 protected 分支。

## 2. 权限判断先于读取 — 工具层验证（本次新增 6 项集成测试）

新增 `tests/test_integration_protected.py`（模拟 CXY 接入方式：`authorize_tool` → 非 ALLOW 直接返回，不触盘）：

```
authorize_tool(req, current_upload)
        │
        ├─ DENY ──→ 返回 PolicyResult(decision="DENY", reason=...)   ← 不读取文件
        │
        └─ ALLOW ──→ _read_text(path)                                ← 仅此分支触盘
```

| 测试用例 | 构造 | 结果 |
|---|---|---|
| IPI-01 恶意文件请求 `read_internal_file` | tool 不在白名单 | DENY / `TOOL_NOT_ALLOWED` / 磁盘零读取 |
| PATH-01 请求 private 文件 | target ≠ 当前上传 | DENY / `FILE_NOT_CURRENT_UPLOAD` / 磁盘零读取 |
| IPI-02 current=private 文件 | 越过 UPLOAD_ROOT | DENY / `PATH_OUTSIDE_UPLOAD_ROOT` / 磁盘零读取 |
| 任务白名单 | `task="CHAT"` 构造请求 | **pydantic Literal 直接拒绝构造**（ValidationError）——任务白名单在数据模型层锁定，攻击者构造不出非法任务 |
| NOR-01 正常当前文件 | ALLOW | 读取成功，`tool_executed=True`，spy 确认仅读取当前上传文件 |
| 5 类 deny 汇总 | 上述全部 | **`tool_executed` 恒为 `False`，`_read_text` 零调用** |

实现细节：用 spy 包裹 `src.tools._read_text`，断言 deny 分支全程未被调用，从**执行轨迹**上证明"权限判断发生在读取动作之前"，而非只看返回字段。

## 3. 测试结果

```
$ python -m pytest -q
......................................                    [100%]
30 passed in 0.31s
FAILED: 0   ERROR: 0
```

组成：`test_policy_gate.py` 14 + `test_output_guard.py` 4 + `test_audit_logger.py` 6 + `test_integration_protected.py` 6。

## 4. 拒绝理由在结果中保留

`execute_tool_protected` 的返回结构为 `{"executed": False, "policy": PolicyResult(decision, reason, normalized_path), "content": None}`：
- `reason` 携带理由码（`TOOL_NOT_ALLOWED` / `FILE_NOT_CURRENT_UPLOAD` / `PATH_OUTSIDE_UPLOAD_ROOT` 等），可直接显示在界面；
- `normalized_path` 为规范化后的真实目标路径，便于审计日志记录。

## 5. 结论与待办

1. **通过标准的达成情况**：deny 用例 `tool_executed` 恒为 `false` —— 已在工具层（`execute_tool_protected`）验证通过 ✅
2. **端到端联调**：待 CXY 把 `authorize_tool` 接入 `pipeline.py` 的 protected 分支（替换 `review_without_model` 回退）后，用 `run_document_review` 做端到端复验（含 UI 拒绝理由展示），计划在 11-02 联调日完成
3. **不夸大声明**：本报告只验证本地隔离环境下的虚构数据，不涉及任何真实系统

---

### 交付物清单（本批次）
- `tests/test_integration_protected.py`：6 项集成验证
- `handoff/xrs/20261030_security_integration_v1/security_integration_report_v1.md`：本报告
