# 20261027 · contracts.py 与 policy_gate.py v1.0 验收记录

- **验收人**：XRS（权限白名单、路径检查、哈希审计负责人）
- **验收日期**：2026-10-27
- **验收对象**：
  - `src/contracts.py`（blob SHA `07fe7b6b8308b428bae4123bd7d92b93d3c773c7`）
  - `src/policy_gate.py`（blob SHA `fdadc61afa3d8beea7ff00c976b0661ee978befb`）
- **对照依据**：分工文档「六 正式接口拍板 v1.0」六点一（固定数据结构）、六点二（固定权限门代码）

## 一、验收结论

启动包中 contracts.py 与 policy_gate.py **已完全符合固定接口 v1.0 与固定判定顺序，无需修改代码**。本次仅新增本验收记录，不改动任何源码。

## 二、contracts.py 字段逐项验收（对照六点一）

| 对象 | 契约要求 | 实测 | 结论 |
|---|---|---|---|
| Decision | Literal["ALLOW","DENY","BLOCK_OUTPUT"] | 一致 | 通过 |
| SystemVersion | 文档内联于 RunResult；仓库提取为别名 Literal["vulnerable","prompt_only","keyword","protected"] | 一致（语义等价，增强可读性） | 通过 |
| ToolRequest.case_id | str | 一致 | 通过 |
| ToolRequest.task | Literal["REVIEW_DOCUMENT"] | 一致 | 通过 |
| ToolRequest.tool_name | str | 一致 | 通过 |
| ToolRequest.target_path | str | 一致 | 通过 |
| PolicyResult.decision | Decision | 一致 | 通过 |
| PolicyResult.reason | str（理由码） | 一致 | 通过 |
| PolicyResult.normalized_path | str（规范化路径） | 一致 | 通过 |
| RunResult.case_id | str | 一致 | 通过 |
| RunResult.system_version | SystemVersion | 一致 | 通过 |
| RunResult.final_text | str | 一致 | 通过 |
| RunResult.tool_requested | Optional[str]=None | 一致 | 通过 |
| RunResult.tool_executed | bool=False | 一致 | 通过 |
| RunResult.policy_decision | Optional[Decision]=None | 一致 | 通过 |
| RunResult.policy_reason | Optional[str]=None | 一致 | 通过 |
| RunResult.secret_leaked | bool=False | 一致 | 通过 |
| RunResult.summary_ok | bool=False | 一致 | 通过 |
| RunResult.error | Optional[str]=None | 一致 | 通过 |

说明：分工文档六点一出现 `from pydantic import Field` 但全文未使用，当前实现未导入，无副作用，保持不导入。

## 三、policy_gate.py 判定顺序与理由码验收（对照六点二）

固定判定顺序：**先 resolve 规范化路径 → 任务白名单 → 工具白名单 → 当前文件 → 上传根目录 → 放行**，实测一致：

| 优先级 | 理由码 | 触发条件 | 返回 | 实测 |
|---|---|---|---|---|
| 1 | TASK_NOT_ALLOWED | req.task != "REVIEW_DOCUMENT" | DENY | 通过（pydantic 字面量已锁定，属防御纵深） |
| 2 | TOOL_NOT_ALLOWED | req.tool_name != "read_uploaded_file" | DENY | 通过 |
| 3 | FILE_NOT_CURRENT_UPLOAD | target != 当前上传文件 | DENY | 通过 |
| 4 | PATH_OUTSIDE_UPLOAD_ROOT | UPLOAD_ROOT 不在 target.parents | DENY | 通过 |
| 5 | CURRENT_UPLOAD_ONLY | 全部通过 | ALLOW | 通过 |

UPLOAD_ROOT = PROJECT_ROOT / "data" / "uploads"（resolve），与 config.yaml 的 allowed_upload_root 一致。

## 四、测试结果

运行 `python -m pytest tests/test_policy_gate.py`：

- 收集用例：14 项
- **结果：14 passed in 0.27s**（无失败、无跳过）
- 覆盖维度：
  - 合法放行（当前文件、相对路径、`./`、normalized_path 绝对化）4 项
  - 工具白名单（read_internal_file、未知工具）2 项
  - 非当前文件 / 越权读取 2 项
  - 路径穿越（`sub/../../private`、`../private`）2 项
  - 大小写混淆（Linux 敏感）1 项
  - 符号链接逃逸与解析 2 项
  - 越过上传根（即使 current==target）1 项

## 五、最终结论

1. contracts.py、policy_gate.py 符合固定接口 v1.0，**无需修改**；
2. 判定顺序不可调换，已按契约实现；
3. 测试全部通过，可作为 11-06 冻结的安全模块基线；
4. 待办：tools.py / output_guard.py / audit_logger.py 属后续任务（2/4）验收范围；output_guard 与 audit_logger 的启动包初版于 10-31 完善并验收。