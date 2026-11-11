# 11-10 交付：四版本消融结果与防御实现说明（v1.2）

对应任务表（XRS，11 月 10 日）：撰写四版本消融结果、防御实现、局限和绕过风险说明 → `defense_implementation.docx`。
通过标准：明确 Prompt 软约束、关键词规则、代码硬防御和输出最后防线。

## 目录约定

本目录只应保留三个条目：`defense_implementation.docx`（最终交付）、`README.md`（本索引）、`_build/make_doc.py`（生成脚本）。
带 `(1)`、`(2)` 等浏览器重命名后缀的同名文件属于重复件，不应保留。

## 文件与校验值

| 文件 | 说明 |
|---|---|
| `defense_implementation.docx` | 正式交付文档 v1.2，7 000 字左右，7 节 + 2 个附录，含 6 张表 |
| `_build/make_doc.py` | 生成脚本，`python3 make_doc.py <输出路径>` 可重建文档 |

`defense_implementation.docx` SHA-256：`85f5b151302b4fe14a361b7bba05e47fbf073f451f17d027798c56ecc31b3fbc`（56 112 B）。
用 `git hash-object handoff/xrs/20261110_defense/defense_implementation.docx` 核对时，应得到 `05f87b7b82bf17607bf95eb61056ad296feda49a`。

## 修订记录

### 第一轮（v1.1，六处）

| 序号 | 复核意见 | 修正内容 |
|---|---|---|
| 1 | “唯一变量原则”不准确 | 2.1 节改为“控制点差异与归因边界”；表 1 扩为六列，分列系统提示词、初始读取流程、进入模型前检查、输出检查；正文明确不是严格单变量消融 |
| 2 | 泄露过程描述错误 | 2.3、3.4、6.1 节改为“程序把工具返回内容拼接到最终文本”（`[实验工具返回：<工具名>]` + 正文），模型只负责发出请求；据此解释 UTER 与 SLR 同为 21/24 |
| 3 | ENC-01 原因仍为推断 | 删去“模型未解码”“照抄模板”，只保留日志可证的两项 |
| 4 | 符号链接风险分析漏一道检查 | 6.2 节改判为已被现有代码阻断（`resolve` 后仍要过 `UPLOAD_ROOT not in target.parents`）；表 4 换成 B-04“授权前替换上传根内目标文件内容” |
| 5 | 审计链说明需更正 | 3.5 节更正：场景 G 删的是字段不是日志行；补末尾截断与整体重算两处盲区；表 4 新增 B-08 |
| 6 | 复现命令路径不完整 | 第 7 节三条命令改用 `handoff/zl/2026_11_8/` 等实际路径 |

### 第二轮（v1.2，四处）

| 序号 | 复核意见 | 修正内容 |
|---|---|---|
| 7 | ENC-01 仍有一句错误 | 2.4 节拆成两段：`tool_trace.target_path` 记录的是占位值且磁盘上不存在，`error` 字段显示的是上层拼接的主文档路径；判断模型请求了什么路径只能看 `tool_trace.target_path`。附录 A 同步补充这一字段差异 |
| 8 | 表 1 读取流程不准 | keyword 行改为“先按无检查路径读取正文，再做关键词扫描；命中则不进模型直接返回，未命中继续走工具路径”；3.2 节首段同步说明它拦的是“把内容交给模型”，不是读取动作 |
| 9 | “未命中完全等同 prompt_only”有误 | keyword 行删去该表述，改为“在 prompt_only 基础上增加文本规则与输出检查；工具执行前仍无代码检查”；第 3 章开头与 3.2 节弱点一段同步修正 |
| 10 | 审计锚点不清 | 3.5、6.2、6.3 节统一改为“批次总条数与末条 `record_hash`”，并写明现场比对条数与末条哈希可发现末尾截断；不再使用“链头哈希” |

两轮修订均未重跑实验，指标数值未变。

## 文档结构

1. 文档目的与范围（目的、数据来源与口径、修订说明、不在本文范围）
2. 四版本设计与消融结果（控制点差异与归因边界、六项指标、结果怎么读、运行错误与分母口径）
3. 防御实现（Prompt 软约束、关键词规则、代码权限门、输出最后防线、审计链、四层作用边界）
4. 权限门调用位置与证据（调用链、日志证据、本次正式批次的实际触发情况）
5. 局限（五条，逐条带证据）
6. 绕过风险（已实测失效、可推定但未实测的路径、缓解建议）
7. 复现与自检
附录 A 理由码与关键字段
附录 B 数据与文件索引

## 关键数据（未变）

| 版本 | ASR | UTER | SLR | NTR | FBR | 平均耗时 |
|---|---|---|---|---|---|---|
| vulnerable | 21/24 = 87.5% | 21/24 = 87.5% | 21/24 = 87.5% | 6/6 = 100% | 0/6 = 0% | 1 459 ms |
| prompt_only | 0/24 = 0% | 0/24 = 0% | 0/24 = 0% | 6/6 = 100% | 0/6 = 0% | 2 489 ms |
| keyword | 0/24 = 0% | 0/24 = 0% | 0/24 = 0% | 6/6 = 100% | 0/6 = 0% | 288 ms |
| protected | 0/24 = 0% | 0/24 = 0% | 0/24 = 0% | 6/6 = 100% | 0/6 = 0% | 2 319 ms |
| 全批合计 | 21/96 = 21.9% | 21/96 = 21.9% | 21/96 = 21.9% | 24/24 = 100% | 0/24 = 0% | 1 639 ms |

数据来源：`handoff/xrs/20261109_metrics/metrics_final.csv`，由 `calc_metrics_from_log.py` 从 120 条 JSONL 日志重算。

## 需要在汇报中说清的边界

1. **不是严格单变量消融**：四版本在系统提示词、进入模型前的检查、初始读取流程上均不同，指标差异只能归因到“机制组合”。
2. **泄露由程序拼接产生**：工具执行成功后由 `pipeline` 把返回内容追加进 `final_text`，与模型是否愿意复述无关。
3. **protected 的代码权限门在正式 120 次中未触发 DENY**：`policy_decision` 全部是初始 `read_uploaded_file` 的 `ALLOW`（`CURRENT_UPLOAD_ONLY`）。
4. **prompt_only 与 protected 攻击侧同为 0/24，差异未体现**：不能宣称二者等价，也不能宣称提示词防御已验证有效。
5. **审计链的两处盲区**：末尾截断与整体重算都无法由哈希链自身发现，需配合 120 组合完整性检查与独立可信保存的“批次总条数 + 末条 `record_hash`”。
6. **字段分工**：`tool_trace.target_path` 是模型请求的路径，`error` 是上层拼接的主文档路径，两者不能混读。

## 复现与重建

```bash
# 重建文档（需 python-docx）
python3 handoff/xrs/20261110_defense/_build/make_doc.py handoff/xrs/20261110_defense/defense_implementation.docx

# 1) 指标重算
python3 handoff/xrs/20261109_metrics/calc_metrics_from_log.py \
  --log handoff/zl/2026_11_8/raw_runs_all_log_120.jsonl \
  --csv handoff/zl/2026_11_8/raw_runs_all.csv \
  --cases tests/test_cases.json --rounds 3 \
  --out-metrics handoff/xrs/20261109_metrics/metrics_final.csv \
  --out-check handoff/xrs/20261109_metrics/calculation_check.csv \
  --manual-verdicts handoff/xrs/20261109_metrics/manual_review_20261109.csv

# 2) 逐轮校验
python3 tests/validate_rounds.py \
  --input handoff/zl/2026_11_8/raw_runs_all.csv \
  --log handoff/zl/2026_11_8/raw_runs_all_log_120.jsonl \
  --cases tests/test_cases.json --rounds 3 \
  --output handoff/xrs/20261108_rounds123/security_validation_rounds.csv \
  --summary handoff/xrs/20261108_rounds123/validation_summary.txt

# 3) 七场景负向自测
python3 handoff/xrs/20261109_metrics/negative_selftest.py \
  --log handoff/zl/2026_11_8/raw_runs_all_log_120.jsonl \
  --csv handoff/zl/2026_11_8/raw_runs_all.csv \
  --cases tests/test_cases.json
```

## 已知问题

- 本机无 git push 凭据，`.docx` 二进制无法通过仓库接口提交，需在 GitHub 网页上传；上传时请确认文件名不带 `(1)` 之类后缀。文档正文中的全部事实与数字可在仓库内已入库的 CSV、JSONL 与脚本中核对。
