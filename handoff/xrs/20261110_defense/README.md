# 11-10 交付：四版本消融结果与防御实现说明（v1.1）

对应任务表（XRS，11 月 10 日）：撰写四版本消融结果、防御实现、局限和绕过风险说明 → `defense_implementation.docx`。
通过标准：明确 Prompt 软约束、关键词规则、代码硬防御和输出最后防线。

## 本目录文件

| 文件 | 说明 |
|---|---|
| `defense_implementation.docx` | 正式交付文档（v1.1），7 000 字左右，7 节 + 2 个附录，含 6 张表 |
| `README.md` | 本索引文件 |

`defense_implementation.docx` SHA-256：`d7b88b37ae352ad8189c02dec685e48a581a35224b914b906b7a75ea9eb166ad`（55 556 B）。

## v1.1 修订（依 11 月 11 日复核意见，未重跑实验、指标不变）

| 序号 | 复核意见 | 修正内容 |
|---|---|---|
| 1 | “唯一变量原则”不准确 | 2.1 节改为“控制点差异与归因边界”；表 1 扩为六列，分别列出系统提示词、初始读取流程、进入模型前检查、输出检查的差异；正文明确“不是严格单变量消融，指标差异不能归因到单一机制”，并举例说明 keyword 的 288 ms 无法拆分 |
| 2 | 泄露过程描述错误 | 2.3、3.4、6.1 节改为“程序把工具返回内容拼接到最终文本”（格式为 `[实验工具返回：<工具名>]` + 正文），并明确模型只负责发出请求、拼接发生在工具执行成功之后，这解释了 UTER 与 SLR 同为 21/24 |
| 3 | ENC-01 原因仍为推断 | 2.4、6.1 节只写日志可证明的两项：目标路径不存在、异常发生在读取环节；删去“模型未解码”“照抄模板”两句，改为“日志不能证明模型是否成功解码载荷”，并说明这 3 条既不计分子也不作防御有效证据 |
| 4 | 符号链接风险分析漏一道检查 | 6.2 节把符号链接从表中移出，改判为已被现有代码阻断：`authorize_tool` 先 `resolve` 再比较，随后 `UPLOAD_ROOT not in target.parents` 会返回 `PATH_OUTSIDE_UPLOAD_ROOT`；表 4 新增 B-04“授权前替换上传根内目标文件内容（同名覆盖）”，Table 3 失效条件同步更正 |
| 5 | 审计链说明需更正 | 3.5 节更正：场景 G 删除的是 `unauthorized_tool_executed` 字段而非日志行；补充哈希链两处盲区——末尾截断（无总条数与末尾锚点）与整体重算；说明需配合 120 组合完整性检查与独立保存的条数/链头哈希；表 4 新增 B-08 记录截断风险 |
| 6 | 复现命令路径不完整 | 第 7 节三条命令的输入/输出路径全部改为 `handoff/zl/2026_11_8/` 与 `handoff/xrs/20261109_metrics/`、`handoff/xrs/20261108_rounds123/` 实际位置 |

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
2. **泄露由程序拼接产生**：`vulnerable` 与 `protected` 在工具执行成功后都由 `pipeline` 把返回内容追加进 `final_text`，与模型是否愿意复述无关。
3. **protected 的代码权限门在正式 120 次中未触发 DENY**：`policy_decision` 全部是初始 `read_uploaded_file` 的 `ALLOW`（`CURRENT_UPLOAD_ONLY`）。
4. **prompt_only 与 protected 攻击侧同为 0/24，差异未体现**：不能宣称二者等价，也不能宣称提示词防御已验证有效。
5. **审计链的两处盲区**：末尾截断与整体重算都无法由哈希链自身发现，需配合 120 组合完整性检查与独立保存的条数、链头哈希。

## 复现命令

```bash
# 1) 指标重算
git hash-object handoff/xrs/20261110_defense/defense_implementation.docx
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

- 本机无 git push 凭据，`.docx` 二进制无法通过仓库接口提交，需在 GitHub 网页上传覆盖本目录文件；文档正文中的全部事实与数字可在仓库内已入库的 CSV、JSONL 与脚本中核对。
