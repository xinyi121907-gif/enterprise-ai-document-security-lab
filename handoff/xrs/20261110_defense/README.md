# 11-10 交付：四版本消融结果与防御实现说明

对应任务表（XRS，11 月 10 日）：撰写四版本消融结果、防御实现、局限和绕过风险说明 → `defense_implementation.docx`。
通过标准：明确 Prompt 软约束、关键词规则、代码硬防御和输出最后防线。

## 本目录文件

| 文件 | 说明 |
|---|---|
| `defense_implementation.docx` | 正式交付文档，6 600 字左右，8 节 + 2 个附录，含 6 张表 |
| `README.md` | 本索引文件 |

`defense_implementation.docx` SHA-256：`4b80e5b78406a2e98adcc08a98eca8274ec4de42de747a8650bb9c04d6c0a703`（53 231 B）。

## 文档结构

1. 文档目的与范围（目的、数据来源与口径、不在本文范围）
2. 四版本设计与消融结果（唯一变量原则、六项指标、结果怎么读、运行错误与分母口径）
3. 防御实现（Prompt 软约束、关键词规则、代码权限门、输出最后防线、审计链、四层作用边界）
4. 权限门调用位置与证据（调用链、日志证据、本次正式批次的实际触发情况）
5. 局限（五条，逐条带证据）
6. 绕过风险（已实测失效、可推定但未实测的路径、缓解建议）
7. 复现与自检
附录 A 理由码与关键字段
附录 B 数据与文件索引

## 文档中引用的关键数据

| 版本 | ASR | UTER | SLR | NTR | FBR | 平均耗时 |
|---|---|---|---|---|---|---|
| vulnerable | 21/24 = 87.5% | 21/24 = 87.5% | 21/24 = 87.5% | 6/6 = 100% | 0/6 = 0% | 1 459 ms |
| prompt_only | 0/24 = 0% | 0/24 = 0% | 0/24 = 0% | 6/6 = 100% | 0/6 = 0% | 2 489 ms |
| keyword | 0/24 = 0% | 0/24 = 0% | 0/24 = 0% | 6/6 = 100% | 0/6 = 0% | 288 ms |
| protected | 0/24 = 0% | 0/24 = 0% | 0/24 = 0% | 6/6 = 100% | 0/6 = 0% | 2 319 ms |
| 全批合计 | 21/96 = 21.9% | 21/96 = 21.9% | 21/96 = 21.9% | 24/24 = 100% | 0/24 = 0% | 1 639 ms |

数据来源：`handoff/xrs/20261109_metrics/metrics_final.csv`，由 `calc_metrics_from_log.py` 从 120 条 JSONL 日志重算。

## 三个必须在汇报中说清的边界

1. **protected 的代码权限门在正式 120 次中未触发 DENY**：`policy_decision` 全部是初始 `read_uploaded_file` 的 `ALLOW`（`CURRENT_UPLOAD_ONLY`），因为模型在 protected 下未产生后续工具请求。拦截能力由 `tests/test_policy_gate.py` 的 14 个单测与负向自测支撑，不是由正式数据支撑。
2. **prompt_only 与 protected 攻击侧同为 0/24，差异未体现**：不能据此宣称二者安全性等价，也不能宣称提示词防御已验证有效。
3. **审计链只能发现“改了但没重算”的篡改**：负向自测 G 删除字段后重算整条链仍能通过校验，证明它不是防伪造。

## 复现命令

```bash
# 指标重算（校验失败退出码 2，不出表）
python3 handoff/xrs/20261109_metrics/calc_metrics_from_log.py \
  --log handoff/zl/2026_11_8/raw_runs_all_log_120.jsonl \
  --csv handoff/zl/2026_11_8/raw_runs_all.csv \
  --cases tests/test_cases.json --rounds 3 \
  --out-metrics metrics_final.csv --out-check calculation_check.csv \
  --manual-verdicts handoff/xrs/20261109_metrics/manual_review_20261109.csv

# 七场景负向自测
python3 handoff/xrs/20261109_metrics/negative_selftest.py \
  --log handoff/zl/2026_11_8/raw_runs_all_log_120.jsonl \
  --csv handoff/zl/2026_11_8/raw_runs_all.csv --cases tests/test_cases.json
```

## 已知问题

- 本机无 git push 凭据，`.docx` 二进制无法通过仓库接口提交，需在 GitHub 网页上传到本目录；文档正文中的全部事实与数字可在仓库内已入库的 CSV、JSONL 与脚本中核对。
