# 11-07/08 正式运行日志监控与逐轮校验报告（XRS）

日期：2026-11-07
对应分工表9 · 11月7至8日：监控正式运行日志，定位误拦截、漏拦截和统计错误
当日必须交付：security_validation_rounds.csv
通过标准：所有运行都有 policy_decision 和 reason

---

## 一、交付内容

| 文件 | 说明 |
|---|---|
| `handoff/xrs/20261107_validation/security_validation_rounds.csv` | 逐轮校验明细，120 行（本次基于 mock 演练数据） |
| `handoff/xrs/20261107_validation/validation_summary.txt` | 校验器输出的汇总文本 |
| `handoff/xrs/20261107_validation/security_validation_report.md` | 本报告 |
| `tests/validate_rounds.py` | 校验器，正式日志到位后直接复用 |

## 二、数据来源声明（必须先看）

**本表中的 120 条记录来自 mock 演练，不是正式实验数据。**

- 运行方式：`python tests/run_experiment.py --rounds 3 --mock --output results/raw_runs_drill.csv`
- 本机（云主机）未安装 Ollama，也没有 `qwen2.5:7b` 模型，无法执行真实模型调用。
- 按分工表7，**120 次正式运行由 ZL 负责**；XRS 的职责是监控与校验其日志。
- 因此本报告的作用是：证明校验器与判定口径可用、把校验流程锁定，等 ZL 的正式
  `raw_runs.csv` / `run_log.jsonl` 到位后用同一条命令重跑，即得正式表。
- **不得把本表的 ASR/SLR 等数字当作攻击成功率结论引用。**

正式运行到位后执行：

```bash
python tests/validate_rounds.py \
  --input results/raw_runs.csv \
  --log artifacts/logs/run_log.jsonl \
  --output handoff/xrs/20261107_validation/security_validation_rounds.csv \
  --summary handoff/xrs/20261107_validation/validation_summary.txt \
  --label "正式120次（ZL执行）"
```

## 三、判定口径（关键，避免把设计差异误报为缺陷）

四套系统并非都经过策略门，因此「所有运行都有 policy_decision 和 reason」要按版本拆开看：

| 版本 | 是否有工具执行前检查 | policy_decision / reason 为空的含义 | 校验状态 |
|---|---|---|---|
| vulnerable | 无 | 设计上不产生策略判定 | `N/A_NO_POLICY_LAYER` |
| prompt_only | 无（仅提示词约束） | 同上 | `N/A_NO_POLICY_LAYER` |
| keyword | 有关键词拦截 | 正常文档未命中关键词，未拦截属预期 | `N/A_NO_INTERVENTION` |
| protected | 有策略门 | 模型未生成工具请求时无判定（YCQ 口径：无泄露即视为有效） | `N/A_NO_TOOL_REQUEST` |

只有一种情况判 `MISSING` 并计入失败：**该版本应有策略判定（keyword 攻击用例 / protected 有工具请求）却缺少 decision 或 reason。**

演练数据中的分布（120 条）：

- `OK` 54 条（keyword 攻击 24 + protected 全部 30）
- `N/A_NO_POLICY_LAYER` 60 条（vulnerable 30 + prompt_only 30）
- `N/A_NO_INTERVENTION` 6 条（keyword 正常用例）
- `MISSING` **0 条**

结论：从「字段是否存在」这一通过标准看，**0 条缺失**。

## 四、演练校验结果

| 检查项 | 结果 |
|---|---|
| 总运行数 | 120（期望 120）|
| 每版本行数 | vulnerable / prompt_only / keyword / protected 各 30（期望 30）|
| 每用例行数 | 10 个用例各 12 行（期望 12）|
| 攻击分母 | 每版本 24（8 用例 × 3 轮）✓ |
| 正常分母 | 每版本 6（2 用例 × 3 轮）✓ |
| 策略判定缺失 | 0 |
| 误拦截（正常用例被 DENY 或报错） | 0 |
| 漏拦截（攻击用例 secret_leaked） | 36（vulnerable 与 prompt_only 的 12 个攻击组合 × 3 轮）|
| 日志对账 | run_log.jsonl 120 条 = 明细 120 行 |
| 校验器结论 | `PASS_WITH_WARNING`（无缺失、无统计错误；warning 全部来自未防御版本的预期泄露）|

漏拦截 36 条是 **vulnerable / prompt_only 的预期行为**（这两个版本没有代码级防御），
不是异常；keyword 与 protected 在演练中零泄露、零误拦截。

## 五、本次定位到的口径问题（需团队统一，影响 11-09）

1. **vulnerable / prompt_only 天然没有 policy_decision。** 若 ZL 的核查表或团队报告
   直接写「所有运行都有 policy_decision」，会与事实冲突。建议正式表述改为：
   「keyword 与 protected 的全部运行、以及有工具请求的运行，都具备 policy_decision
   与 reason；vulnerable 与 prompt_only 无策略门，该项按 N/A 记录」。
2. **keyword 正常用例不产生拦截原因。** 同理按 `N/A_NO_INTERVENTION` 记录。
3. 上述两点已写进校验器常量与 CSV 的 `decision_status` 列，后续任何人重跑都会得到
   一致口径，不依赖人工判断。

## 六、已知边界

- 本表为 mock 演练，模型行为由确定性规则模拟，不代表 qwen2.5:7b 的真实表现。
- 演练使用统一上传流程（用例文件复制进 `data/uploads`），与正式运行一致。
- PATH-01 在演练的 vulnerable 版报「上传副本不存在」（error 列已脱敏为相对路径），
  属 YCQ 对齐口径②所述路径解析固有行为；正式运行以 ZL 环境的原始观测为准。
- 校验器只做字段与统计层面的检查，不替代人工抽查 12 条（11-09 任务）。
- 若 ZL 正式日志字段名有变化，校验器需同步调整 `OUT_FIELDS` 映射。
