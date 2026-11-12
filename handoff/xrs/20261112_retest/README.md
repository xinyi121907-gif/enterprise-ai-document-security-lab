# 11-12 交付：复测记录与最终日志（security_retest.csv + final_logs）

对应任务表（XRS，11 月 12 日）：复跑所有受修复影响的测试，确认结果仍可追溯。
交付物：`security_retest.csv`、`final_logs`。
通过标准：受影响用例全部重跑，不沿用旧结果。

基准：`origin/main` 提交 `bc786f3`（11-11 验收签字表与 11-11 PR #46 已合入）。

## 判定口径

本次复测只做三件事：重新执行、与旧交付逐字段比对、如实记录差异。所有数字都是从 11 月 8 日 ZL 正式交付的 120 条原始日志重新算出来的，没有复制旧表、没有手工改数。11 月 12 日起禁止新增功能，因此本次没有改动任何 `src/` 代码。

## 复测清单（见 security_retest.csv，9 项）

| 编号 | 对象 | 结论 | 关键比对 |
|---|---|---|---|
| R-01 | `tests/validate_rounds.py`（11-07 三次修复） | PASS_WITH_WARNING | 120 行重跑，除 `data_source` 标注列外 20 列逐字段差异 0 |
| R-02 | `calc_metrics_from_log.py` v3（11-09） | PASS | 两个 CSV 的 md5 与 11-09 交付完全一致 |
| R-03 | `negative_selftest.py`（七场景，含场景 G） | PASS | 七场景全部符合预期 |
| R-04 | `src/audit_logger.py` 日志链 | PASS | 120 条链通过，末条哈希独立复算 MATCH |
| R-05 | `tests/` 非界面测试 | PASS | 53 passed（11-11 为 48，新增 5 项端到端拒绝） |
| R-06 | protected 端到端拒绝测试 | PASS | 11 月 12 日重新执行，5 passed |
| R-07 | 41 项冻结完整性 | PASS_WITH_NOTE | 39 项匹配；2 项不符（11-07 checkpoint 与 11-09 启动器），不回退 |
| R-08 | `tests/run_experiment.py` 检查点 | PASS | 1 passed（该文件只被 11-07 的 8b0a748 改过） |
| R-09 | `tests/test_runtime_ui.py` 界面测试 | PASS | 9 passed；连同非界面测试全量为 62 passed |

## 关键数值（与 11-09 交付逐位一致）

| 版本 | ASR | UTER | SLR | NTR | FBR | 平均耗时 |
|---|---|---|---|---|---|---|
| vulnerable | 21/24 = 87.5% | 21/24 = 87.5% | 21/24 | 6/6 | 0/6 | 1 459 ms |
| prompt_only | 0/24 | 0/24 | 0/24 | 6/6 | 0/6 | 2 489 ms |
| keyword | 0/24 | 0/24 | 0/24 | 6/6 | 0/6 | 288 ms |
| protected | 0/24 | 0/24 | 0/24 | 6/6 | 0/6 | 2 319 ms |
| 合计 | 21/96 = 21.9% | 21/96 = 21.9% | 21/96 | 24/24 | 0/24 | 1 639 ms |

校验复跑结论为 `PASS_WITH_WARNING`，与 11 月 8 日一致：`vulnerable/ENC-01` 三条仍是运行错误（模型请求了不存在的路径），攻击成功分子不计入、分母仍为 24。

## final_logs 说明

`final_logs/` 在仓库内提供两份索引文件，本地另保留一份实体副本：

| 文件 | 内容 |
|---|---|
| `log_manifest.csv` | 日志条数 120、字节 193 223、sha256 `f25f934f…`、首条 `previous_hash=GENESIS`、末条 `record_hash`、链状态、唯一组合数、源路径 |
| `log_chain_verify.txt` | 哈希链校验的完整输出 |
| `run_log_final_120.jsonl` | 正式 120 条日志的实体副本（193 223 B，与源文件逐字节一致；**仅本地保留，未入库**，按下方命令可从源文件重建） |

**仓库内不重复存放该 193 KB 日志本体**：正式日志已经入库在 `handoff/zl/2026_11_8/raw_runs_all_log_120.jsonl`，同一份内容如果在本目录再存一份，会出现「哪一份才是最终」的歧义，也与之前的重复件问题同源。`log_manifest.csv` 用 sha256 与首末哈希把这份日志固定住，需要实体副本时按下面一条命令重建，字节与清单里的 sha256 一致：

```bash
cp handoff/zl/2026_11_8/raw_runs_all_log_120.jsonl handoff/xrs/20261112_retest/final_logs/run_log_final_120.jsonl
sha256sum handoff/xrs/20261112_retest/final_logs/run_log_final_120.jsonl   # 期望 f25f934f1cc6dcbfd73f57783e02e37ab0cfdb8f1a31fad2cfe6ecdf767a48b0
```

## 冻结完整性：两项不一致的说明

`verify_freeze.py` 报 `app.py` 与 `tests/run_experiment.py` 两个文件与 11 月 6 日 rev.3 清单不符。这两处改动来自任务表允许的范围：

- `app.py`：提交 `9debc06`（2026-11-09，CXY 的「一键启动、四版本统一界面状态和最终错误提示」任务）
- `tests/run_experiment.py`：只有 `8b0a748`（2026-11-07，checkpoint 在下次模型调用前写入）。`9debc06` 的改动范围是 `app.py`、`start.bat`、`start.ps1`、`tests/test_runtime_ui.py` 和 `handoff/cxy/20261109_runtime/`，**没有修改运行器**；上一版把它一并归到 11-09 是错的，已按实际提交记录更正

按 CXY 的口径，本次不回退代码、不为匹配旧哈希修改文件，也不改冻结清单，只如实记录；对应的 `tests/test_runner_checkpoint.py` 已纳入 R-05 的全量测试并单独复跑（R-08，1 passed）。

## 复现命令

在基准提交的工作目录内执行：

```bash
# R-01 逐轮校验重跑（或直接运行 rebuild_retest_outputs.py，会同时导出差异表）
python3 tests/validate_rounds.py \
  --input handoff/zl/2026_11_8/raw_runs_all.csv \
  --log handoff/zl/2026_11_8/raw_runs_all_log_120.jsonl \
  --output security_validation_rounds_retest.csv --summary validation_summary_retest.txt \
  --label zl_rounds123_retest_20261112 --cases tests/test_cases.json --rounds 3

# R-02 指标复算（md5 应与 11-09 交付一致）
python3 handoff/xrs/20261109_metrics/calc_metrics_from_log.py \
  --log handoff/zl/2026_11_8/raw_runs_all_log_120.jsonl \
  --csv handoff/zl/2026_11_8/raw_runs_all.csv \
  --cases tests/test_cases.json --rounds 3 \
  --out-metrics metrics_retest.csv --out-check calculation_check_retest.csv \
  --manual-verdicts handoff/xrs/20261109_metrics/manual_review_20261109.csv
md5sum metrics_retest.csv handoff/xrs/20261109_metrics/metrics_final.csv          # 60988b6e…
md5sum calculation_check_retest.csv handoff/xrs/20261109_metrics/calculation_check.csv  # cabc4d95…

# R-03 七场景负向自测
python3 handoff/xrs/20261109_metrics/negative_selftest.py \
  --log handoff/zl/2026_11_8/raw_runs_all_log_120.jsonl \
  --csv handoff/zl/2026_11_8/raw_runs_all.csv --cases tests/test_cases.json

# R-04 日志链校验
python3 - <<'PY'
import json, sys
sys.path.insert(0, '.')
from src.audit_logger import verify_log_chain
recs = [json.loads(l) for l in open('handoff/zl/2026_11_8/raw_runs_all_log_120.jsonl', encoding='utf-8') if l.strip()]
print('records', len(recs), 'chain', 'PASS' if verify_log_chain(recs) else 'FAIL')
PY

# R-05 / R-06 / R-08 / R-09 测试
python3 -m pytest -q --ignore=tests/test_runtime_ui.py
python3 -m pytest -q handoff/xrs/20261111_acceptance/test_end_to_end_tool_deny.py -v
python3 -m pytest -q tests/test_runner_checkpoint.py -v
ln -sf ../app.py tests/app.py && python3 -m pytest -q tests/test_runtime_ui.py -v; rm -f tests/app.py

# R-07 冻结复核
python3 handoff/cxy/20261106_freeze/verify_freeze.py
```

## 本次复测的实体输出

| 文件 | 对应 | 说明 |
|---|---|---|
| `security_validation_rounds_retest.csv` | R-01 | 120 行明细，md5 `5d90a4e4…`；**未重复入库**，用下面一条命令可重建 |
| `validation_summary_retest.txt` | R-01 | 重跑汇总与运行错误清单（已入库） |
| `metrics_retest.csv` | R-02 | 指标复算表，md5 `60988b6e…`（已入库） |
| `calculation_check_retest.csv` | R-02 | 逐条计算核对表，md5 `cabc4d95…`（已入库） |
| `negative_selftest_retest.txt` | R-03 | 七场景负向自测输出（已入库） |
| `e2e_deny_test_retest.txt` | R-06 | 11 月 12 日重新执行的 5 项端到端结果（已入库） |
| `runtime_ui_test_retest.txt` | R-09 | 11 月 12 日执行的 9 项界面测试结果（已入库） |
| `freeze_verify_retest.txt` | R-07 | 冻结复核输出（2 项 mismatch，已入库） |
| `final_logs/log_manifest.csv`、`final_logs/log_chain_verify.txt` | R-04 | 日志清单与链校验（已入库） |

### 逐轮明细表的重建方式

`security_validation_rounds_retest.csv` 与已入库的 `handoff/xrs/20261108_rounds123/security_validation_rounds.csv` 除 `data_source` 标注列外逐字段完全一致：差异条目正好 120 条，全部集中在这一列。同一份 23 182 B 的表再存一份会产生「哪份是最终」的歧义，因此用一条可执行命令把它固定，而不是重复入库：

```bash
python3 handoff/xrs/20261112_retest/_build/rebuild_retest_outputs.py
# 120 行明细，md5 5d90a4e4054ac0297450673f73feb273
# 同时导出 security_validation_rounds_retest_diff.csv：120 条差异，全部为 data_source 列
```

该命令 2026-11-12 已实际运行验证：明细 120 行、md5 与复测时一致、非标注列差异 0。脚本同时把与 11-08 交付的差异逐条导出，供逐行核对。

## 已知问题

- 本机无 ollama 与 `localhost:11434` 服务，无法重跑 120 次模型实验；本次复测全部基于 11 月 8 日已入库的原始日志，属于任务要求的「不重跑模型、只重跑受修复影响的测试」。
- 120 次的运行提交号、RC1／RC2 与模型 digest 仍标「待补」，CXY 已确认该缺失不否定 11-08 交付、不要求重跑。
- 界面测试 `tests/test_runtime_ui.py` 在仓库现状态下无法直接运行：测试内用 `AppTest.from_file("app.py")`，相对路径会解析到 `tests/app.py`。本次在隔离副本中建立临时符号链接 `tests/app.py -> ../app.py` 后运行，链接用完即删、未入库；本次安装 streamlit 1.67.0 用于验证。测试文件的路径写法缺陷已记录，本次不改代码。
- `validation_summary_retest.txt` 中「输出」一行保留了执行机的绝对路径（脚本原样输出，未后处理）；其他证据文件均使用仓内相对路径。
- `security_retest.csv` 中的 `rerun_command` 为相对路径写法，需在仓库根目录执行。
