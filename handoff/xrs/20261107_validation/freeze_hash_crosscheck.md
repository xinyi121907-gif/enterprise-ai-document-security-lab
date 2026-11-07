# 冻结基准交叉核对（XRS 实测 vs main 上的统一冻结记录）

核对时间：2026-11-07
核对人：XRS
核对对象：`handoff/xrs/20261106_security_freeze/security_freeze_hash.txt`（main 上曾被 CXY 改写为「统一冻结记录 2026-11-06」，基准 commit `0ca8d07da31bd4162ba5ec51939df6b43dd304cc`）

## 一、为什么要做这次核对

11-06 冻结清单原由 XRS 按 `052d8da` 计算（rev.2）。同步 main 时发现该文件在 main 上已被
CXY 的整合复核版本整体替换，且其中记录的哈希与 main 上的**实际文件内容**不一致。
11-07/08 的正式运行与 11-09 的指标终算都要以这份清单为基准，若基准与实际代码不符，
后续 120 次实验结果将无法与冻结记录对上。故按 main 实际内容做一次逐文件实测。

**本文件只记录实测事实，不覆盖、不改写 CXY 的冻结记录。**

## 二、实测方法

```
git fetch origin
git show origin/main:<path> | sha256sum
git show origin/main:<path> | wc -c
```

当前 main HEAD：`2b864d3c8e9566fae4ae1a919a18134b12db377c`

## 三、实测结果

| 文件 | main 实测 SHA256 | 实测大小 | 统一冻结记录（0ca8d07） | 结论 |
|---|---|---|---|---|
| src/contracts.py | `fa8e2759…4639e9` | 778 B | 778 B / 哈希相同 | 一致 |
| src/policy_gate.py | `4b1e3c96…ab5de` | 1265 B | 1265 B / 哈希相同 | 一致 |
| src/output_guard.py | `3b54e268…055993` | 396 B | 396 B / 哈希相同 | 一致 |
| config.yaml | `0d21899d…c50de` | 257 B | 257 B / 哈希相同 | 一致 |
| tests/test_cases.json | `da9719ce…38133` | 4479 B | 4479 B / 哈希相同 | 一致 |
| src/audit_logger.py | `c0f480e1…8b79` | **1844 B** | 1812 B / `d83cd9e9…` | **不符** |
| src/model_client.py | `653508ed…489a2` | **8548 B** | 8330 B / `501b6a84…` | **不符** |
| src/pipeline.py | `dd26c18a…a1869` | **11670 B** | 9001 B / `03c8493d…` | **不符** |
| src/tools.py | `09fce4c4…b6d05` | **1369 B** | 870 B / `4e870dcc…` | **不符** |
| tests/run_experiment.py | `3118bab4…d48300` | **10987 B** | 11239 B / `84f77bcd…` | **不符** |
| tests/metrics_script.py | `346009f1…3e14` | **6017 B** | 5389 B / `07f2fb53…` | **不符** |
| app.py | `b837021b…cea54` | **5083 B** | 5066 B / `7d2fcef7…` | **不符** |

汇总：12 项中 **5 项一致、7 项不符**；不符项含 4 个安全模块核心文件
（audit_logger / model_client / pipeline / tools）与 2 个测试器（run_experiment / metrics_script）。

## 四、结论与推测

1. main 当前代码与 `052d8da` 一致（XRS 已实测 11 个文件 11/11 与 rev.2 相同），
   说明 CXY 记录中的哈希对应的是 `0ca8d07` 那条线（她的 rc1 整合版本），该版本内容
   已不在当前 main 上。
2. 因此存在**基准与实际代码不一致**的情况：若团队按 `0ca8d07` 记录作为冻结基准，
   而正式 120 次运行用的是 main 代码，两者的 pipeline / tools / 测试器并不同源，
   指标复算会与冻结清单对不上。
3. 需要 CXY 确认：正式冻结基准取 `0ca8d07`（并使用该版本的代码）还是取当前 main
   （= `052d8da` 代码线，XRS rev.2 已按它算过）。**在确认前，XRS 的 11-07/08 校验与
   11-09 指标计算，一律以 origin/main 实际文件为准，并在报告中注明所用 commit。**

## 五、可复现命令

```bash
git fetch origin
git show origin/main:src/pipeline.py | sha256sum      # dd26c18a…a1869
git show origin/main:src/audit_logger.py | sha256sum  # c0f480e1…8b79
git show origin/main:tests/run_experiment.py | sha256sum  # 3118bab4…d48300
```

完整 11 项（XRS 侧冻结范围：src 7 个 + tests 3 个 + config.yaml）：

```
fa8e2759c89a1d7e7bfc19b254a04a621cce46ef41c149e4e45cbb6a194639e9     778  src/contracts.py
4b1e3c96fbeb635daffc0d7f4ed08339a54e90eebf4fbfa30e544176bdfab5de    1265  src/policy_gate.py
3b54e268f97dabec687b376dce8e6ab847eb49fdf814da77fba7b5d060055993     396  src/output_guard.py
c0f480e1a2ed67f28ce10f458629a1ae43942358a9534b664c102da1d51e8b79    1844  src/audit_logger.py
dd26c18a9a1b0141bbf2bbd083d2cac0d1d3415292ea8b40aabad2b9e96a1869   11670  src/pipeline.py
09fce4c4bb0b0a3709e0962d01dcfc1169d33b916e744240baffa227469b6d05    1369  src/tools.py
653508ed7a98c7b9367fba18da92ee01c2b5c8cd656beb90de293e79991489a2    8548  src/model_client.py
3118bab44323f512e25e4db635dd59c0d883293c724c3d9cb6dea35b9ed48300   10987  tests/run_experiment.py
346009f1c71e5ef681780b86aad80bed1234e1eda3138d92ec69294818d43e14    6017  tests/metrics_script.py
da9719ce69e0adcdffe36a505aa4e662cc21fb5108d02748042cf1669a838133    4479  tests/test_cases.json
0d21899d6d52d9810e990a99ff49d8472334475c3ad674a2335e5d721d6c50de     257  config.yaml
```

## 六、给 CXY 的问题（一句话版）

main 上的统一冻结记录写的是 `0ca8d07`，但 main 实际代码是 `052d8da` 线
（pipeline 11670B 而非 9001B、tools 1369B 而非 870B）。正式冻结与正式 120 次运行
应该统一到哪一个？我这边可以先按 main 实测口径推进，等你确认后再调整。

---

## 七、新版基准确认后的核对结果（2026-11-07 追加）

**CXY 答复：正式冻结代码基准统一采用 `052d8da15da3086b0d50c4f84249ec3da079a033`，
不回退到 `0ca8d07`；以 `docs/freeze_record_20261106.md` 与
`handoff/cxy/20261106_freeze/freeze_manifest.json` 为准。旧核对报告保留并补充新版结果。**

### 7.1 权威依据已核实

| 依据 | 关键字段 | 实测 |
|---|---|---|
| `docs/freeze_record_20261106.md` | 「本次冻结基于已合并的修复版本 `052d8da…`」；「本记录替代此前基于 0ca8d07 的整合冻结说明」 | 与答复一致 |
| `freeze_manifest.json` | `source_commit = 052d8da15da3086b0d50c4f84249ec3da079a033`，`files` 共 **41** 项 | 与答复一致 |
| `prompt_snapshot.json` | `prompt_snapshot_sha256 = e2dabe1c…` | 校验通过 |

> 说明：main 上 `handoff/xrs/20261106_security_freeze/security_freeze_hash.txt` 当时仍残留
> 0ca8d07 文本，属于尚未对齐的历史残留，**不是当前基准**。本报告第三节的 7 项「不符」，
> 比对对象就是这段已被废弃的文本，不是针对 052d8da 基准的结论。

### 7.2 CXY 要求的校验命令实测

```
$ python handoff/cxy/20261106_freeze/verify_freeze.py
PASS: 41 files, prompt snapshot
Source commit: 052d8da15da3086b0d50c4f84249ec3da079a033
退出码 0

$ python handoff/cxy/20261106_freeze/verify_freeze.py --check-model
model verification unavailable: <urlopen error [Errno 111] Connection refused>
退出码 1
```

- 41 项文件 + prompt 快照校验**全部通过**，source commit 与确认基准一致。
- `--check-model` **本机未通过**：本机（云主机）无 Ollama、`localhost:11434` 无服务。
  该项需在装有 qwen2.5:7b 的运行机器（YCQ / ZL 环境）执行，本报告不宣称该项已通过。

### 7.3 XRS 负责的 11 项与 manifest 逐项比对

11 项（src 7 + tests 3 + config.yaml）全部命中 manifest 对应条目，
`sha256` 与字节数**11/11 一致，0 项不符**。完整数值见第五节，或直接以 manifest 为准。

### 7.4 本次动作与边界

1. 已将 `handoff/xrs/20261106_security_freeze/security_freeze_hash.txt` 重写为对齐
   `052d8da` 的 **rev.3**，写明版本沿革（rev.1 作废 / rev.2 被替换 / rev.3 对齐）、
   权威依据、11 项哈希、理由码、指标公式、config 契约与验证结果。
2. **未修改、未回退任何代码**；工作区 `src/`、`tests/`、`config.yaml` 与
   `052d8da`/main 保持原样（由 `verify_freeze.py` 41 项 PASS 佐证）。
3. 旧核对内容（第一至六节）全部保留，作为「曾发现基准不一致」的过程证据。
4. 遗留待办：`--check-model` 需在有 Ollama 的机器复跑，结果应由该机器负责人记录。
