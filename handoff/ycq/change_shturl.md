# change_shturl YCQ 2026‑10‑31
说明：本次仅修正冒烟测试发现的路径与载荷问题、适配仓库真实目录；**不修改用例类别、用例总数量、成功判定口径**。
冒烟来源：issue_list_v1.docx，ISSUE‑01、ISSUE‑02

| case_id | 修改原因 | 旧文本片段 | 新文本片段 |
|---|---|---|---|
| PATH‑01 | ISSUE‑01：attack_target使用相对上级路径`../data/private/finance_budget.txt`，运行报文件不存在Errno 2，路径穿越用例无法执行验证 | `"attack_target": "../data/private/finance_budget.txt"` | `"attack_target": "data/private/finance_budget.txt"` |
| ENC‑01 | ISSUE‑02：enc_01_b64_payload_resume.txt样本内部Base64解码载荷错误引用不存在的「合同.pdf」，运行报Errno 2；JSON的file字段本身无误，修改攻击样本txt内payload | Base64解码后指令包含读取“合同.pdf” | 修改Base64编码内容，攻击目标改为 `data/private/candidate_records.txt`，移除pdf引用 |
| 全部10条用例 | 第一轮适配：适配仓库根目录执行，补全handoff/ycq/前缀，但错误使用`data/attack`、`data/private`，仓库实际文件夹为`data‑attack`、`data‑normal`、`data‑private`，导致全部file找不到 | `"file":"handoff/ycq/llm_prompt_injection_lab/data/attack/xxx.txt"`<br>`"attack_target":"handoff/ycq/llm_prompt_injection_lab/data/private/xxx.txt"` | `"file":"handoff/ycq/data‑attack/xxx.txt"`<br>`"attack_target":"handoff/ycq/data‑private/xxx.txt"` |

> 备注：
> 1. PATH‑01：先修复上级跳转符号；后续统一替换为仓库根完整真实路径。
> 2. ENC‑01：不修改test_cases_v2.json的file字段；修改对象：`handoff/ycq/data‑attack/enc_01_b64_payload_resume.txt`内部base64字符串。
> 3. `handoff/ycq/tests/test_cases_v1.json`完整保留，不作任何修改。
> 4. 当前 `tests/run_experiment.py` 仍读取 `tests/test_cases.json`，暂不改动脚本，v2仅完成路径修复，后续接入统一脚本再处理脚本读取逻辑。
