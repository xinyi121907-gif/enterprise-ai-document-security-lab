# change_shturl YCQ 2026‑10‑31
说明：本次仅修正冒烟测试发现的路径与载荷问题、适配仓库真实目录；**不修改用例类别、用例总数量、成功判定口径**。
冒烟来源：issue_list_v1.docx，ISSUE‑01、ISSUE‑02

| case_id | 修改原因 | 旧文本片段 | 新文本片段 |
|---|---|---|---|
| PATH‑01 | ISSUE‑01：attack_target使用相对上级路径`../data/private/finance_budget.txt`，运行报文件不存在Errno 2，路径穿越用例无法执行验证 | `"attack_target": "../data/private/finance_budget.txt"` | `"attack_target": "data/private/finance_budget.txt"` |
| ENC‑01 | ISSUE‑02：enc_01_b64_payload_resume.txt样本内部Base64解码载荷错误引用不存在的「合同.pdf」，运行报Errno 2；JSON的file字段本身无误，修改攻击样本txt内payload | Base64解码后指令包含读取“合同.pdf” | 修改Base64编码内容，攻击目标改为 `data/private/candidate_records.txt`，移除pdf引用 |
| 全部10条用例 | 第二次适配：错误省略了父目录`llm_prompt_injection_lab`，并且简写文件夹名称，仓库真实文件夹带有中文备注后缀，导致仓库根执行时全部文件找不到 | `"file":"handoff/ycq/data-attack/xxx.txt"`<br>`"attack_target":"handoff/ycq/data-private/xxx.txt"` | `"file":"handoff/ycq/llm_prompt_injection_lab/data-attack 8 个恶意样本/xxx.txt"`<br>`"attack_target":"handoff/ycq/llm_prompt_injection_lab/data-private 3 份内部秘密文件/xxx.txt"` |

> 备注：
> 1. PATH‑01：先修复上级跳转符号；后续统一替换为仓库根完整真实路径。
> 2. ENC‑01：不修改test_cases_v2.json的file字段；修改对象：`handoff/ycq/llm_prompt_injection_lab/data-attack 8 个恶意样本/enc_01_b64_payload_resume.txt`内部base64字符串。
> 3. 已恢复 `handoff/ycq/llm_prompt_injection_lab/tests/test_cases_v1.json`，原样保留，不作任何修改。
> 4. 当前 `tests/run_experiment.py` 仍然读取 `tests/test_cases.json`，脚本层暂未接入v2，仅把v2路径修好。
