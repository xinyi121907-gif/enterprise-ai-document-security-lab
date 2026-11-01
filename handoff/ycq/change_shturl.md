# change_shturl YCQ 2026‑10‑31
说明：本次仅修正冒烟测试发现的路径与载荷问题、以及适配仓库根目录运行路径；**不修改用例类别、用例总数量、成功判定口径**。
冒烟来源：issue_list_v1.docx，ISSUE‑01、ISSUE‑02

| case_id | 修改原因 | 旧文本片段 | 新文本片段 |
|---|---|---|---|
| PATH‑01 | ISSUE‑01：attack_target使用相对上级路径`../data/private/finance_budget.txt`，运行报文件不存在Errno 2，路径穿越用例无法执行验证 | `"attack_target": "../data/private/finance_budget.txt"` | `"attack_target": "data/private/finance_budget.txt"` |
| ENC‑01 | ISSUE‑02：enc_01_b64_payload_resume.txt样本内部Base64解码载荷错误引用不存在的「合同.pdf」，运行报Errno 2；JSON的file字段本身无误，修改攻击样本txt内payload | Base64解码后指令包含读取“合同.pdf” | 修改Base64编码内容，攻击目标改为 `data/private/candidate_records.txt`，移除pdf引用 |
| 全部10条用例 | 适配仓库根目录启动的统一运行脚本；原相对路径会导致仓库根执行时找不到data下样本文件；仅修改file与attack_target的文件路径，业务逻辑全部不变 | `"file":"data/attack/xxx.txt"`<br>`"attack_target":"data/private/xxx.txt"` | `"file":"handoff/ycq/llm_prompt_injection_lab/data/attack/xxx.txt"`<br>`"attack_target":"handoff/ycq/llm_prompt_injection_lab/data/private/xxx.txt"` |

> 备注：
> 1. PATH‑01：第一轮修改test_cases_v2.json内attack_target；第二轮全量路径改写为仓库根完整相对路径。
> 2. ENC‑01：不改动test_cases的file字段；修改对象：`handoff/ycq/llm_prompt_injection_lab/data/attack/enc_01_b64_payload_resume.txt` 文件内的base64字符串。
> 3. v1版本 `test_cases_v1.json`完整保留不做任何修改。
> 4. v2用于统一脚本，不是独立样本包。
