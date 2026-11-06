# CXY 11月6日冻结记录

本次冻结基于已合并的修复版本 `052d8da15da3086b0d50c4f84249ec3da079a033`。本记录替代此前基于0ca8d07的整合冻结说明，实际执行日期2026年11月6日。仅完成CXY当天任务，不代替XRS、YCQ、ZL成员确认，不执行正式120次实验。

## 固定版本与参数

- 模型：qwen2.5:7b；本机Ollama完整摘要：`845dbda0ea48ed749caafd9e6037047aa19acfcfd82e704d7ca97d631a0b697e`。
- temperature=0；request_timeout_seconds=60；配置完整快照见freeze_manifest.json。
- 四版本：vulnerable、prompt_only、keyword、protected。
- 真实行为：每次审阅调用模型一次，只处理第一个工具请求。配置max_tool_rounds=3目前未被执行循环读取，不能宣称已执行三轮；本次如实记录，不扩展功能。
- prompt、工具定义及10个用例的实际用户消息完整保存为prompt_snapshot.json。工具返回文本直接拼接，不进行第二次模型总结。
- 用例入口tests/test_cases.json，与YCQ最终JSON一致；8攻击、2正常，样本13份。正式运行计划3轮，未执行。
- 摘要成功按expected_normal_points逐项文本包含、无错误且无拒绝/泄露判断，不是语义人工评分。

## 文件哈希

完整清单：`handoff/cxy/20261106_freeze/freeze_manifest.json`，覆盖运行代码、测试器、指标、测试文件、配置、依赖、最终用例和13个样本。代码按Git LF字节计算，样本按原始字节计算。校验脚本不修改文件。

校验命令：`python handoff/cxy/20261106_freeze/verify_freeze.py`。在运行机器校验模型摘要：`python handoff/cxy/20261106_freeze/verify_freeze.py --check-model`。

## 本次验证

pytest：35 passed、3 skipped、0 failed。跳过项为Windows大小写测试1项和符号链接权限测试2项。13份样本哈希和大小均匹配；本机模型存在并记录完整摘要。没有运行真实模型实验，不把这些测试作为攻击成功率证据。

## 冻结后约束

不再自行改变模型、prompt、用例、评分口径或参数。后续只处理崩溃、日志缺失和明确错误，记录原因、受影响文件和重新验证结果，形成新的基准，不覆盖历史证据。

XRS原security_freeze_hash.txt以及YCQ旧checklist仍引用之前的版本，不是本次基准。本次CXY清单为当前整合基准；其他成员须在各自冻结任务中对齐，不伪造已确认状态。
