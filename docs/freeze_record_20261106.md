# 11月6日统一冻结

统一冻结记录（2026-11-06，整合复核更新）
代码及样本基准提交：0ca8d07da31bd4162ba5ec51939df6b43dd304cc
本记录替代原先 rc1 + XRS 分支组合；原记录保留为 security_freeze_hash_initial.txt。
正式入口：tests/test_cases.json，与 handoff/ycq/test_cases_final.json 一致。
正式规模：10 用例 × 4 版本 × 3 轮；每版本攻击 24、正常 6。
正常分类兼容 normal / normal_baseline；指标公式未改变。
已接入 CXY rc1 的 app.py、src/pipeline.py 路径及错误处理。
测试：29 passed, 3 skipped；原测试28通过，新分母回归测试1通过。
跳过：Windows大小写测试1项、无符号链接权限2项；不宣称31项全部执行通过。
未进行真实模型120次正式实验，也不代替成员签字确认。
代码和清单固定LF，样本保持原始字节。下表SHA256按完整文件字节计算。

SHA256  size_bytes  path

详细哈希：`handoff/xrs/20261106_security_freeze/security_freeze_hash.txt`。

正式运行前先切换到仓库根目录，再执行 `python tests/run_experiment.py --rounds 3`。正式日志不得混入 mock 冒烟结果。

此次为整合复核记录；未代替 CXY、XRS、YCQ 的个人确认。
