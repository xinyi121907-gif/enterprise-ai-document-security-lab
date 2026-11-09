# CXY 11月9日运行验收

交付：一键启动、四版本统一上传界面和最终状态/错误提示，及 final_runtime_checklist.csv。

- NOR-01、IPI-01、PATH-01 × 四版本 × 每项连续三次，共36次真实 Ollama 调用，36次均无运行错误。
- CSV与 runtime_log.jsonl 按 record_hash 对应；runtime_environment.json 保存运行基线与模型完整 digest。
- 这36次是 pipeline 连续运行验收，界面交互另由 Streamlit AppTest 模拟验证；不宣称人工点击了36次。
- 自动测试：54 passed，3 skipped；跳过项为原有可选测试。状态测试使用模拟结果，覆盖四版本上传、拒绝、输出阻断、运行错误、泄露提示和缺少上传。
- 本次仅调整界面与启动方式，不改 pipeline、安全策略、冻结用例、指标公式，不覆盖历史冻结清单和正式120次数据。无崩溃不等于攻击未成功。

启动：仓库根目录双击 start.bat；依赖与服务检查可执行 powershell -File start.ps1 -CheckOnly。需要预先安装 Python 3.11、Ollama 和 qwen2.5:7b。

复现连续运行：在仓库根目录执行 python handoff/cxy/20261109_runtime/run_acceptance.py。脚本会拒绝覆盖已有日志；如需复验，请先在独立副本中将输出目录改为新的目录。运行基线 source_base 代表 pipeline 代码基线，不代表新增界面文件已包含在该提交。

补充验证：start.ps1 -CheckOnly 通过（指定已有测试虚拟环境）；Streamlit 实际启动后健康接口返回 ok；36条日志哈希链及CSV逐条对应均通过。首次新建虚拟环境路径未在本次重装验证。
