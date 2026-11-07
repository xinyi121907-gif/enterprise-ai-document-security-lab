批次：11月7日 第1轮 40 次（4版本 × 10用例 × 1轮）
状态：运行路径异常，待确认是否计入正式数据；已确认不计入正式 120 次
生成时间：2026-11-07
执行命令：python -m tests.run_round1
代码提交号：20627130190cfb0bb9a5ead50870f7c6ed83a60b
分支：feature/zl-evidence

异常原因：
自写脚本 run_round1.py 直接把 test_cases.json 的原始路径
（data/normal、data/attack）传给 pipeline，未调用官方测试器
run_experiment.py 的 prepare_upload（未把样本复制到 data/uploads），
效果等价于 --no-upload。
导致 protected 的 authorize_tool 对全部文档判 PATH_OUTSIDE_UPLOAD_ROOT，
正常用例 NOR-01、NOR-02 也被 DENY（误拒）。

影响：
protected 正常用例 2/2 被误拒，若计入正式数据会使 XRS 的 FBR 失真。

处置：
1. 本批次不删除、不改写，仅作异常存档；
2. 同目录保留自写 run_round1.py，便于说明异常原因；
3. 正式数据以官方入口重跑结果为准：
   python -m tests.run_experiment --rounds 1 --output results/raw_runs_round1.csv
   （未加 --no-upload，未加 --mock，upload对齐=True）
4. 正式交付存放于 handoff/zl/2026_11_7/；
5. 未修改 config.yaml，未扩大允许目录，未修改冻结样本，未做 hotfix。
