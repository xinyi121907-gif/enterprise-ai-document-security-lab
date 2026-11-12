# 11月12日最终候选交付

交付人：CXY。范围：合并验收文件、固定候选包，不增加产品功能。

## 版本与获取方式

最终候选使用 GitHub Release `final-release-v1-20261112` 的 `final_release_v1.zip` 附件。
Release 固定提交号；包内 `RELEASE_MANIFEST.json` 记录源提交及每个文件的 SHA256，Release 同时提供整个 ZIP 的 SHA256。不要用后续变化的 main ZIP 代替此固定候选。

已整合 YCQ PR #50（文档一致性修订）、XRS PR #48（最终复测）、ZL PR #49（视频清单）。整合基准为 `323694fe364b1e2884275915d6c2bb487d36aadd`；随后仅增加本交付记录。

## 包内内容与正式证据入口

- 启动：根目录 README.md、start.bat、start.ps1、requirements.txt、app.py。
- 代码与测试：src/、tests/、config.yaml。
- 样本：data/attack/、data/normal/、data/private/；私有资料均为虚构测试数据。
- 正式120次数据：handoff/zl/2026_11_8/raw_runs_all.csv。
- 对应正式日志：handoff/zl/2026_11_8/raw_runs_all_log_120.jsonl。
- 最终指标及人工抽查：handoff/xrs/20261109_metrics/metrics_final.csv、calculation_check.csv、manual_review_20261109.csv。
- 最终复测：handoff/xrs/20261112_retest/；逐轮明细可按其 README 重建。
- 文档一致性：handoff/ycq/docs_final_consistency.csv 及两份已修订的旧文档。
- 空环境复现：handoff/zl/2026_11_11/reproduction_report_final.docx。
- 演示视频：handoff/zl/2026_11_12/video_manifest.csv，视频本体仍在 Release demo-videos-20261110，未复制进代码包。

根目录 results/ 是运行输出位置，正式结果入口以上述 handoff 文件为准。历史异常批次、mock 和归档244条日志保留追溯用途，不作为正式120条输入。模型权重、Python环境及运行依赖不内置，按根目录 README 安装。

## 验证记录

在整合基准执行全量 pytest：59 passed、3 skipped。Windows跳过1项大小写敏感测试及2项需符号链接权限的测试；未将跳过计为通过。界面9项和端到端拒绝5项包含在通过项内。XRS另有固定Streamlit 1.39.0环境的62项通过记录。

重新运行逐轮校验：120行完整，除data_source标注外与原交付差异0，日志与CSV内容不一致0，哈希链通过，结论PASS_WITH_WARNING。指标负向自测七场景均符合预期。视频四项文件大小和SHA256均与GitHub Release附件元数据一致；本次未重新人工观看视频。

## 保留的限制

- 正式120次的运行提交号、RC1/RC2对应及模型digest证据仍不完整，不能用当前候选提交号替代当时运行版本。
- vulnerable/ENC-01三条运行错误保留，攻击分母仍24；未伪造修复后模型运行。
- prompt_only与protected本批攻击侧同为0，不能据此证明二者的普遍优劣。protected正式运行未触发后续DENY，拒绝能力另由测试验证。
- 本次打包不是新一轮真实模型实验；旧冻结清单保持历史原样，最终包由独立清单固定，不要求旧哈希重新匹配。

## 验收结论

代码、样本、正式日志及结果文件齐全；候选可交付，以上证据限制随包保留。后续如修改内容，应发布新版本，不覆盖本包。
