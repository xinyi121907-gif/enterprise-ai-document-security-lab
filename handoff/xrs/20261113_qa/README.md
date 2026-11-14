# 11-13 交付：安全机制与指标问答（XRS_QA.docx）

对应任务表（XRS，11 月 13 日）：参与最终复现，准备安全机制与指标问答。
交付物：`XRS_QA.docx`。通过标准：能解释最小权限、路径规范化、六项指标和哈希审计。

## 文件

| 文件 | 说明 |
|---|---|
| `XRS_QA.docx` | 问答底稿，正文约 5 300 字、5 张表、动态目录 |
| `_build/make_qa_doc.py` | 生成脚本，改内容后重跑即可再生成 |
| `_build/fix_toc_pages.py` | 目录页码校正脚本（域计算页码与渲染不一致时使用） |

## 文档结构

1. 文档说明（用途、代码基准、数据来源）
2. 最小权限：判定顺序与四条理由码、初始读取与模型后续请求走同一函数、拒绝时不读取的证据、三条常见追问
3. 路径规范化：三处 `resolve`、符号链接绕过为什么走不通（更正早期 B-04 结论）、TOCTOU 与大小写归一等残余风险
4. 六项指标：口径表、本次结果表、三个最容易说错的口径（ENC-01 运行错误、UTER 取值依据、耗时 30 次分母）
5. 哈希审计：链式结构、校验方法、120 条校验结果、边界（末尾截断、内容真实性与链完整性是两件事、脱敏副本不可验）
6. 一分钟口径（四段可直接背的结论）
7. 附录：代码位置与证据索引

## 事实基准

- 代码：候选提交 `7185769`（main 上的最终候选）。11-12 复测在 `bc786f3` 执行，`bc786f3`→`7185769` 之间 `src/` 与 `tests/` 无改动，差异仅在 `handoff/`；复测记录仍是 11-12 的记录，不替代今天最终复现的记录
- 指标：`handoff/xrs/20261109_metrics/`，11-12 复算逐字节一致
- 复测与日志：`handoff/xrs/20261112_retest/`
- 端到端拒绝测试：`handoff/xrs/20261111_acceptance/test_end_to_end_tool_deny.py`，11-12 复跑 5 passed

## 编写口径（与 11-10 文档一致，未新增结论）

- 只陈述代码与已入库证据能支撑的内容，未实测的绕过与风险明确标为推定或局限
- vulnerable / prompt_only 不过权限门是设计对照，不按 protected 的标准判错
- prompt_only 与 protected 本批次都未被攻破，如实写明「未体现二者效果差异，不能据此宣称安全性等价」
- 提示词约束的局限按机制风险写，不用 vulnerable 的 21/24 当证据（两者不是同一版本，prompt_only 本批攻击成功为 0）
- protected 每版本共 30 次，其中攻击子集 24 次；「全部 ALLOW」只在攻击子集上使用
- ENC-01 三条保留为运行错误，分子不计入、分母仍为 24
- FBR 按实现定义：正常用例中 `DENY`、`BLOCK_OUTPUT` 或 `error` 的次数 ÷ 正常总数
- 哈希链：单独删掉中间一行会断链（下一条 `previous_hash` 接不上），尾部截断与整链重算后链可能仍通过，因此「校验通过」不等于「未被改动」；仓库内 `log_manifest.csv` 与日志同源，不作独立锚点。可用的外部依据是 GitHub Release `final-release-v1-20261112` 的 ZIP SHA256 与包内 `RELEASE_MANIFEST.json`，定位为**已发布候选包的校验依据**：ZIP 的 SHA256 用于核对拿到的是哪一份发布包，包内清单随包保存，同一组有发布权限的人也可能替换附件，因此不称为独立可信锚点
- `tests/metrics_script.py` 文档字符串与实现（优先 `unauthorized_tool_executed`）不一致，作为已知文字偏差记录，不擅自改动以免触发冻结清单重新冻结

## 生成方式

```bash
# 1 生成正文（正文内容只由这一步决定）
python3 handoff/xrs/20261113_qa/_build/make_qa_doc.py

# 2 刷新目录域（需要 word skill 的 catalogue.py 与 lark-cli；无 lark-cli 时跳过，Word 打开后按 F9 更新）
python3 <word-skill>/scripts/catalogue.py --file handoff/xrs/20261113_qa/XRS_QA.docx

# 3 页码校正（仅当域计算页码与渲染页码不一致时执行；页码取自第 4 步 PDF 的实测结果）
python3 handoff/xrs/20261113_qa/_build/fix_toc_pages.py handoff/xrs/20261113_qa/XRS_QA.docx --pages 1,1,4,5,7,9,11

# 4 渲染核对
soffice --headless --convert-to pdf --outdir <outdir> handoff/xrs/20261113_qa/XRS_QA.docx
```

依赖 `python-docx`。文档内含动态 TOC 域，并用 `updateFields` 设置打开时自动更新；第 3 步的页码顺序对应：文档说明、最小权限、路径规范化、六项指标、哈希审计、一分钟口径、附录。本次交付的页码为 `1,1,4,5,7,9,11`（共 13 页，正文 11 页）。

## 已知问题

- 渲染检查：已把 docx 转成 PDF 逐页查看（13 页，封面 1 + 目录 1 + 正文 11）。核对项：目录 7 条与实测页码逐条一致；5 张表逐行不拆分（`cantSplit`）、表头跨页重复（`tblHeader`）、本次均未跨页；附录单独起页；正文页码从 1 起。生成阶段曾出现目录为空、长路径段落被两端对齐撑成单字一行、表格列宽超出 16 cm 版心、附录未起页四处问题，已分别用 TOC 域刷新、长路径段落改左对齐、固定列宽、附录 `page_break_before` 修正。
- 文中引用的行号（`src/pipeline.py` 第 182 行起、第 349 行附近）以候选提交 `7185769` 的版本为准；若后续改动 `pipeline.py`，行号需同步。
