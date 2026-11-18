# LaminaDB 提交审计报告:跨行守恒规则的可证明性

本报告由 `audit/analyze.py` 仅从 `audit/evidence/` 的留存材料生成,不接触任何活数据库实例;全部结论可由 `report/reconstruction.json` 与材料清单逐项复核。

## 1. 审计对象与规则

- 跨行规则:**关系 `spectra` 全部可见行的 `amplitude` 之和恒等于 210**(genesis 由种子提交 seq 2 确立)。该规则引擎不强制,属外部审计不变量。
- 证据通道:在线变更馈送 `GET /changes`(逐次提交记录)与周期图像 `GET /backup`(保留版本);两者按真实提交序号与可达范围(`history_base` / 图像水位)对齐。
- 场景:源实例提交 1..10 后停服;由 imgB@9 在异目录恢复形成新历史(基点 9),继续提交 10..15。源 seq 10 在基点之后,属被遗弃尾部。

## 2. 谱系对齐与采集事实

| 谱系 | history_base | 头部 | 记录数 | 说明 |
| --- | --- | --- | --- | --- |
| source | 0 | 10 | 10 | 停服前全量 |
| restored | 9 | 15 | 6 | 异目录恢复的新历史 |

- **基点缺口**:恢复实例对 `after=0` 与 `after=8` 的变更请求全部返回 410(探测 2 次),采集器按 `/stats` 的 `history_base=9` 对齐,首条记录序号为 10。
- **重复分页**:采集器以 limit=3 小页轮询,每轮重叠 2 条并模拟一次崩溃回退;源谱系去重 13 条、恢复谱系去重 2 条,全部逐字节一致,无同号异文。
- **同号不同文**:源 seq 10 与恢复 seq 10 序号相同、内容不同(记录 sha 前 12 位分别为 bfee3ac36245 与 cb83813172a1),已按谱系分别归档,规范谱系取恢复线,源 seq 10 标记为被遗弃尾部。

## 3. 材料清单(留存证据)

| 材料 | 字节 | sha256(前 16) | 覆盖范围 | 留存策略 |
| --- | --- | --- | --- | --- |
| `changes-restored.jsonl` | 2262 | 857b505b1474e95f | (9..15] | A(全量), C(尾部) |
| `changes-source.jsonl` | 4340 | b508c397932afce9 | (0..10] | A(全量), C(尾部) |
| `collection-log.json` | 8685 | abe9a42a3d8ecb6e | — | 全部(采集元数据) |
| `images/imgA-seq0002.lmi` | 977 | a9cb622c9eceeb7f | [1..2] | B, C |
| `images/imgB-seq0009.lmi` | 1378 | 3eb711525a2ccb44 | [6..9] | A, B, C |
| `images/imgC-seq0015.lmi` | 1239 | c431ddd186b7e543 | [13..15] | B |

机器可读清单:`audit/evidence/manifest.json`(含每件材料完整 sha256 与策略归属)。

## 4. 独立重建与交叉校验

独立重放器(不依赖引擎代码)从变更记录重建版本链,并与图像保留版本逐点互校:

| 校验 | 结果 | 细节 |
| --- | --- | --- |
| rec-sha: changes-source.jsonl seq 1 记录摘要可独立复算 | ✅ |  |
| rec-sha: changes-source.jsonl seq 2 记录摘要可独立复算 | ✅ |  |
| rec-sha: changes-source.jsonl seq 3 记录摘要可独立复算 | ✅ |  |
| rec-sha: changes-source.jsonl seq 4 记录摘要可独立复算 | ✅ |  |
| rec-sha: changes-source.jsonl seq 5 记录摘要可独立复算 | ✅ |  |
| rec-sha: changes-source.jsonl seq 6 记录摘要可独立复算 | ✅ |  |
| rec-sha: changes-source.jsonl seq 7 记录摘要可独立复算 | ✅ |  |
| rec-sha: changes-source.jsonl seq 8 记录摘要可独立复算 | ✅ |  |
| rec-sha: changes-source.jsonl seq 9 记录摘要可独立复算 | ✅ |  |
| rec-sha: changes-source.jsonl seq 10 记录摘要可独立复算 | ✅ |  |
| rec-sha: changes-restored.jsonl seq 10 记录摘要可独立复算 | ✅ |  |
| rec-sha: changes-restored.jsonl seq 11 记录摘要可独立复算 | ✅ |  |
| rec-sha: changes-restored.jsonl seq 12 记录摘要可独立复算 | ✅ |  |
| rec-sha: changes-restored.jsonl seq 13 记录摘要可独立复算 | ✅ |  |
| rec-sha: changes-restored.jsonl seq 14 记录摘要可独立复算 | ✅ |  |
| rec-sha: changes-restored.jsonl seq 15 记录摘要可独立复算 | ✅ |  |
| img-sha: imgA-seq0002.lmi 信封 sha256 独立复算一致 | ✅ |  |
| img-hdr: imgA-seq0002.lmi 图像头合法(format=1 且 horizon<=sequence) | ✅ | format=1 horizon=0 sequence=2 |
| img-sha: imgB-seq0009.lmi 信封 sha256 独立复算一致 | ✅ |  |
| img-hdr: imgB-seq0009.lmi 图像头合法(format=1 且 horizon<=sequence) | ✅ | format=1 horizon=6 sequence=9 |
| img-sha: imgC-seq0015.lmi 信封 sha256 独立复算一致 | ✅ |  |
| img-hdr: imgC-seq0015.lmi 图像头合法(format=1 且 horizon<=sequence) | ✅ | format=1 horizon=13 sequence=15 |
| src-contig: 源 lineage 记录序号自基点连续无缺口 | ✅ | base=0 head=10 n=10 |
| dst-contig: 恢复 lineage 记录序号自基点连续无缺口 | ✅ | base=9 head=15 n=6 |
| pivot-base: 恢复实例 history_base 与基点图像序号一致 | ✅ | history_base=9 imgB.sequence=9 |
| pivot-first: 恢复 lineage 首条记录序号 == 基点+1 | ✅ |  |
| base-gap-410: 基点之前游标探测全部被 410 拒绝(基点缺口成立) | ✅ | probes=[(0, 410), (8, 410)] |
| abandoned-tail: 源头部存在基点之后的被遗弃尾部 | ✅ | abandoned=[10] |
| lineage-collision: 被遗弃序号在两条 lineage 内容不同(必须按谱系对齐,不能按序号合并) | ✅ | src[10].sha=bfee3ac36245 dst[10].sha=cb83813172a1 |
| dup-identical: 重复分页重取的记录逐字节一致,无同号异文(独立复核采集日志) | ✅ | deliveries=31 unique=16 redelivered=15 collector_counted=15 |
| dup-count: 采集器去重计数与采集日志独立统计一致 | ✅ |  |
| head-monotonic: 各 lineage 观测到的 head 单调不减 | ✅ |  |
| xcheck-imgA: 重放状态与 imgA@2 图像可见状态逐行一致 | ✅ | rows=6 replay_rows=6 |
| xcheck-imgB: 重放状态与 imgB@9 图像可见状态逐行一致 | ✅ | rows=6 replay_rows=6 |
| xcheck-imgC: 重放状态与 imgC@15 图像可见状态逐行一致 | ✅ | rows=6 replay_rows=6 |
| violations-as-designed: 全量证据下发现且仅发现设计的两处瞬时违规 | ✅ | violations=[4, 12] |
| equal-endpoints-trap: imgB@9 与 imgC@15 总量相等,但 (9,13) 内确有违规(端点相等≠中间合规) | ✅ | total@9=210 total@15=210 |

## 5. 规则评估(全量证据)

| 谱系 | 序号 | 总量 | 规则 | 状态指纹(前 12) |
| --- | --- | --- | --- | --- |
| canonical | 1 | 0 | —(规则未生效) | 779552558fec |
| canonical | 2 | 210 | ✅ 成立 | 1a1a0fd6517e |
| canonical | 3 | 210 | ✅ 成立 | 28bfac0b3351 |
| canonical | 4 | 190 | ❌ **违规** | 82d17e753826 |
| canonical | 5 | 210 | ✅ 成立 | 9937858d59dd |
| canonical | 6 | 210 | ✅ 成立 | 9937858d59dd |
| canonical | 7 | 210 | ✅ 成立 | 3e82af42d52d |
| canonical | 8 | 210 | ✅ 成立 | 3e82af42d52d |
| canonical | 9 | 210 | ✅ 成立 | e6ae24fa7f8f |
| canonical | 10 | 210 | ✅ 成立 | e57440de3de7 |
| canonical | 11 | 210 | ✅ 成立 | 9572f56b8ed3 |
| canonical | 12 | 190 | ❌ **违规** | 032df52c89ac |
| canonical | 13 | 210 | ✅ 成立 | 3219fed771b9 |
| canonical | 14 | 210 | ✅ 成立 | 3219fed771b9 |
| canonical | 15 | 210 | ✅ 成立 | 5d47cf8280a9 |
| abandoned-source | 10 | 210 | ✅ 成立 | a1ed4c8ca04f |

发现 2 处违规,均为**短暂出现后消失**的瞬时违规:
- seq 4(源谱系):总量 190 ≠ 210;下一提交即修复,且其后的回收已抹除中间版本,周期图像无法再现该状态。
- seq 12(恢复谱系):总量 190 ≠ 210;下一提交即修复,且其后的回收已抹除中间版本,周期图像无法再现该状态。

**缺口两端相等陷阱(实证)**:imgB@9 总量 = 210,imgC@15 总量 = 210,两端相同;但规范谱系 (9,13) 区间内的 seq 12 实际违规。因此,缺口两端当前值相同**不能**作为中间未违规的证据。

## 6. 限定保存规模下的策略比较

保存预算:**5973 字节**(定为全量留存 7964 字节的 75%)。

| 策略 | 留存内容 | 字节 | 预算内 | 可证明序号 | 发现违规 | 遗漏违规 |
| --- | --- | --- | --- | --- | --- | --- |
| A 全量变更留存 | 图像 imgB;全部记录 | 7964 | ❌ 超预算 | 15/15 | [4, 12] | 无 |
| B 仅周期图像 | 图像 imgA+imgB+imgC;无记录 | 3594 | ✅ | 9/15 | 无 | [4, 12] |
| C 预算内混合(图像+记录尾窗) | 图像 imgA+imgB;源尾部 1 条+恢复尾部 6 条 | 5066 | ✅ | 12/15 | [12] | [4] |

结论:全量变更可发现两处瞬时违规但超预算;仅周期图像最省字节却两处皆遗漏;预算内混合策略发现 1 处(seq 12,位于恢复记录尾窗内),另 1 处(seq 4)落在不可证明区间。

策略 C 由枚举搜索选出(目标:可证明序号最多,其次被遗弃尾部可证明,再次字节最少)。预算内得分最高的三个候选组合:

| 候选 | 图像 | 源尾窗 | 恢复尾窗 | 字节 | 可证明 |
| --- | --- | --- | --- | --- | --- |
| 1 | imgA+imgB | 1 | 6 | 5066 | 12/15+尾部 |
| 2 | imgA+imgB | 2 | 6 | 5518 | 12/15+尾部 |
| 3 | imgA+imgB | 3 | 6 | 5704 | 12/15+尾部 |

## 7. 明确的不确定结论

以下区间在对应策略下**没有任何留存材料可重放提交状态**,规则状态未知,不得因区间两端总量相同而推断成立:

- 策略 A(超预算,仅作对照基准):规范谱系全部 15 个序号均可证明;被遗弃尾部可证明。
- 策略 B:规范谱系序号 [3, 4, 5, 10, 11, 12] 不可证明;被遗弃尾部 seq [10] 不可证明。
- 策略 C:规范谱系序号 [3, 4, 5] 不可证明;被遗弃尾部可证明。

被遗弃尾部(源 seq 10)说明:该提交曾对外发布并被本审计留存,其规则状态为成立,但其效果未进入恢复后的规范历史;它证明的是“当时可观察到的状态”,不构成规范谱系的一部分。

## 8. 边界与限制

- 本审计校验的是**服务端提供证据的内部一致性**(记录连续性、图像摘要、重放与图像互校),未直接读取 `journal.lmw` 磁盘字节;按项目规范,校验和是完整性而非身份认证边界。
- 采集器在源停服前完成末次轮询(采集日志 head=10 与停服 stats 一致),本次样本的在线窗口无遗漏;若实例在两次轮询之间崩溃且日志不可达,该窗口将退化为不确定区间。
- 策略 C 的“记录尾窗”是流式留存语义(只保留最近 W 条);本样本规模小,最优解的恢复尾窗恰好覆盖整条恢复谱系,长运行系统中该窗口只能覆盖近期区间。
- 未实现任何新的审计接口,未改写任何源记录;全部材料为只读采集。

## 9. 复现

```sh
go build -o bin/laminad ./cmd/laminad
python3 -I audit/run_audit.py   # 采集:重建 evidence/
python3 -I audit/analyze.py     # 分析:重建 manifest.json、reconstruction.json 与本报告
```
