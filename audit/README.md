# LaminaDB 提交审计样本

本目录是一次**只读**提交审计的完整交付:不修改 LaminaDB 源码、不新增审计接口、不改写任何源记录,
仅通过公开 HTTP 接口(`/changes`、`/backup`、`/stats`、事务接口)采集证据并给出可复查结论。

## 审计问题

源实例的在线变更(逐次提交记录)与异目录恢复形成的新历史(基点之后的记录),
能否证明跨行规则 **`spectra` 全部可见行 `amplitude` 之和恒等于 210** 一直成立?
两路证据按真实提交序号与可达范围(`history_base`、图像水位)对齐;
缺口两端总量相同**不**作为中间未违规的证据。

## 目录结构

```
audit/
  README.md                  本文件
  run_audit.py               阶段一:起真实实例、执行确定性工作负载、采集证据
  analyze.py                 阶段二:只读证据,独立重建 + 交叉校验 + 策略比较 + 生成报告
  evidence/                  留存材料(采集产物,analyze.py 的唯一输入)
    changes-source.jsonl     源谱系变更记录(每行含记录 sha256)
    changes-restored.jsonl   恢复谱系变更记录
    images/*.lmi             周期备份图像(imgA@2、imgB@9=恢复基点、imgC@15)
    collection-log.json      采集日志:分页/重复抓取/410 探测/回退/备份/恢复事件
    manifest.json            材料清单(分析产物:逐件 sha256、字节、覆盖范围、策略归属)
  report/
    reconstruction.json      独立关系重建结果(逐序号总量、状态指纹、校验明细)
    audit-report.md          可复查结论(含明确的不确定区间)
```

## 复现

```sh
go build -o bin/laminad ./cmd/laminad
python3 -I audit/run_audit.py   # 采集:重建 evidence/(实例数据目录为临时目录,结束即删)
python3 -I audit/analyze.py     # 分析:重建 manifest.json、reconstruction.json、audit-report.md
```

`run_audit.py` 会清空并重建 `evidence/`;两次运行的记录事务 ID 随机,材料 sha 会不同,
但序号布局、违规位置与结论结构确定。

## 样本场景(确定性)

| 序号 | 谱系 | 内容 | 规则状态 |
| --- | --- | --- | --- |
| 1 | source | 建关系 spectra | — |
| 2 | source | 种子 6 行,总量 210(genesis);imgA@2 | 成立 |
| 3 | source | 原子转账 | 成立 |
| 4 | source | 非原子转账第一步(总量 190) | **违规(瞬时)** |
| 5 | source | 第二步修复 | 成立 |
| 6–7 | source | 建索引;原子转账 | 成立 |
| 8 | source | vacuum horizon=6(抹除 seq 4 中间版本) | 成立 |
| 9 | source | 原子转账;imgB@9(恢复基点) | 成立 |
| 10 | source | 原子转账,随后源停服 → **被遗弃尾部** | 成立(被回滚) |
| 10–11 | restored | 新历史原子转账(与源 seq 10 同号不同文) | 成立 |
| 12 | restored | 非原子转账第一步(总量 190) | **违规(瞬时)** |
| 13 | restored | 第二步修复 | 成立 |
| 14 | restored | vacuum horizon=13(抹除 seq 12 中间版本) | 成立 |
| 15 | restored | 原子转账;imgC@15 | 成立 |

## 结论速览

- 全量证据下规则在 seq 4 与 seq 12 两处瞬时违规,其余可证明序号全部成立;详见
  `report/audit-report.md` 第 5 节。
- 周期图像策略(B)两处违规都无法发现:违规版本被后续 vacuum 抹除,且 imgB/imgC 两端总量相同——
  端点相等不能推断中间合规(报告第 5 节实证)。
- 保存预算 = 全量留存 75% 时,最优混合策略(C)可证明 12/15 序号、发现 1 处违规;
  全量留存(A)可全覆盖但超预算。不确定区间逐策略列于报告第 7 节。
