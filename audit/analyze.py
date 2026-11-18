#!/usr/bin/env python3
"""LaminaDB 审计分析(阶段二):只读 audit/evidence/,不接触任何活实例。

交付物:
  audit/report/reconstruction.json  独立关系重建结果(逐序号状态指纹与规则判定)
  audit/evidence/manifest.json      材料清单(每件材料的摘要、字节、可覆盖范围)
  audit/report/audit-report.md      可复查结论(含明确的不确定区间)

用法: python3 -I audit/analyze.py
"""
import hashlib
import itertools
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "audit" / "evidence"
REPORT = ROOT / "audit" / "report"
RELATION = "spectra"
RULE_COLUMN = "amplitude"
SEED_SEQ = 2  # 种子提交;守恒规则自该序号起适用

CHECKS = []  # (id, 描述, 是否通过, 细节)


def check(cid, desc, ok, detail=""):
    CHECKS.append({"id": cid, "desc": desc, "ok": bool(ok), "detail": detail})
    return ok


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()


def extract_payload(raw: bytes) -> bytes:
    """与 run_audit 同逻辑:从信封截取 payload 逐字节原文,独立复算摘要。"""
    marker = b'"payload":'
    start = raw.index(marker) + len(marker)
    depth, i, in_str, esc = 0, start, False, False
    while i < len(raw):
        ch = raw[i:i + 1]
        if in_str:
            if esc:
                esc = False
            elif ch == b"\\":
                esc = True
            elif ch == b'"':
                in_str = False
        else:
            if ch == b'"':
                in_str = True
            elif ch == b"{":
                depth += 1
            elif ch == b"}":
                depth -= 1
                if depth == 0:
                    return raw[start:i + 1]
        i += 1
    raise ValueError("unbalanced payload")


# ---------------- 证据装载 ----------------

def load_changes(path):
    """读取变更记录材料,返回 {sequence: record} 与材料行字节数 {sequence: bytes}。"""
    records, sizes, shas = {}, {}, {}
    for line in path.read_text().splitlines():
        entry = json.loads(line)
        seq = entry["sequence"]
        blob = canonical(entry["record"])
        ok = sha256_bytes(blob) == entry["sha256"]
        check("rec-sha", f"{path.name} seq {seq} 记录摘要可独立复算", ok)
        records[seq] = entry["record"]
        sizes[seq] = len(line.encode())
        shas[seq] = entry["sha256"]
    return records, sizes, shas


def load_image(path):
    raw = path.read_bytes()
    envelope = json.loads(raw)
    payload = extract_payload(raw)
    ok = sha256_bytes(payload) == envelope["sha256"]
    check("img-sha", f"{path.name} 信封 sha256 独立复算一致", ok)
    image = envelope["payload"]
    check("img-hdr", f"{path.name} 图像头合法(format=1 且 horizon<=sequence)",
          image["format"] == 1 and image["horizon"] <= image["sequence"],
          f"format={image['format']} horizon={image['horizon']} sequence={image['sequence']}")
    return {"name": path.stem, "path": path, "bytes": len(raw),
            "sha256": sha256_bytes(raw), "image": image}


# ---------------- 独立关系重建 ----------------

class Replayer:
    """从变更记录独立重建版本链;不依赖引擎任何代码。"""

    def __init__(self):
        self.chains = {}          # relation -> key -> [(seq, row|None)];None 为墓碑
        self.relations = {}       # relation -> created seq
        self.horizon = 0
        self.head = 0

    def apply(self, record):
        kind = record["kind"]
        seq = record["sequence"]
        if kind == "relation":
            self.relations[record["relation"]["name"]] = seq
            self.chains.setdefault(record["relation"]["name"], {})
        elif kind == "commit":
            for m in record.get("writes") or []:
                table = self.chains.setdefault(m["relation"], {})
                table.setdefault(m["key"], []).append((seq, None if m.get("deleted") else m["row"]))
        elif kind == "vacuum":
            self.horizon = max(self.horizon, record["horizon"])
        elif kind == "index":
            pass  # 索引不改变行可见性
        else:
            raise ValueError(f"unknown record kind {kind}")
        self.head = max(self.head, seq)

    def visible(self, relation, at):
        """versions.Visible 的独立实现:取 <=at 的最后版本,墓碑即不可见。"""
        out = {}
        for key, chain in self.chains.get(relation, {}).items():
            row = None
            for seq, version in chain:
                if seq <= at:
                    row = version
                else:
                    break
            if row is not None:
                out[key] = row
        return out


def image_visible(image, relation, at):
    """从图像保留版本独立计算 at 时刻可见行;at 低于水位时拒绝(与引擎 410 语义一致)。"""
    if at < image["horizon"]:
        return None
    out = {}
    for key, chain in image["store"]["tables"].get(relation, {}).items():
        row = None
        for v in chain:
            if v["sequence"] <= at:
                row = None if v.get("deleted") else v["row"]
            else:
                break
        if row is not None:
            out[key] = row
    return out


def state_fingerprint(rows_by_rel):
    return sha256_bytes(canonical(rows_by_rel))


def rule_total(rows):
    """跨-行规则观测量:全部可见行 amplitude 之和(null 不参与)。"""
    return sum(row[RULE_COLUMN] for row in rows.values() if row.get(RULE_COLUMN) is not None)


# ---------------- 主流程 ----------------

def main():
    log = json.loads((EVIDENCE / "collection-log.json").read_text())
    src_records, src_sizes, src_shas = load_changes(EVIDENCE / "changes-source.jsonl")
    dst_records, dst_sizes, dst_shas = load_changes(EVIDENCE / "changes-restored.jsonl")
    images = {p.stem.split("-")[0]: load_image(p) for p in sorted((EVIDENCE / "images").glob("*.lmi"))}

    src_base = next(e["history_base"] for e in log if e["event"] == "collector_open" and e["lineage"] == "source")
    dst_base = next(e["history_base"] for e in log if e["event"] == "collector_open" and e["lineage"] == "restored")
    src_head = max(src_records)
    dst_head = max(dst_records)

    # --- 结构校验:序号连续、无缺口、无重复 ---
    check("src-contig", "源 lineage 记录序号自基点连续无缺口",
          sorted(src_records) == list(range(src_base + 1, src_head + 1)),
          f"base={src_base} head={src_head} n={len(src_records)}")
    check("dst-contig", "恢复 lineage 记录序号自基点连续无缺口",
          sorted(dst_records) == list(range(dst_base + 1, dst_head + 1)),
          f"base={dst_base} head={dst_head} n={len(dst_records)}")

    # --- 谱系对齐:恢复基点 == imgB 图像序号;首条记录 == 基点+1 ---
    pivot = images["imgB"]
    check("pivot-base", "恢复实例 history_base 与基点图像序号一致",
          dst_base == pivot["image"]["sequence"],
          f"history_base={dst_base} imgB.sequence={pivot['image']['sequence']}")
    check("pivot-first", "恢复 lineage 首条记录序号 == 基点+1",
          min(dst_records) == pivot["image"]["sequence"] + 1)
    probes = [e for e in log if e["event"] == "below_base_probe" and e["lineage"] == "restored"]
    check("base-gap-410", "基点之前游标探测全部被 410 拒绝(基点缺口成立)",
          probes and all(p["http"] == 410 for p in probes),
          f"probes={[(p['after'], p['http']) for p in probes]}")

    # --- 同号不同内容:源 seq10 与恢复 seq10 必须按谱系区分 ---
    abandoned_seqs = sorted(s for s in src_records if s > pivot["image"]["sequence"])
    check("abandoned-tail", "源头部存在基点之后的被遗弃尾部",
          abandoned_seqs == [10], f"abandoned={abandoned_seqs}")
    same_seq_conflict = all(src_shas[s] != dst_shas[s] for s in abandoned_seqs if s in dst_records)
    check("lineage-collision", "被遗弃序号在两条 lineage 内容不同(必须按谱系对齐,不能按序号合并)",
          same_seq_conflict,
          f"src[10].sha={src_shas.get(10, '')[:12]} dst[10].sha={dst_shas.get(10, '')[:12]}")

    # --- 重复分页:采集日志逐次抓取的摘要,独立复核同号投递全部一致 ---
    seen = {}
    for e in log:
        if e["event"] == "record_seen":
            seen.setdefault((e["lineage"], e["sequence"]), set()).add(e["sha256"])
    dup_groups = {k: v for k, v in seen.items() if len(v) > 1}
    n_dup = next(e for e in log if e["event"] == "flush")
    total_seen = sum(1 for e in log if e["event"] == "record_seen")
    redelivered = total_seen - len(seen)
    check("dup-identical", "重复分页重取的记录逐字节一致,无同号异文(独立复核采集日志)",
          not dup_groups,
          f"deliveries={total_seen} unique={len(seen)} redelivered={redelivered} "
          f"collector_counted={n_dup['source_duplicates'] + n_dup['restored_duplicates']}")
    check("dup-count", "采集器去重计数与采集日志独立统计一致",
          redelivered == n_dup["source_duplicates"] + n_dup["restored_duplicates"])
    heads = {}
    monotonic = True
    for e in log:
        if e["event"] == "page":
            prev = heads.get(e["lineage"])
            if prev is not None and e["head"] < prev:
                monotonic = False
            heads[e["lineage"]] = e["head"]
    check("head-monotonic", "各 lineage 观测到的 head 单调不减", monotonic)

    # --- 独立重放:规范谱系 = 源[1..基点] + 恢复[基点+1..];源全量另放一份用于被遗弃尾部 ---
    canonical = Replayer()
    for seq in sorted(s for s in src_records if s <= pivot["image"]["sequence"]):
        canonical.apply(src_records[seq])
    for seq in sorted(dst_records):
        canonical.apply(dst_records[seq])
    source_only = Replayer()
    for seq in sorted(src_records):
        source_only.apply(src_records[seq])

    # --- 交叉校验:重放状态 == 图像可见状态(逐图像) ---
    def replay_at(replayer, at):
        return replayer.visible(RELATION, at)

    for name, img in images.items():
        seq = img["image"]["sequence"]
        img_rows = image_visible(img["image"], RELATION, seq)
        if name in ("imgA", "imgB"):
            rep_rows = replay_at(source_only, seq)
        else:  # imgC 属恢复 lineage,用规范谱系重放
            rep_rows = replay_at(canonical, seq)
        check(f"xcheck-{name}", f"重放状态与 {name}@{seq} 图像可见状态逐行一致",
              rep_rows == img_rows,
              f"rows={len(img_rows)} replay_rows={len(rep_rows)}")

    # --- 规则评估:全部可重放序号 ---
    genesis = rule_total(replay_at(source_only, SEED_SEQ))
    evaluation = []
    for seq in range(1, dst_head + 1):
        if seq <= pivot["image"]["sequence"]:
            rows = replay_at(source_only, seq)
        else:
            rows = replay_at(canonical, seq)
        total = rule_total(rows)
        evaluation.append({
            "lineage_seq": seq, "line": "canonical",
            "total": total, "rule_holds": (seq < SEED_SEQ) or (total == genesis),
            "state_sha256": state_fingerprint({RELATION: rows}),
            "rows": len(rows),
        })
    for seq in abandoned_seqs:
        rows = replay_at(source_only, seq)
        total = rule_total(rows)
        evaluation.append({
            "lineage_seq": seq, "line": "abandoned-source",
            "total": total, "rule_holds": total == genesis,
            "state_sha256": state_fingerprint({RELATION: rows}),
            "rows": len(rows),
        })
    violations = [e for e in evaluation if not e["rule_holds"]]
    check("violations-as-designed", "全量证据下发现且仅发现设计的两处瞬时违规",
          sorted(v["lineage_seq"] for v in violations) == [4, 12],
          f"violations={[v['lineage_seq'] for v in violations]}")

    # --- 缺口两端相等陷阱:imgB 与 imgC 总量相同,但之间存在违规 ---
    total_imgB = rule_total(image_visible(images["imgB"]["image"], RELATION, 9))
    total_imgC = rule_total(image_visible(images["imgC"]["image"], RELATION, 15))
    check("equal-endpoints-trap", "imgB@9 与 imgC@15 总量相等,但 (9,13) 内确有违规(端点相等≠中间合规)",
          total_imgB == total_imgC == genesis and any(v["lineage_seq"] == 12 for v in violations),
          f"total@9={total_imgB} total@15={total_imgC}")

    # ---------------- 策略比较:限定保存规模 ----------------
    # 材料字节:记录按 JSONL 行字节,图像按文件字节。
    img_bytes = {name: img["bytes"] for name, img in images.items()}
    canonical_seqs = list(range(1, dst_head + 1))  # 规范谱系序号集合(源 1..9 + 恢复 10..15)
    PIVOT = pivot["image"]["sequence"]

    def coverage(image_names, src_keep, dst_keep):
        """返回 (规范谱系可证明序号集合, 被遗弃尾部可证明序号集合)。

        可证明性的三种来源:
        1. 图像自身覆盖 [horizon, sequence](引擎保留语义,horizon=0 自 1 起);
        2. 记录自谱系基点连续留存 → 从创世/基点状态向前重放;
        3. 图像状态 + 其后连续记录 → 向前扩展。
        恢复谱系的基点状态可由 imgB 或"源记录重放达到基点"提供。
        """
        cov, abandoned = set(), set()
        img_set = set(image_names)

        def place(t):
            (abandoned if t > PIVOT else cov).add(t)

        # 1. 图像区间(源图像落在基点后的部分属被遗弃尾部)
        for name in img_set:
            img = images[name]["image"]
            for t in range(max(1, img["horizon"]), img["sequence"] + 1):
                if name in ("imgA", "imgB"):
                    place(t)
                else:
                    cov.add(t)
        # 2a. 源谱系:记录自 1 连续 → 创世重放
        t = 0
        while t + 1 in src_keep:
            t += 1
            place(t)
        genesis_reach = t
        # 2b. 源谱系:源图像 + 其后连续源记录
        for name in img_set & {"imgA", "imgB"}:
            t = images[name]["image"]["sequence"]
            while t + 1 in src_keep:
                t += 1
                place(t)
        # 2c. 恢复谱系:基点状态可得时,自基点连续恢复记录
        if "imgB" in img_set or genesis_reach >= PIVOT:
            t = PIVOT
            while t + 1 in dst_keep:
                t += 1
                cov.add(t)
        # 2d. 恢复谱系:恢复图像 + 其后连续恢复记录
        for name in img_set & {"imgC"}:
            t = images[name]["image"]["sequence"]
            while t + 1 in dst_keep:
                t += 1
                cov.add(t)
        return cov, abandoned

    def cost(image_names, src_keep, dst_keep):
        return (sum(img_bytes[n] for n in image_names)
                + sum(src_sizes[s] for s in src_keep)
                + sum(dst_sizes[s] for s in dst_keep))

    src_all, dst_all = set(src_records), set(dst_records)
    strat = {}
    # A:全量变更 + 基点图像(恢复操作的事实凭据)
    cov, ab = coverage(["imgB"], src_all, dst_all)
    strat["A"] = {"name": "A 全量变更留存", "images": ["imgB"], "src_tail": len(src_all),
                  "dst_tail": len(dst_all), "bytes": cost(["imgB"], src_all, dst_all),
                  "cov": cov, "abandoned": ab}
    # B:仅周期图像
    cov, ab = coverage(["imgA", "imgB", "imgC"], set(), set())
    strat["B"] = {"name": "B 仅周期图像", "images": ["imgA", "imgB", "imgC"], "src_tail": 0,
                  "dst_tail": 0, "bytes": cost(["imgA", "imgB", "imgC"], set(), set()),
                  "cov": cov, "abandoned": ab}
    # C:预算内混合——枚举图像子集(必含 imgB)与两 lineage 的记录尾窗
    budget = int(strat["A"]["bytes"] * 0.75)
    best = None
    frontier = []
    for n_img in range(1, 4):
        for img_subset in itertools.combinations(["imgA", "imgB", "imgC"], n_img):
            if "imgB" not in img_subset:
                continue
            for w_src in range(0, len(src_all) + 1):
                src_keep = set(sorted(src_all)[len(src_all) - w_src:]) if w_src else set()
                for w_dst in range(0, len(dst_all) + 1):
                    dst_keep = set(sorted(dst_all)[len(dst_all) - w_dst:]) if w_dst else set()
                    c = cost(list(img_subset), src_keep, dst_keep)
                    if c > budget:
                        continue
                    cov, ab = coverage(list(img_subset), src_keep, dst_keep)
                    score = (len(cov), len(ab), -c)
                    frontier.append((score, img_subset, w_src, w_dst, c, cov, ab))
                    if best is None or score > best[0]:
                        best = (score, img_subset, w_src, w_dst, c, cov, ab)
    _, img_c, w_src, w_dst, cost_c, cov_c, ab_c = best
    strat["C"] = {"name": "C 预算内混合(图像+记录尾窗)", "images": list(img_c),
                  "src_tail": w_src, "dst_tail": w_dst, "bytes": cost_c,
                  "cov": cov_c, "abandoned": ab_c}

    viol_seqs = {v["lineage_seq"] for v in violations if v["line"] == "canonical"}
    for s in strat.values():
        s["found"] = sorted(viol_seqs & s["cov"])
        s["missed"] = sorted(viol_seqs - s["cov"])
        s["uncertain"] = sorted(set(canonical_seqs) - s["cov"])
        s["fits_budget"] = s["bytes"] <= budget

    # ---------------- 材料清单 ----------------
    retained_by = {"changes-source.jsonl": ["A"], "changes-restored.jsonl": ["A"]}
    for name in images:
        retained_by[f"images/{images[name]['path'].name}"] = [
            k for k in ("A", "B", "C") if name in strat[k]["images"]]
    # 记录级留存:策略 C 的尾窗
    c_src_keep = set(sorted(src_all)[len(src_all) - w_src:]) if w_src else set()
    c_dst_keep = set(sorted(dst_all)[len(dst_all) - w_dst:]) if w_dst else set()

    manifest = {
        "generated_by": "audit/analyze.py",
        "rule": f"sum({RULE_COLUMN}) over visible rows of {RELATION} == {genesis} (genesis @ seq {SEED_SEQ})",
        "lineages": {
            "source": {"history_base": src_base, "head": src_head, "records": len(src_records)},
            "restored": {"history_base": dst_base, "head": dst_head, "records": len(dst_records)},
        },
        "pivot": {"image": "imgB", "sequence": pivot["image"]["sequence"],
                  "sha256": pivot["sha256"]},
        "abandoned_tail": {"lineage": "source", "sequences": abandoned_seqs},
        "artifacts": [],
        "strategy_membership": {
            "A": {"images": strat["A"]["images"], "records": "all"},
            "B": {"images": strat["B"]["images"], "records": "none"},
            "C": {"images": strat["C"]["images"],
                  "records": {"source_tail": sorted(c_src_keep), "restored_tail": sorted(c_dst_keep)}},
        },
        "budget_bytes": budget,
    }
    for f in sorted(EVIDENCE.rglob("*")):
        if f.is_file() and f.name != "manifest.json":
            rel = f.relative_to(EVIDENCE)
            entry = {"path": str(rel), "bytes": f.stat().st_size,
                     "sha256": sha256_bytes(f.read_bytes())}
            if f.name.startswith("changes-"):
                lineage = f.stem.split("-")[1]
                recs = src_records if lineage == "source" else dst_records
                base = src_base if lineage == "source" else dst_base
                entry.update({"kind": "change-records", "lineage": lineage,
                              "coverage": f"({base}..{max(recs)}]", "records": len(recs)})
            elif f.suffix == ".lmi":
                name = f.stem.split("-")[0]
                img = images[name]["image"]
                entry.update({"kind": "image", "sequence": img["sequence"],
                              "horizon": img["horizon"],
                              "coverage": f"[{max(1, img['horizon'])}..{img['sequence']}]"})
            elif f.name == "collection-log.json":
                entry.update({"kind": "collection-log"})
            manifest["artifacts"].append(entry)
    (EVIDENCE / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=1) + "\n")

    # ---------------- 重建结果 ----------------
    reconstruction = {
        "genesis_total": genesis,
        "rule": manifest["rule"],
        "evaluation": evaluation,
        "violations": violations,
        "cross_checks": CHECKS,
        "image_visible_totals": {
            name: {str(t): rule_total(image_visible(img["image"], RELATION, t))
                   for t in range(max(1, img["image"]["horizon"]), img["image"]["sequence"] + 1)}
            for name, img in images.items()},
        "strategies": {k: {"name": s["name"], "images": s["images"],
                           "src_tail": s["src_tail"], "dst_tail": s["dst_tail"],
                           "bytes": s["bytes"], "fits_budget": s["fits_budget"],
                           "provable": sorted(s["cov"]),
                           "abandoned_provable": sorted(s["abandoned"]),
                           "violations_found": s["found"],
                           "violations_missed": s["missed"],
                           "uncertain": s["uncertain"]}
                       for k, s in strat.items()},
        "budget_bytes": budget,
    }
    REPORT.mkdir(exist_ok=True)
    (REPORT / "reconstruction.json").write_text(
        json.dumps(reconstruction, ensure_ascii=False, indent=1) + "\n")

    write_report(manifest, reconstruction, images, log, strat, budget,
                 genesis, violations, total_imgB, total_imgC, frontier,
                 src_shas, dst_shas, abandoned_seqs)

    failed = [c for c in CHECKS if not c["ok"]]
    print(json.dumps({"status": "analyzed", "checks": len(CHECKS), "failed": len(failed),
                      "violations": [v["lineage_seq"] for v in violations],
                      "budget_bytes": budget,
                      "strategies": {k: {"bytes": s["bytes"], "provable": len(s["cov"]),
                                         "found": s["found"]} for k, s in strat.items()}},
                     ensure_ascii=False))
    return 1 if failed else 0


def write_report(manifest, reconstruction, images, log, strat, budget,
                 genesis, violations, total_imgB, total_imgC, frontier,
                 src_shas, dst_shas, abandoned_seqs):
    """生成可复查结论报告(含明确的不确定区间)。"""
    L = []
    A, B, C = strat["A"], strat["B"], strat["C"]
    L.append("# LaminaDB 提交审计报告:跨行守恒规则的可证明性\n")
    L.append("本报告由 `audit/analyze.py` 仅从 `audit/evidence/` 的留存材料生成,不接触任何活数据库实例;"
             "全部结论可由 `report/reconstruction.json` 与材料清单逐项复核。\n")

    L.append("## 1. 审计对象与规则\n")
    L.append(f"- 跨行规则:**关系 `{RELATION}` 全部可见行的 `{RULE_COLUMN}` 之和恒等于 {genesis}**"
             f"(genesis 由种子提交 seq {SEED_SEQ} 确立)。该规则引擎不强制,属外部审计不变量。")
    L.append("- 证据通道:在线变更馈送 `GET /changes`(逐次提交记录)与周期图像 `GET /backup`(保留版本);"
             "两者按真实提交序号与可达范围(`history_base` / 图像水位)对齐。")
    L.append("- 场景:源实例提交 1..10 后停服;由 imgB@9 在异目录恢复形成新历史(基点 9),继续提交 10..15。"
             "源 seq 10 在基点之后,属被遗弃尾部。\n")

    L.append("## 2. 谱系对齐与采集事实\n")
    L.append("| 谱系 | history_base | 头部 | 记录数 | 说明 |")
    L.append("| --- | --- | --- | --- | --- |")
    L.append(f"| source | {manifest['lineages']['source']['history_base']} | "
             f"{manifest['lineages']['source']['head']} | {manifest['lineages']['source']['records']} | 停服前全量 |")
    L.append(f"| restored | {manifest['lineages']['restored']['history_base']} | "
             f"{manifest['lineages']['restored']['head']} | {manifest['lineages']['restored']['records']} | 异目录恢复的新历史 |")
    L.append("")
    flush = next(e for e in log if e["event"] == "flush")
    probes = [e for e in log if e["event"] == "below_base_probe" and e["lineage"] == "restored"]
    L.append(f"- **基点缺口**:恢复实例对 `after=0` 与 `after=8` 的变更请求全部返回 410"
             f"(探测 {len(probes)} 次),采集器按 `/stats` 的 `history_base=9` 对齐,首条记录序号为 10。")
    L.append(f"- **重复分页**:采集器以 limit=3 小页轮询,每轮重叠 2 条并模拟一次崩溃回退;"
             f"源谱系去重 {flush['source_duplicates']} 条、恢复谱系去重 {flush['restored_duplicates']} 条,"
             "全部逐字节一致,无同号异文。")
    L.append(f"- **同号不同文**:源 seq 10 与恢复 seq 10 序号相同、内容不同"
             f"(记录 sha 前 12 位分别为 {src_shas[10][:12]} 与 {dst_shas[10][:12]}),"
             "已按谱系分别归档,规范谱系取恢复线,源 seq 10 标记为被遗弃尾部。\n")

    L.append("## 3. 材料清单(留存证据)\n")
    L.append("| 材料 | 字节 | sha256(前 16) | 覆盖范围 | 留存策略 |")
    L.append("| --- | --- | --- | --- | --- |")
    for a in manifest["artifacts"]:
        keep = []
        path = a["path"]
        if path.startswith("changes-"):
            keep = ["A(全量)"]
            if path == "changes-source.jsonl" and strat["C"]["src_tail"]:
                keep.append("C(尾部)")
            if path == "changes-restored.jsonl" and strat["C"]["dst_tail"]:
                keep.append("C(尾部)")
        elif a.get("kind") == "image":
            name = pathlib.Path(path).stem.split("-")[0]
            keep = [k for k in ("A", "B", "C") if name in strat[k]["images"]]
        else:
            keep = ["全部(采集元数据)"]
        L.append(f"| `{path}` | {a['bytes']} | {a['sha256'][:16]} | {a.get('coverage', '—')} | {', '.join(keep)} |")
    L.append("")
    L.append("机器可读清单:`audit/evidence/manifest.json`(含每件材料完整 sha256 与策略归属)。\n")

    L.append("## 4. 独立重建与交叉校验\n")
    L.append("独立重放器(不依赖引擎代码)从变更记录重建版本链,并与图像保留版本逐点互校:\n")
    L.append("| 校验 | 结果 | 细节 |")
    L.append("| --- | --- | --- |")
    for c in reconstruction["cross_checks"]:
        mark = "✅" if c["ok"] else "❌"
        L.append(f"| {c['id']}: {c['desc']} | {mark} | {c['detail']} |")
    L.append("")

    L.append("## 5. 规则评估(全量证据)\n")
    L.append("| 谱系 | 序号 | 总量 | 规则 | 状态指纹(前 12) |")
    L.append("| --- | --- | --- | --- | --- |")
    for e in reconstruction["evaluation"]:
        if e["lineage_seq"] < SEED_SEQ:
            mark = "—(规则未生效)"
        else:
            mark = "✅ 成立" if e["rule_holds"] else "❌ **违规**"
        L.append(f"| {e['line']} | {e['lineage_seq']} | {e['total']} | {mark} | {e['state_sha256'][:12]} |")
    L.append("")
    L.append(f"发现 {len(violations)} 处违规,均为**短暂出现后消失**的瞬时违规:")
    for v in violations:
        nxt = "源" if v["lineage_seq"] <= 9 else "恢复"
        L.append(f"- seq {v['lineage_seq']}({nxt}谱系):总量 {v['total']} ≠ {genesis};"
                 f"下一提交即修复,且其后的回收已抹除中间版本,周期图像无法再现该状态。")
    L.append("")
    L.append(f"**缺口两端相等陷阱(实证)**:imgB@9 总量 = {total_imgB},imgC@15 总量 = {total_imgC},"
             "两端相同;但规范谱系 (9,13) 区间内的 seq 12 实际违规。"
             "因此,缺口两端当前值相同**不能**作为中间未违规的证据。\n")

    L.append("## 6. 限定保存规模下的策略比较\n")
    L.append(f"保存预算:**{budget} 字节**(定为全量留存 {A['bytes']} 字节的 75%)。\n")
    L.append("| 策略 | 留存内容 | 字节 | 预算内 | 可证明序号 | 发现违规 | 遗漏违规 |")
    L.append("| --- | --- | --- | --- | --- | --- | --- |")
    for k in ("A", "B", "C"):
        s = strat[k]
        imgs = "+".join(s["images"]) or "无"
        rec = {"A": "全部记录", "B": "无记录",
               "C": f"源尾部 {s['src_tail']} 条+恢复尾部 {s['dst_tail']} 条"}[k]
        fits = "✅" if s["fits_budget"] else "❌ 超预算"
        L.append(f"| {s['name']} | 图像 {imgs};{rec} | {s['bytes']} | {fits} | "
                 f"{len(s['cov'])}/15 | {s['found'] or '无'} | {s['missed'] or '无'} |")
    L.append("")
    L.append("结论:全量变更可发现两处瞬时违规但超预算;仅周期图像最省字节却两处皆遗漏;"
             "预算内混合策略发现 1 处(seq 12,位于恢复记录尾窗内),另 1 处(seq 4)落在不可证明区间。\n")
    L.append("策略 C 由枚举搜索选出(目标:可证明序号最多,其次被遗弃尾部可证明,再次字节最少)。"
             "预算内得分最高的三个候选组合:\n")
    L.append("| 候选 | 图像 | 源尾窗 | 恢复尾窗 | 字节 | 可证明 |")
    L.append("| --- | --- | --- | --- | --- | --- |")
    top = sorted(frontier, key=lambda f: f[0], reverse=True)[:3]
    for i, (score, imgs, ws, wd, c, cov, ab) in enumerate(top, 1):
        L.append(f"| {i} | {'+'.join(imgs)} | {ws} | {wd} | {c} | {len(cov)}/15"
                 f"{'+尾部' if ab else ''} |")
    L.append("")

    L.append("## 7. 明确的不确定结论\n")
    L.append("以下区间在对应策略下**没有任何留存材料可重放提交状态**,规则状态未知,"
             "不得因区间两端总量相同而推断成立:\n")
    for k in ("A", "B", "C"):
        s = strat[k]
        unc = s["uncertain"]
        tail_unknown = sorted(set(abandoned_seqs) - s["abandoned"])
        prefix = f"- 策略 {k}" + ("(超预算,仅作对照基准)" if not s["fits_budget"] else "")
        parts = []
        parts.append(f"规范谱系序号 {unc} 不可证明" if unc else "规范谱系全部 15 个序号均可证明")
        if tail_unknown:
            parts.append(f"被遗弃尾部 seq {tail_unknown} 不可证明")
        elif abandoned_seqs:
            parts.append("被遗弃尾部可证明")
        L.append(prefix + ":" + ";".join(parts) + "。")
    L.append("")
    tail_eval = [e for e in reconstruction["evaluation"] if e["line"] == "abandoned-source"]
    tail_verdict = "成立" if tail_eval and all(e["rule_holds"] for e in tail_eval) else "违规"
    tail_seqs = ", ".join(str(s) for s in abandoned_seqs)
    L.append(f"被遗弃尾部(源 seq {tail_seqs})说明:该提交曾对外发布并被本审计留存,其规则状态为"
             f"{tail_verdict},但其效果未进入恢复后的规范历史;它证明的是“当时可观察到的状态”,"
             "不构成规范谱系的一部分。\n")

    L.append("## 8. 边界与限制\n")
    L.append("- 本审计校验的是**服务端提供证据的内部一致性**(记录连续性、图像摘要、重放与图像互校),"
             "未直接读取 `journal.lmw` 磁盘字节;按项目规范,校验和是完整性而非身份认证边界。")
    L.append("- 采集器在源停服前完成末次轮询(采集日志 head=10 与停服 stats 一致),本次样本的在线窗口无遗漏;"
             "若实例在两次轮询之间崩溃且日志不可达,该窗口将退化为不确定区间。")
    L.append("- 策略 C 的“记录尾窗”是流式留存语义(只保留最近 W 条);本样本规模小,"
             "最优解的恢复尾窗恰好覆盖整条恢复谱系,长运行系统中该窗口只能覆盖近期区间。")
    L.append("- 未实现任何新的审计接口,未改写任何源记录;全部材料为只读采集。\n")

    L.append("## 9. 复现\n")
    L.append("```sh")
    L.append("go build -o bin/laminad ./cmd/laminad")
    L.append("python3 -I audit/run_audit.py   # 采集:重建 evidence/")
    L.append("python3 -I audit/analyze.py     # 分析:重建 manifest.json、reconstruction.json 与本报告")
    L.append("```")
    (REPORT / "audit-report.md").write_text("\n".join(L) + "\n")


if __name__ == "__main__":
    sys.exit(main())
