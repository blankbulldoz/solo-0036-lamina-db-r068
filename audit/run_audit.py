#!/usr/bin/env python3
"""LaminaDB 审计证据采集(阶段一):真实实例 + 工作负载 + 变更馈送/图像采集。

只使用公开 HTTP 接口(/changes、/backup、/stats、/transactions ...),
不修改源码、不新增审计接口、不改写任何源记录。实例数据目录为临时目录,
运行结束后删除;全部留存证据写入 audit/evidence/。

用法: python3 -I audit/run_audit.py
"""
import hashlib
import json
import pathlib
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[1]
BINARY = ROOT / "bin" / "laminad"
EVIDENCE = ROOT / "audit" / "evidence"
IMAGES = EVIDENCE / "images"

PAGE_LIMIT = 3        # 故意小页,强制多次分页
POLL_OVERLAP = 2      # 每轮采集回重叠已存记录,制造重复分页
REWIND_AFTER_SEQ = 7  # 源 lineage 在此序号后模拟采集器崩溃回退

SCHEMA = {
    "name": "spectra",
    "primary": "sample",
    "columns": [
        {"name": "sample", "type": "int"},
        {"name": "band", "type": "text"},
        {"name": "amplitude", "type": "int", "nullable": True},
        {"name": "valid", "type": "bool"},
    ],
}
# 种子:sample 1..6,amplitude 10..60,总量 210(守恒规则 genesis)
SEED = [(1, 10), (2, 20), (3, 30), (4, 40), (5, 50), (6, 60)]


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()


class Instance:
    """一个 laminad 进程;restore=图像路径时执行异目录恢复。"""

    def __init__(self, binary, data_dir, restore=None):
        self.binary = str(binary)
        self.data_dir = pathlib.Path(data_dir)
        self.restore = restore
        self.process = None
        self.log = None
        self.url = None

    def start(self):
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        self.url = f"http://127.0.0.1:{port}/v1/lamina"
        args = [self.binary, "-data", str(self.data_dir), "-listen", f"127.0.0.1:{port}"]
        if self.restore is not None:
            args += ["-restore", str(self.restore)]
        self.log = tempfile.TemporaryFile()
        self.process = subprocess.Popen(args, stdout=self.log, stderr=self.log)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                self.log.seek(0)
                raise RuntimeError("instance exited: " + self.log.read().decode())
            try:
                self.call("GET", "/health")
                return self
            except (OSError, urllib.error.URLError):
                time.sleep(0.03)
        raise RuntimeError("instance did not become ready")

    def stop(self):
        if self.process and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=12)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()
        if self.log:
            self.log.close()
            self.log = None

    def call(self, method, path, data=None, status=200, raw=False):
        body = None if data is None else json.dumps(data, ensure_ascii=False).encode()
        req = urllib.request.Request(self.url + path, data=body, method=method,
                                     headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=12) as resp:
                code, payload = resp.status, resp.read()
        except urllib.error.HTTPError as e:
            code, payload = e.code, e.read()
        if code != status:
            raise RuntimeError(f"{method} {path}: expect {status}, got {code}: {payload.decode()}")
        return payload if raw else json.loads(payload)

    # ---- 工作负载辅助 ----
    def begin(self):
        return self.call("POST", "/transactions", {}, 201)["id"]

    def put(self, tx, sample, amplitude):
        row = {"sample": sample, "band": f"b{sample}", "amplitude": amplitude, "valid": True}
        return self.call("POST", f"/transactions/{tx}/put",
                         {"relation": "spectra", "row": row, "insert_only": False})

    def commit(self, tx):
        return self.call("POST", f"/transactions/{tx}/commit")

    def transfer_atomic(self, moves):
        """单事务内完成全部转账:守恒规则在每个提交边界成立。"""
        tx = self.begin()
        for sample, amplitude in moves:
            self.put(tx, sample, amplitude)
        return self.commit(tx)["sequence"]

    def transfer_step(self, sample, amplitude):
        """非原子转账的单步:单独一个提交,可能瞬时破坏守恒规则。"""
        tx = self.begin()
        self.put(tx, sample, amplitude)
        return self.commit(tx)["sequence"]

    def stats(self):
        return self.call("GET", "/stats")


class ChangeCollector:
    """/changes 采集器:小页分页、轮间重叠重取、重复记录逐字节比对去重。"""

    def __init__(self, inst, lineage, out_path, events):
        self.inst = inst
        self.lineage = lineage
        self.out_path = out_path
        self.events = events
        self.records = {}          # sequence -> canonical bytes(去重后的权威副本)
        self.duplicates = 0
        self.conflicts = []
        stats = inst.stats()
        self.base = stats["history_base"]
        self.cursor = self.base
        self.events.append({"event": "collector_open", "lineage": lineage,
                            "history_base": self.base, "observed_head": stats["sequence"]})

    def probe_below_base(self):
        """基点缺口证据:对 before-base 游标必须得到 410。"""
        body = None if self.base == 0 else self.base - 1
        for after in ({0, body} if body else {0}):
            try:
                page = self.inst.call("GET", f"/changes?after={after}&limit={PAGE_LIMIT}")
                self.events.append({"event": "below_base_probe", "lineage": self.lineage,
                                    "after": after, "http": 200, "records": len(page["records"])})
            except RuntimeError as exc:
                self.events.append({"event": "below_base_probe", "lineage": self.lineage,
                                    "after": after, "http": 410, "detail": str(exc)[:200]})

    def rewind(self, steps):
        """模拟采集器崩溃:游标回退,下一轮重取已存记录。"""
        old = self.cursor
        self.cursor = max(self.base, self.cursor - steps)
        self.events.append({"event": "collector_rewind", "lineage": self.lineage,
                            "cursor_from": old, "cursor_to": self.cursor})

    def _fetch(self, after):
        return self.inst.call("GET", f"/changes?after={after}&limit={PAGE_LIMIT}")

    def poll(self):
        """轮询一轮:从(游标-重叠)开始向前翻页,直到 more=false。"""
        after = max(self.base, self.cursor - POLL_OVERLAP)
        while True:
            page = self._fetch(after)
            if page["history_base"] != self.base:
                raise RuntimeError(f"history_base changed on {self.lineage}: "
                                   f"{self.base} -> {page['history_base']}")
            seqs = []
            for record in page["records"]:
                blob = canonical(record)
                seq = record["sequence"]
                seqs.append(seq)
                # 每次抓取都记录摘要(含重复投递),供分析阶段独立复核"重复分页逐字节一致"
                self.events.append({"event": "record_seen", "lineage": self.lineage,
                                    "sequence": seq, "sha256": sha256_bytes(blob)})
                if seq in self.records:
                    if self.records[seq] != blob:
                        self.conflicts.append(seq)
                        raise RuntimeError(f"duplicate page conflict at seq {seq} on {self.lineage}")
                    self.duplicates += 1
                else:
                    self.records[seq] = blob
            self.events.append({"event": "page", "lineage": self.lineage,
                                "after": after, "got": seqs, "cursor": page["cursor"],
                                "head": page["head"], "more": page["more"]})
            if not page["more"]:
                self.cursor = max(self.cursor, page["cursor"])
                return page["head"]
            after = page["cursor"]

    def flush(self):
        """按序号写出权威 JSONL(每条记录带 sha256,便于复查)。"""
        lines = []
        for seq in sorted(self.records):
            record = json.loads(self.records[seq])
            lines.append(json.dumps({"lineage": self.lineage, "sequence": seq,
                                     "record": record, "sha256": sha256_bytes(self.records[seq])},
                                    ensure_ascii=False, sort_keys=True))
        self.out_path.write_text("\n".join(lines) + ("\n" if lines else ""))
        return len(lines)


def extract_payload(raw: bytes) -> bytes:
    """从信封原始字节中截取 payload 的逐字节原文(用于独立复算 sha256)。

    Go json.Marshal 把 payload 作为内嵌 JSON 直接拼接,因此按括号配平截取。
    """
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
    raise ValueError("unbalanced payload in envelope")


def take_backup(inst, name, events):
    """GET /backup 落盘为图像材料,记录摘要与图像内序号/水位。"""
    blob = inst.call("GET", "/backup", raw=True)
    envelope = json.loads(blob)
    image = envelope["payload"]  # Go json.RawMessage 内嵌,Python 解析后即为 dict
    path = IMAGES / f"{name}-seq{image['sequence']:04d}.lmi"
    path.write_bytes(blob)
    events.append({"event": "backup", "image": name, "path": path.name,
                   "sequence": image["sequence"], "horizon": image["horizon"],
                   "bytes": len(blob), "sha256": sha256_bytes(blob)})
    return path, image["sequence"]


def main():
    if not BINARY.exists():
        raise SystemExit("build first: go build -o bin/laminad ./cmd/laminad")
    if EVIDENCE.exists():
        shutil.rmtree(EVIDENCE)
    IMAGES.mkdir(parents=True)
    events = []
    work = pathlib.Path(tempfile.mkdtemp(prefix="lamina-audit-"))
    source = restored = None
    try:
        # ---------- 源实例:在线变更 + 周期图像 ----------
        source = Instance(BINARY, work / "source").start()
        src = ChangeCollector(source, "source", EVIDENCE / "changes-source.jsonl", events)
        src.probe_below_base()  # base=0,after=0 合法,记录可达范围

        source.call("POST", "/relations", SCHEMA, 201)                       # seq 1
        tx = source.begin()
        for sample, amp in SEED:
            source.put(tx, sample, amp)
        assert source.commit(tx)["sequence"] == 2                            # seq 2 种子,总量 210
        src.poll()
        take_backup(source, "imgA", events)                                  # imgA @2 (horizon 0)

        assert source.transfer_atomic([(1, 0), (2, 30)]) == 3                # seq 3 原子转账 ✓
        assert source.transfer_step(3, 10) == 4                              # seq 4 瞬时违规(总量 190)
        assert source.transfer_step(4, 60) == 5                              # seq 5 修复(总量 210)
        source.call("POST", "/indexes",
                    {"name": "by_amplitude", "relation": "spectra",
                     "column": "amplitude", "unique": False}, 201)           # seq 6 索引记录
        assert source.transfer_atomic([(5, 45), (6, 65)]) == 7               # seq 7 ✓
        src.poll()
        src.rewind(REWIND_AFTER_SEQ - 2)                                     # 模拟崩溃回退,重取 3..7
        src.poll()
        vac = source.call("POST", "/vacuum", {"horizon": 6})                 # seq 8 回收,抹掉 seq4 证据
        assert vac["horizon"] == 6 and not vac["pinned"]
        assert source.transfer_atomic([(1, 5), (2, 25)]) == 9                # seq 9 ✓
        src.poll()
        imgB_path, imgB_seq = take_backup(source, "imgB", events)            # imgB @9 (horizon 6)=恢复基点
        assert source.transfer_atomic([(6, 60), (3, 15)]) == 10              # seq 10 ✓(将被遗弃的尾部)
        src.poll()
        source_stats = source.stats()
        events.append({"event": "source_shutdown", "head": source_stats["sequence"],
                       "horizon": source_stats["horizon"], "journal_records": source_stats["journal_records"]})
        source.stop()
        source = None

        # ---------- 异目录恢复:新历史从基点 9 继续 ----------
        restored = Instance(BINARY, work / "restored", restore=imgB_path).start()
        dst = ChangeCollector(restored, "restored", EVIDENCE / "changes-restored.jsonl", events)
        events.append({"event": "restore", "from_image": imgB_path.name,
                       "restored_history_base": dst.base})
        dst.probe_below_base()  # after=0 与 after=8 必须 410:基点缺口
        dst.poll()

        assert restored.transfer_atomic([(4, 55), (5, 50)]) == 10            # seq 10'(新历史,与源 seq10 同号不同内容)
        assert restored.transfer_atomic([(6, 70), (1, 0)]) == 11             # seq 11' ✓
        assert restored.transfer_step(2, 5) == 12                            # seq 12' 瞬时违规(总量 190)
        assert restored.transfer_step(5, 70) == 13                           # seq 13' 修复(总量 210)
        dst.poll()
        vac = restored.call("POST", "/vacuum", {"horizon": 13})              # seq 14' 回收,抹掉 seq12' 证据
        assert vac["horizon"] == 13
        assert restored.transfer_atomic([(3, 20), (4, 45)]) == 15            # seq 15' ✓
        dst.poll()
        take_backup(restored, "imgC", events)                                # imgC @15' (horizon 13)
        restored_stats = restored.stats()
        events.append({"event": "restored_shutdown", "head": restored_stats["sequence"],
                       "horizon": restored_stats["horizon"],
                       "journal_records": restored_stats["journal_records"]})
        restored.stop()
        restored = None

        n_src = src.flush()
        n_dst = dst.flush()
        events.append({"event": "flush", "source_records": n_src, "restored_records": n_dst,
                       "source_duplicates": src.duplicates, "restored_duplicates": dst.duplicates})
        (EVIDENCE / "collection-log.json").write_text(
            json.dumps(events, ensure_ascii=False, indent=1) + "\n")
        print(json.dumps({"status": "collected", "source_records": n_src,
                          "restored_records": n_dst,
                          "duplicates": {"source": src.duplicates, "restored": dst.duplicates},
                          "evidence": str(EVIDENCE)}, ensure_ascii=False))
    finally:
        if source:
            source.stop()
        if restored:
            restored.stop()
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
