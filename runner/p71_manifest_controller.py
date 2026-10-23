#!/usr/bin/env python3
"""Manifest-driven two-direction HASH160 controller (CPU correctness reference).

Commands:
  selftest                      Fast deterministic tests (no Puzzle 71 scanning)
  validate --manifest FILE      Verify range coverage geometry and P2PKH identity
  canary --state-dir DIR         Isolated 100,000,000-candidate CPU canary
  scan --manifest FILE --state-dir DIR --canary-dir DIR
  status --state-dir DIR

The controller does NOT use JeanLucPons Kangaroo or CUDA. It provides independently
checkpointed CPU workers. GPU tuning remains external and gated on canary proof.
"""
import argparse
import csv
import hashlib
import json
import multiprocessing as mp
import os
from pathlib import Path
import queue
import sys
import time
import tempfile

PUZZLE_ADDRESS = "1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU"
EXPECTED_HASH160 = "f6f5431d25bbf7b12e8add9af5e3475c44a0a5b8"
LO, HI = 1 << 70, (1 << 71) - 1
CURVE_N = int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
HEADER = "timestamp,manifest_sha256,rank,chunk_index,slice_index,start_hex,end_hex,direction,command,input_file,exit_code,elapsed_seconds,scanner_result,checkpoint_before_sha256,checkpoint_after_sha256,error_text".split(",")
CANARY_SIZE = 100_000_000
# Synthetic range. Target secret is OUTSIDE the range, to prove complete coverage.
CANARY_START = 1 << 32


class PlannedStop(Exception):
    """Deterministic interruption for checkpoint/restart testing."""


def json_bytes(obj):
    return (json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode("utf-8")


def checksum(obj):
    return hashlib.sha256(json_bytes(obj)).hexdigest()


def atomic_write(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp." + str(os.getpid()))
    with open(tmp, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)
    if os.name != "nt":
        fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def sha256d(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def decode_p2pkh(addr):
    n = 0
    for c in addr:
        if c not in BASE58:
            raise ValueError("Not Base58")
        n = 58 * n + BASE58.index(c)
    raw = (b"\x00" * (len(addr) - len(addr.lstrip("1")))) + (n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b"")
    if len(raw) != 25 or raw[0] != 0 or sha256d(raw[:21])[:4] != raw[21:]:
        raise ValueError("Invalid mainnet P2PKH version, size, or checksum")
    return raw[1:21]


def hash160(data):
    x = hashlib.sha256(data).digest()
    try:
        h = hashlib.new("ripemd160")
        h.update(x)
        return h.digest()
    except ValueError:
        try:
            from Crypto.Hash import RIPEMD160
            return RIPEMD160.new(x).digest()
        except ImportError as exc:
            raise RuntimeError("RIPEMD160 unavailable: install pycryptodome") from exc


def engine_name(requested):
    if requested in ("auto", "coincurve"):
        try:
            import coincurve  # noqa: F401
            return "coincurve"
        except ImportError:
            if requested == "coincurve":
                raise RuntimeError("Install coincurve: py -m pip install coincurve")
    try:
        from cryptography.hazmat.primitives.asymmetric import ec  # noqa: F401
        return "cryptography"
    except ImportError as exc:
        raise RuntimeError("Install coincurve or cryptography") from exc


def compressed_key(k, engine):
    if not 1 <= k < CURVE_N:
        raise ValueError("Private scalar out of secp256k1 bounds")
    if engine == "coincurve":
        from coincurve import PublicKey
        return PublicKey.from_valid_secret(k.to_bytes(32, "big")).format(compressed=True)
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    pub = ec.derive_private_key(k, ec.SECP256K1()).public_key()
    return pub.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint)


def scan_batch(start, bound, direction, limit, target, engine):
    """Inclusive range. Return (number really hashed, hit or None)."""
    assert direction in (-1, 1) and limit >= 1
    count = min(limit, abs(bound - start) + 1)
    if direction * (bound - start) < 0:
        raise ValueError("Worker next pointer has passed its bound")
    if engine == "coincurve":
        from coincurve import PublicKey
        point = PublicKey.from_valid_secret(start.to_bytes(32, "big"))
        delta = (1 if direction == 1 else CURVE_N - 1).to_bytes(32, "big")
        for j in range(count):
            if hash160(point.format(compressed=True)) == target:
                return j + 1, start + j * direction
            if j + 1 != count:
                point.add(delta, update=True)
    else:
        for j in range(count):
            k = start + j * direction
            if hash160(compressed_key(k, engine)) == target:
                return j + 1, k
    return count, None


def parse_hex(x):
    if not isinstance(x, str) or not x:
        raise ValueError("Manifest boundaries must be hex strings")
    return int(x, 16)


def split_chunk(start, end):
    if start > end:
        raise ValueError("Reversed range")
    mid = (start + end) // 2
    return {"forward": (start, mid, 1), "backward": (end, mid + 1, -1)}


def load_manifest(path, canary=False):
    raw = Path(path).read_bytes()
    data = json.loads(raw)
    chunks = data["chunks"] if isinstance(data, dict) else data
    if not isinstance(chunks, list) or not chunks:
        raise ValueError("Manifest must be a nonempty array or {'chunks': [...]}")
    processed = []
    ids = set()
    for c in chunks:
        chunk_id = int(c["chunk_id"])
        rank = int(c["rank"])
        score = float(c.get("score", 0))
        a, b = parse_hex(c["start"]), parse_hex(c["end"])
        if chunk_id in ids:
            raise ValueError(f"Repeated chunk_id {chunk_id}")
        if rank < 1 or not (0 <= score <= 100):
            raise ValueError(f"Invalid rank or priority score: {chunk_id}")
        if not (1 <= a <= b < CURVE_N):
            raise ValueError(f"Malformed interval in chunk {chunk_id}")
        if not canary and not (LO <= a <= b <= HI):
            raise ValueError(f"Out of Puzzle 71 range: chunk {chunk_id}")
        if c.get("forward_status", "pending") != "pending" or c.get("backward_status", "pending") != "pending":
            raise ValueError("Manifest is immutable input; completion must be supported by runner state, not embedded statuses")
        ids.add(chunk_id)
        processed.append({"chunk_id": chunk_id, "rank": rank, "score": score, "start": a, "end": b})
    ordered = sorted(processed, key=lambda x: (x["start"], x["end"]))
    for left, right in zip(ordered, ordered[1:]):
        if right["start"] <= left["end"]:
            raise ValueError(f"Overlapping manifest chunks {left['chunk_id']} and {right['chunk_id']}")
    processed.sort(key=lambda x: (x["rank"], -x["score"], x["chunk_id"]))
    return hashlib.sha256(raw).hexdigest(), processed


def initial_worker(start, bound, step):
    return {"start": f"{start:x}", "bound": f"{bound:x}", "step": step,
            "next": f"{start:x}", "processed": 0, "status": "pending", "hit": None}


def expected_count(w):
    return abs(int(w["start"], 16) - int(w["bound"], 16)) + 1


def worker_key(chunk_id, direction):
    return str(chunk_id) + ":" + direction


def create_state(manifest_sha, target_hex, chunks, mode):
    workers = {}
    for c in chunks:
        for d, (a, b, step) in split_chunk(c["start"], c["end"]).items():
            workers[worker_key(c["chunk_id"], d)] = {"position": initial_worker(a, b, step), "proof": None}
    return {"schema": 1, "mode": mode, "manifest_sha256": manifest_sha,
            "target_hash160": target_hex, "workers": workers}


def validate_state(state, manifest_sha, target_hex, chunks, mode):
    if state.get("schema") != 1 or state.get("mode") != mode or state.get("manifest_sha256") != manifest_sha or state.get("target_hash160") != target_hex:
        raise ValueError("Checkpoint does not match this manifest, target or mode")
    expected_keys = {worker_key(c["chunk_id"], d) for c in chunks for d in ("forward", "backward")}
    if set(state["workers"]) != expected_keys:
        raise ValueError("Checkpoint worker inventory differs from manifest")
    for c in chunks:
        for d, (a, b, step) in split_chunk(c["start"], c["end"]).items():
            item = state["workers"][worker_key(c["chunk_id"], d)]
            w = item["position"]
            size = abs(a - b) + 1
            scanned = int(w["processed"])
            if (int(w["start"], 16), int(w["bound"], 16), int(w["step"])) != (a, b, step):
                raise ValueError("Checkpoint geometry mismatch")
            if not (0 <= scanned <= size) or int(w["next"], 16) != a + scanned * step:
                raise ValueError("Checkpoint count/next mismatch")
            if w["status"] == "completed":
                if scanned != size or not item["proof"] or item["proof"]["after"] != checksum(w):
                    raise ValueError("Unproven or corrupted completion")
            elif w["status"] == "found":
                if not item["proof"] or item["proof"]["after"] != checksum(w) or w["hit"] is None:
                    raise ValueError("Unproven or corrupted match")
            elif w["status"] != "pending" or item["proof"] is not None:
                raise ValueError("Invalid worker status")


def save_state(path, state):
    atomic_write(path, json_bytes(state))


def rebuild_evidence(folder, state, chunks, manifest_path):
    meta = {c["chunk_id"]: c for c in chunks}
    rows = []
    for key, item in state["workers"].items():
        proof = item["proof"]
        if proof is None:
            continue
        chunk_id, direction = key.split(":")
        c = meta[int(chunk_id)]
        w = item["position"]
        rows.append({
            "timestamp": proof["timestamp"], "manifest_sha256": state["manifest_sha256"],
            "rank": c["rank"], "chunk_index": c["chunk_id"], "slice_index": 0,
            "start_hex": w["start"], "end_hex": w["bound"], "direction": direction,
            "command": proof["command"], "input_file": manifest_path, "exit_code": 0,
            "elapsed_seconds": f"{proof['elapsed_seconds']:.3f}",
            "scanner_result": "verified_match" if w["status"] == "found" else "complete_no_match",
            "checkpoint_before_sha256": proof["before"], "checkpoint_after_sha256": proof["after"],
            "error_text": ""
        })
    for failure in state.get("errors", []):
        cid = failure.get("chunk_id")
        chunk = meta.get(cid)
        rows.append({
            "timestamp": failure["timestamp"], "manifest_sha256": state["manifest_sha256"],
            "rank": chunk["rank"] if chunk else "", "chunk_index": cid if cid is not None else "",
            "slice_index": 0, "start_hex": failure.get("start_hex", ""),
            "end_hex": failure.get("end_hex", ""), "direction": failure.get("direction", ""),
            "command": failure.get("command", ""), "input_file": manifest_path, "exit_code": 1,
            "elapsed_seconds": failure.get("elapsed_seconds", ""), "scanner_result": "runner_error",
            "checkpoint_before_sha256": failure.get("checkpoint_sha256", ""),
            "checkpoint_after_sha256": failure.get("checkpoint_sha256", ""),
            "error_text": failure["error_text"]
        })
    # Re-render from checkpoint proofs, never invent past results or infer completion from filenames.
    import io
    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(buffer, fieldnames=HEADER, lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    atomic_write(Path(folder) / "evidence.csv", buffer.getvalue().encode("utf-8"))
    hits = []
    for key, item in state["workers"].items():
        if item["position"]["status"] == "found":
            hits.append({"worker": key, "private_key_hex": item["position"]["hit"],
                         "hash160": state["target_hash160"], "verification": "independent backend"})
    if hits:
        atomic_write(Path(folder) / "verified_matches.json", json_bytes(hits))


def worker_process(key, pos, target_hex, limit, engine, result_queue, ack_queue):
    try:
        nxt = int(pos["next"], 16)
        end = int(pos["bound"], 16)
        step = int(pos["step"])
        target = bytes.fromhex(target_hex)
        while (nxt <= end if step > 0 else nxt >= end):
            t = time.perf_counter()
            count, hit = scan_batch(nxt, end, step, limit, target, engine)
            result_queue.put({"key": key, "start": nxt, "count": count, "hit": hit,
                              "elapsed": time.perf_counter() - t})
            if ack_queue.get() != "continue" or hit is not None:
                break
            nxt += count * step
    except BaseException as exc:
        result_queue.put({"key": key, "error": repr(exc)})


def execute(manifest_sha, chunks, target_hex, state_dir, mode, engine, batch_size, manifest_path, max_commits=None):
    folder = Path(state_dir)
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / "checkpoint.json"
    if path.exists():
        state = json.loads(path.read_text("utf-8"))
        validate_state(state, manifest_sha, target_hex, chunks, mode)
    else:
        state = create_state(manifest_sha, target_hex, chunks, mode)
        save_state(path, state)
    rebuild_evidence(folder, state, chunks, manifest_path)
    total = sum(c["end"] - c["start"] + 1 for c in chunks)
    done = sum(i["position"]["processed"] for i in state["workers"].values())
    print(f"Mode: {mode} | Engine: {engine} | Processed (durable): {done:,} / {total:,}", flush=True)
    if any(i["position"]["status"] == "found" for i in state["workers"].values()):
        print("Verified match already recorded. No further scanning performed.")
        return 0
    context = mp.get_context("spawn")
    commits = 0
    current_key = None
    current_chunk = None
    try:
        for c in chunks:
            current_chunk = c["chunk_id"]
            keys = [worker_key(c["chunk_id"], d) for d in ("forward", "backward")]
            pending = [k for k in keys if state["workers"][k]["position"]["status"] == "pending"]
            if not pending:
                continue
            results = context.Queue()
            workers = {}
            for key in pending:
                ack = context.Queue()
                proc = context.Process(target=worker_process, args=(key, state["workers"][key]["position"],
                                       target_hex, batch_size, engine, results, ack))
                proc.start()
                workers[key] = (proc, ack, time.perf_counter())
            try:
                live = set(pending)
                found_this_chunk = False
                while live:
                    try:
                        msg = results.get(timeout=2)
                    except queue.Empty:
                        dead = [k for k in live if not workers[k][0].is_alive()]
                        if dead:
                            current_key = dead[0]
                            raise RuntimeError("Worker died without a committed result; resume safely from checkpoint")
                        continue
                    key = msg["key"]
                    current_key = key
                    if key not in live:
                        raise RuntimeError("Unexpected or duplicate worker result")
                    if "error" in msg:
                        raise RuntimeError(f"{key}: {msg['error']}")
                    item = state["workers"][key]
                    old = item["position"]
                    start, step, bound = int(old["next"], 16), int(old["step"]), int(old["bound"], 16)
                    if msg["start"] != start or not 1 <= msg["count"] <= batch_size:
                        raise RuntimeError("Out of order or invalid worker acknowledgment")
                    last = start + (msg["count"] - 1) * step
                    if not (min(start, bound) <= last <= max(start, bound)):
                        raise RuntimeError("Batch overshot its assigned interval")
                    hit = msg["hit"]
                    if hit is not None:
                        if not (min(start, last) <= hit <= max(start, last)):
                            raise RuntimeError("Hit outside reported processed interval")
                        # Verification intentionally uses a different ECC backend where possible.
                        other = "cryptography" if engine == "coincurve" else engine
                        if hash160(compressed_key(hit, other)).hex() != target_hex:
                            raise RuntimeError("Candidate did not pass independent verification")
                    updated = dict(old)
                    updated["processed"] += msg["count"]
                    updated["next"] = f"{start + msg['count'] * step:x}"
                    if hit is not None:
                        updated["status"] = "found"
                        updated["hit"] = f"{hit:064x}"
                        found_this_chunk = True
                    elif last == bound:
                        updated["status"] = "completed"
                    if updated["status"] != "pending":
                        item["proof"] = {"timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                                         "before": checksum(old), "after": checksum(updated),
                                         "command": "p71_manifest_controller.py " + mode + " --engine " + engine,
                                         "elapsed_seconds": time.perf_counter() - workers[key][2]}
                    item["position"] = updated
                    # The parent is the SOLE writer. Save before releasing worker for the next batch.
                    save_state(path, state)
                    commits += 1
                    if max_commits is not None and commits >= max_commits:
                        raise PlannedStop("Intentional stop after durable checkpoint")
                    if updated["status"] == "pending" and not found_this_chunk:
                        workers[key][1].put("continue")
                    else:
                        workers[key][1].put("stop")
                        live.remove(key)
                        if updated["status"] != "pending":
                            rebuild_evidence(folder, state, chunks, manifest_path)
                            print(f"{key}: {updated['status']} ({updated['processed']:,} verified candidates)", flush=True)
                for proc, ack, _ in workers.values():
                    proc.join(timeout=5)
                    if proc.exitcode not in (0, None):
                        raise RuntimeError(f"Worker process failed with exit code {proc.exitcode}")
                if found_this_chunk:
                    print("Verified match saved. Remaining manifest chunks were not scanned.")
                    return 0
            finally:
                for proc, ack, _ in workers.values():
                    if proc.is_alive():
                        proc.terminate()
                    proc.join(timeout=2)
                results.close()
                for proc, ack, _ in workers.values():
                    ack.close()
    except KeyboardInterrupt:
        print("Stopped by user. Resume from last DURABLE checkpoint. Current batch may replay.", file=sys.stderr)
        return 130
    except PlannedStop:
        raise
    except Exception as exc:
        item = state["workers"].get(current_key) if current_key is not None else None
        pos = item["position"] if item else None
        state.setdefault("errors", []).append({
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "chunk_id": current_chunk,
            "direction": current_key.split(":")[1] if current_key and ":" in current_key else "",
            "start_hex": pos["start"] if pos else "",
            "end_hex": pos["bound"] if pos else "",
            "checkpoint_sha256": checksum(pos) if pos else "",
            "command": "p71_manifest_controller.py " + mode + " --engine " + engine,
            "error_text": str(exc)
        })
        save_state(path, state)
        rebuild_evidence(folder, state, chunks, manifest_path)
        raise
    done = sum(i["position"]["processed"] for i in state["workers"].values())
    finished = all(i["position"]["status"] == "completed" for i in state["workers"].values())
    print(f"Durably processed: {done:,} / {total:,}; Exhausted: {finished}")
    return 0


def make_canary_manifest(path):
    manifest = {"chunks": [{"rank": 1, "chunk_id": 0, "start": f"{CANARY_START:x}",
                           "end": f"{CANARY_START + CANARY_SIZE - 1:x}",
                           "score": 0, "forward_status": "pending", "backward_status": "pending"}]}
    data = json_bytes(manifest)
    path = Path(path)
    if path.exists() and path.read_bytes() != data:
        raise ValueError("Canary manifest already exists with DIFFERENT contents")
    if not path.exists():
        atomic_write(path, data)
    return path


def is_canary_passed(folder):
    """Accept ONLY the upgraded 100 x 1M independently-checked real ECC canary."""
    cp = Path(folder) / "integrity_checkpoint.json"
    if not cp.exists():
        return False
    try:
        # Imported lazily to avoid circular imports during CLI startup.
        import p71_integrity_canary as robust_canary
        state = json.loads(cp.read_text("utf-8"))
        return bool(robust_canary.validate_checkpoint(state))
    except (ValueError, RuntimeError, OSError, KeyError, ImportError, TypeError):
        return False


def selftest(engine):
    # Published generator-vector identity: privkey 1 -> compressed G -> HASH160.
    pub = compressed_key(1, engine)
    assert pub.hex() == "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    assert hash160(pub).hex() == "751e76e8199196d454941c45d1b3a323f1433bd6"
    assert decode_p2pkh(PUZZLE_ADDRESS).hex() == EXPECTED_HASH160
    assert split_chunk(10, 19) == {"forward": (10, 14, 1), "backward": (19, 15, -1)}
    for direction, a, b in ((1, 10, 19), (-1, 19, 10)):
        target = hash160(compressed_key(14, engine))
        count, hit = scan_batch(a, b, direction, 10, target, engine)
        assert hit == 14 and count == (5 if direction == 1 else 6)
        miss = hash160(compressed_key(22, engine))
        count, hit = scan_batch(a, b, direction, 10, miss, engine)
        assert count == 10 and hit is None
    print(f"PASS: generator vector, Base58Check target, two directions, positive/negative tests [{engine}]")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("selftest")
    sub.add_parser("smoketest").add_argument("--engine", choices=("auto", "coincurve", "cryptography"), default="auto")
    val = sub.add_parser("validate")
    val.add_argument("--manifest", required=True)
    c = sub.add_parser("canary")
    c.add_argument("--state-dir", required=True)
    scan = sub.add_parser("scan")
    scan.add_argument("--manifest", required=True)
    scan.add_argument("--state-dir", required=True)
    scan.add_argument("--canary-dir", required=True)
    status = sub.add_parser("status")
    status.add_argument("--state-dir", required=True)
    for p in (sub.choices["selftest"], c, scan):
        p.add_argument("--engine", choices=("auto", "coincurve", "cryptography"), default="auto")
    for p in (c, scan):
        p.add_argument("--batch-size", type=int, default=8192)
    args = parser.parse_args()
    try:
        if args.cmd == "status":
            p = Path(args.state_dir) / "checkpoint.json"
            if not p.exists():
                print("No checkpoint found")
                return 1
            state = json.loads(p.read_text("utf-8"))
            for name, item in state["workers"].items():
                w = item["position"]
                print(f"{name}: {w['status']}; processed={w['processed']:,}; next=0x{w['next']}; proof={bool(item['proof'])}")
            print("Canary passed:", is_canary_passed(args.state_dir))
            return 0
        if args.cmd == "validate":
            sha, chunks = load_manifest(args.manifest)
            target = decode_p2pkh(PUZZLE_ADDRESS).hex()
            if target != EXPECTED_HASH160:
                raise ValueError("Canonical target hash mismatch")
            print("PASS: Puzzle 71 mainnet address checksum / HASH160 target identity")
            print("PASS: all chunk bounds, no overlapping ranges, directional partition geometry")
            print("SHA256:", sha, "| Chunks:", len(chunks), "| Keys:", f"{sum(c['end']-c['start']+1 for c in chunks):,}")
            print("NOTE: No Puzzle 71 public key has been verified by this step.")
            return 0
        engine = engine_name(args.engine)
        selftest(engine)
        if args.cmd == "selftest":
            return 0
        if args.cmd == "smoketest":
            with tempfile.TemporaryDirectory(prefix="p71smoke_") as tmp:
                p = Path(tmp) / "smoke_manifest.json"
                lower = 1000
                size = 1001
                atomic_write(p, json_bytes({"chunks": [{"rank": 1, "chunk_id": 3, "start": f"{lower:x}",
                    "end": f"{lower+size-1:x}", "score": 0}]}))
                sha, chunks = load_manifest(p, canary=True)
                outside_target = hash160(compressed_key(lower + size + 1, engine)).hex()
                try:
                    execute(sha, chunks, outside_target, tmp, "smoke", engine, 37, str(p), max_commits=3)
                    raise AssertionError("Fault injection did not stop the run")
                except PlannedStop:
                    print("PASS: deliberate interruption after durable checkpoint")
                before = json.loads((Path(tmp) / "checkpoint.json").read_text("utf-8"))
                assert sum(x["position"]["processed"] for x in before["workers"].values()) >= 3*37
                assert execute(sha, chunks, outside_target, tmp, "smoke", engine, 37, str(p)) == 0
                after = json.loads((Path(tmp) / "checkpoint.json").read_text("utf-8"))
                validate_state(after, sha, outside_target, chunks, "smoke")
                assert sum(x["position"]["processed"] for x in after["workers"].values()) == size
                assert all(x["position"]["status"] == "completed" for x in after["workers"].values())
                with open(Path(tmp) / "evidence.csv", newline="", encoding="utf-8") as f:
                    rows = list(csv.DictReader(f))
                assert len(rows) == 2 and all(row["scanner_result"] == "complete_no_match" for row in rows)
                assert all(len(row["checkpoint_after_sha256"]) == 64 for row in rows)
                assert execute(sha, chunks, outside_target, tmp, "smoke", engine, 37, str(p)) == 0
                with open(Path(tmp) / "evidence.csv", newline="", encoding="utf-8") as f:
                    assert len(list(csv.DictReader(f))) == 2
                print("PASS: no skipped/double-counted durable coverage, resume, CSV proof reconstruction, idempotent rerun")
            with tempfile.TemporaryDirectory(prefix="p71hit_") as tmp:
                p = Path(tmp) / "positive_manifest.json"
                a, n = 2500, 211
                atomic_write(p, json_bytes({"chunks": [{"rank": 1, "chunk_id": 9,
                    "start": f"{a:x}", "end": f"{a+n-1:x}", "score": 1}]}))
                sha, chunks = load_manifest(p, canary=True)
                target = hash160(compressed_key(a + 3, engine)).hex()
                assert execute(sha, chunks, target, tmp, "smoke", engine, 13, str(p)) == 0
                state = json.loads((Path(tmp) / "checkpoint.json").read_text("utf-8"))
                validate_state(state, sha, target, chunks, "smoke")
                assert len([w for w in state["workers"].values() if w["position"]["status"] == "found"]) == 1
                found = json.loads((Path(tmp) / "verified_matches.json").read_text("utf-8"))
                assert int(found[0]["private_key_hex"], 16) == a + 3
                recorded = sum(w["position"]["processed"] for w in state["workers"].values())
                assert execute(sha, chunks, target, tmp, "smoke", engine, 13, str(p)) == 0
                assert sum(w["position"]["processed"] for w in json.loads((Path(tmp) / "checkpoint.json").read_text("utf-8"))["workers"].values()) == recorded
                print("PASS: verified match stored, early-stop and no rescanning after verified hit")
            return 0
        if args.batch_size <= 0 or args.batch_size > 10_000_000:
            raise ValueError("Batch size must be between 1 and 10,000,000")
        if args.cmd == "canary":
            import p71_integrity_canary as robust_canary
            if args.engine == "auto":
                try:
                    robust_engine = engine_name("coincurve")
                except RuntimeError:
                    robust_engine = "python-step"
            else:
                robust_engine = engine
            robust_canary.run_canary(args.state_dir, robust_engine,
                                      robust_canary.CANARY_SIZE,
                                      robust_canary.INTEGRITY_INTERVAL)
            passed = is_canary_passed(args.state_dir)
            print("INTEGRITY-VERIFIED GATE 2:", "TECHNICAL PASS" if passed else "NOT PASSED")
            print("PUZZLE 71 PUBLIC KEY: NOT VERIFIED; GPU TUNING LOCKED")
            return 0 if passed else 2
        if args.cmd == "scan":
            if not is_canary_passed(args.canary_dir):
                raise RuntimeError("GATE 2 LOCKED: complete the isolated 100,000,000-key canary first")
            sha, chunks = load_manifest(args.manifest)
            target = decode_p2pkh(PUZZLE_ADDRESS).hex()
            if target != EXPECTED_HASH160:
                raise ValueError("Target identity failed")
            print("GATE 1: address/HASH160 PASS. This does not establish any published full public key.")
            print("GATE 2: verified 100,000,000-key canary PASS; GPU tuning not performed.")
            return execute(sha, chunks, target, args.state_dir, "scan", engine, args.batch_size, args.manifest)
    except (ValueError, OSError, RuntimeError, KeyError, AssertionError) as exc:
        print("ERROR:", exc, file=sys.stderr)
        return 1
    return 1


if __name__ == "__main__":
    mp.freeze_support()
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("Interrupted. Checkpoints preserved.", file=sys.stderr)
        sys.exit(130)
