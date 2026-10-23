PUZZLE 71: CPU ECC/HASH160 CANARY WITH INTEGRITY CHECK EVERY 1,000,000 KEYS
================================================================================

HONEST GATE STATUS
------------------
Puzzle 71 address: 1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU
Address-derived HASH160: f6f5431d25bbf7b12e8add9af5e3475c44a0a5b8
Puzzle 71 original full public key: NOT ESTABLISHED.

No program can derive that unique missing full public key from the address alone.
The separately generated CANARY control public key is a known test identity,
NOT the missing Puzzle 71 public key. Never substitute it into Kangaroo or
mark the Puzzle 71 full-public-key identity gate PASS because of this canary.

CONTENTS
--------
p71_integrity_canary.py           new integrity checker + CPU synthetic canary
p71_manifest_controller.py       existing manifest runner, patched to honor ONLY
                                 the upgraded 100-milestone canary proof
RUN_P71_CONTROLLER_WINDOWS.bat   Windows menu; all operations leave console open
priority_manifest_example.json   example manifest, never implicitly expanded
P71_INTEGRITY_UPGRADE_README.txt  this document
P71_INTEGRITY_VALIDATION_REPORT.txt
reference_evidence_2m/           actual audited partial execution, NOT final pass

DEPENDENCIES
------------
64-bit Python 3.10 or newer. Install cryptography:
    py -3 -m pip install cryptography

Recommended optional accelerator:
    py -3 -m pip install coincurve

If RIPEMD160 is missing from your OpenSSL build:
    py -3 -m pip install pycryptodome

The 'auto' engine uses coincurve when installed; otherwise python-step:
python-step uses a real Python secp256k1 group add/subtract per candidate,
with one initial scalar multiplication per million-key segment. It DOES NOT
replace ECC or HASH160 with fake counters. Full OpenSSL-based cryptography
scalar multiplication for every key is supported but much slower.

COMMANDS (Windows PowerShell or CMD, from extracted folder)
-------------------------------------------------------------
1. Check Puzzle 71 target address and HASH160 identity:
    py -3 p71_integrity_canary.py identity

2. Check a candidate (33-byte 02/03 compressed PUBLIC key only):
    py -3 p71_integrity_canary.py identity --pubkey 0336dcea7c21e16c3f7cacfe81bd0aebd6241653b4c8927e91c9acae0db02fcb58
   If it does not produce the target HASH160, the candidate is NOT verified.

3. Test real ECC, dual-direction, sampled integrity and JSON checkpoints:
    py -3 p71_integrity_canary.py smoketest --state-dir C:\p71\smoke
   This uses a deliberately SMALL synthetic range. It is NEVER a 100M pass.

4. Run the full 100,000,000-key real-CPU canary:
    py -3 p71_integrity_canary.py run --state-dir C:\p71\canary

5. Stop cleanly with Ctrl+C. Re-run exactly the same command to resume.
   Work in a partially processed 1,000,000-key segment MAY replay.
   Only fully verified million-key segments get durable coverage credit.

6. Inspect proof and status:
    py -3 p71_integrity_canary.py status --state-dir C:\p71\canary

7. Validate manifest and scan ONLY after the full technical canary passes:
    py -3 p71_manifest_controller.py validate --manifest priority_manifest_example.json
    py -3 p71_manifest_controller.py scan --manifest priority_manifest_example.json --canary-dir C:\p71\canary --state-dir C:\p71\scan

The original controller 'canary' command has also been routed to the upgraded
checker. Legacy canary checkpoints without 1M integrity samples DO NOT unlock
manifest scans.

EXACT 100M GEOMETRY
-------------------
Synthetic key interval: 0x100000000 through + 99,999,999 inclusive.
Forward worker:       first 50,000,000 keys, increasing.
Backward worker:      last 50,000,000 keys, decreasing.
A segment is exactly 1,000,000 candidate keys, 50 segments per direction.
Total integrity checkpoints: exactly 100 (50 + 50).

Each segment:
- Actually calculates a compressed secp256k1 public key for every scalar.
- Actually calculates SHA256 then RIPEMD160 for every compressed public key.
- Directly compares the resulting 20-byte HASH160 to a deterministic negative
  control target derived from a key OUTSIDE the scanned synthetic range.
- Records the scan-produced HASH160 for first, middle, and final key.
- Independently recomputes those three samples using separate secp256k1 math
  AND OpenSSL-backed cryptography scalar multiplication.
- Computes SHA256 chaining the latest segment to its worker's previous verified
  segment, and atomically saves the state before counting the segment as done.

A separate positive test checks that a KNOWN matching compressed public key is
correctly found in BOTH a short forward and a short backward scan. This test
is not counted toward the 100-million-key negative coverage requirement.

EVIDENCE AND RESUME
-------------------
State directory:
 integrity_checkpoint.json       authoritative, atomic commit record
 integrity_every_1m.csv           sample hashes and chained integrity milestones
 identity_and_canary_report.json  results and honest gate statuses
 evidence.csv                     exact 16-column user-required evidence header;
                                  only contains completed-worker rows after a
                                  full verified 100-million-key canary pass.

The output checkpoint is pinned to the exact source Python file SHA256,
canary geometry, engine, known control public key/HASH160, independent
revalidated segment sample hashes, and the hash-chain. Do not modify the
Python file between runs or change engine midway through a checkpoint.

This is local evidence, not third-party-attested proof. Checking three samples
per million does not mathematically prove each intermediate computation is
correct if the executing code or computer is malicious or faulty.

GATE POLICY
-----------
Gate 1 address/HASH160 identity: verified.
Gate 1 actual Puzzle 71 full public key: NOT VERIFIED (unknown key).
Gate 2 100,000,000 CPU canary: only technical PASS after ALL 100 checkpoints.
Gate 3 GPU tuning: LOCKED until all required earlier correctness gates pass.
No GPU implementation or GPU performance claim is included.

A nonzero status (2) for an incomplete canary or smoke demo is intentional,
not evidence of a crash; it prevents false 'success' automation.

