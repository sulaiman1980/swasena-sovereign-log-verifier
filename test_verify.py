#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Reproducible test + public test-vector generator for the independent verifier (v1).
Generates public test vectors (valid + tampered) and proves the verifier accepts a
valid v1 log and rejects tampering. Deterministic (fixed timestamps) so vectors are
byte-stable and publishable.
"""
import os, sys, json, hashlib, subprocess, unicodedata

HERE = os.path.dirname(os.path.abspath(__file__))
VEC = os.path.join(HERE, "test_vectors")
VERIFIER = os.path.join(HERE, "swasena_verify.py")


def _nfc(obj):
    if isinstance(obj, str):
        return unicodedata.normalize("NFC", obj)
    if isinstance(obj, dict):
        return {unicodedata.normalize("NFC", k): _nfc(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_nfc(x) for x in obj]
    return obj


def _canonical(rec):
    r = _nfc({k: v for k, v in rec.items() if k != "chain"})
    return json.dumps(r, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def build_chain(records):
    """Attach a v1 chain (256-bit, RFC 8785 JCS, NFC, 0x00 separator, v:1) to each record."""
    prev, out = "", []
    for rec in records:
        r = dict(rec); r["v"] = 1
        r["chain"] = hashlib.sha256((prev + "\x00" + _canonical(r)).encode("utf-8")).hexdigest()
        prev = r["chain"]
        out.append(r)
    return out


def write_jsonl(name, records):
    p = os.path.join(VEC, name)
    with open(p, "w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    return p


def write_raw(name, text):
    with open(os.path.join(VEC, name), "w", encoding="utf-8") as f:
        f.write(text)


def run(path, *extra):
    r = subprocess.run([sys.executable, VERIFIER, path, *extra], capture_output=True, text=True)
    return r.returncode, (r.stdout + r.stderr)


def main():
    os.makedirs(VEC, exist_ok=True)
    # Valid v1 chain (labeled sample data; previews carry only placeholder tokens).
    base = [
        {"ts": 1785000000, "action": "event", "category": "-", "secrets_kept_local": 2,
         "obfuscated_preview": "a message mentioning <<ENTITY_1>> and <<ENTITY_2>>"},
        {"ts": 1785000060, "action": "event", "category": "-", "secrets_kept_local": 1,
         "obfuscated_preview": "an update to record <<ENTITY_1>>"},
        {"ts": 1785000120, "action": "event", "category": "-", "secrets_kept_local": 3,
         "obfuscated_preview": "a note to <<ENTITY_2>> at <<ENTITY_3>>"},
        {"ts": 1785000180, "action": "event", "category": "-", "secrets_kept_local": 0,
         "obfuscated_preview": "what is the capital of Japan?"},
    ]
    valid = build_chain(base)
    write_jsonl("valid.jsonl", valid)
    head = valid[-1]["chain"]
    assert len(head) == 64, "v1 links must be full 256-bit (64 hex)"

    # (1) interior edit keeping the old link => REJECTED
    edit = [dict(r) for r in valid]
    edit[1] = dict(edit[1]); edit[1]["obfuscated_preview"] = "an altered value for <<ENTITY_1>>"
    write_jsonl("tampered_edit.jsonl", edit)

    # (2) interior delete => REJECTED
    write_jsonl("tampered_delete.jsonl", [valid[0], valid[2], valid[3]])

    # (3) insert a forged record => REJECTED
    forged = {"v": 1, "ts": 1785000090, "action": "event", "category": "-", "secrets_kept_local": 0,
              "obfuscated_preview": "inserted record", "chain": "de" * 32}
    write_jsonl("tampered_insert.jsonl", [valid[0], valid[1], forged, valid[2], valid[3]])

    # (4) tail-truncation: a valid prefix => consistent WITHOUT anchor, REJECTED WITH anchor
    write_jsonl("tampered_truncate.jsonl", valid[:2])

    # (5) duplicate keys => REJECTED
    r1 = valid[1]
    dup = ('{"v":1,"action":"other","ts":%d,"category":%s,"secrets_kept_local":%d,'
           '"obfuscated_preview":%s,"action":"event","chain":%s}\n' % (
               r1["ts"], json.dumps(r1["category"]), r1["secrets_kept_local"],
               json.dumps(r1["obfuscated_preview"]), json.dumps(r1["chain"])))
    write_raw("tampered_dupkey.jsonl", json.dumps(valid[0], ensure_ascii=False) + "\n" + dup)

    # (6) empty log => REJECTED ; (7) NaN => REJECTED ; (8) non-object => REJECTED cleanly
    write_raw("tampered_empty.jsonl", "")
    write_raw("tampered_nan.jsonl", '{"v":1,"ts":1,"score":NaN,"chain":"x"}\n')
    write_raw("tampered_nonobject.jsonl", '["chain","x"]\n')

    # (9) Infinity overflow ; (10) float ; (11) integer > 2^53 => all REJECTED
    write_raw("tampered_infinity.jsonl", '{"v":1,"ts":1,"secrets_kept_local":1e400,"chain":"x"}\n')
    write_raw("tampered_float.jsonl", '{"v":1,"ts":1,"score":3.14,"chain":"x"}\n')
    write_raw("tampered_bigint.jsonl", '{"v":1,"ts":18446744073709551616,"chain":"x"}\n')

    # (12) missing/unknown version => REJECTED (bad_version)
    write_raw("tampered_bad_version.jsonl", json.dumps({k: v for k, v in valid[0].items() if k != "v"}) + "\n")

    # (13) an astral (> U+FFFF) key => REJECTED (keys MUST be in the BMP, SPEC §4d)
    write_raw("tampered_astral_key.jsonl", '{"v":1,"\U00010000":1,"chain":"x"}\n')

    # (14) pathologically nested JSON => REJECTED cleanly, never a traceback (SPEC §8.5)
    write_raw("tampered_deepnest.jsonl", '{"v":1,"chain":"x","a":' + "[" * 5000 + "]" * 5000 + "}\n")

    # (15) NFC-equivalent keys (byte-distinct, collapse under NFC) => REJECTED (SPEC §4e).
    # U+00C5 (composed) and U+0041 U+030A (A + combining ring) normalize to the same key.
    _k1, _k2 = "\u00c5", "A\u030a"
    assert _k1 != _k2 and unicodedata.normalize("NFC", _k2) == _k1, "NFC vector keys"
    write_raw("tampered_nfc_collision.jsonl",
              '{"v":1,%s:1,%s:2,"chain":"x"}\n' % (json.dumps(_k1), json.dumps(_k2)))

    cases = [("valid.jsonl", 0, "valid accepted (256-bit v1)", ()),
             ("valid.jsonl", 0, "valid + correct anchor accepted", ("--expect-head", head, "--expect-count", "4")),
             ("valid.jsonl", 1, "valid + wrong anchor rejected", ("--expect-head", "0" * 64)),
             ("tampered_edit.jsonl", 1, "edit rejected", ()),
             ("tampered_delete.jsonl", 1, "interior delete rejected", ()),
             ("tampered_insert.jsonl", 1, "insert rejected", ()),
             ("tampered_truncate.jsonl", 0, "tail-truncation: consistent without anchor", ()),
             ("tampered_truncate.jsonl", 1, "tail-truncation: caught with anchor", ("--expect-head", head, "--expect-count", "4")),
             ("tampered_dupkey.jsonl", 1, "duplicate keys rejected", ()),
             ("tampered_empty.jsonl", 1, "empty log rejected", ()),
             ("tampered_nan.jsonl", 1, "NaN rejected", ()),
             ("tampered_nonobject.jsonl", 1, "non-object line rejected cleanly", ()),
             ("tampered_infinity.jsonl", 1, "Infinity (1e400) rejected", ()),
             ("tampered_float.jsonl", 1, "float rejected", ()),
             ("tampered_bigint.jsonl", 1, "integer above 2^53 rejected", ()),
             ("tampered_bad_version.jsonl", 1, "missing/unknown version rejected", ()),
             ("tampered_astral_key.jsonl", 1, "astral (non-BMP) key rejected", ()),
             ("tampered_deepnest.jsonl", 1, "deeply-nested JSON rejected cleanly (no traceback)", ()),
             ("tampered_nfc_collision.jsonl", 1, "NFC-equivalent keys rejected", ())]
    ok = True
    for name, expect_rc, desc, extra in cases:
        rc, out = run(os.path.join(VEC, name), *extra)
        good = (rc == expect_rc) and not (expect_rc == 1 and "Traceback" in out)
        ok = ok and good
        print(("  [ok] " if good else "  [FAIL] ") + f"{desc}: rc={rc} (expected {expect_rc})")
    print("\n" + ("All passed — accepts a valid v1 log, catches interior tampering, rejects "
                  "cleanly, and the anchor catches tail-truncation." if ok else "Some cases FAILED."))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
