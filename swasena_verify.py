#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Swasena Sovereign Log — Independent Verifier (v1, standardized profile)
======================================================================
Re-verifies a tamper-EVIDENT, append-only audit log WITHOUT trusting Swasena:
no network, no Swasena code, Python standard library only. Deterministic and
reproducible: the same file yields the same verdict for every auditor, in any
language, because canonicalization is the international standard RFC 8785 (JCS).

Each record carries "v": 1 and is committed by a full 256-bit chain link:

    chain_i = sha256( chain_{i-1}  ||  0x00  ||  JCS(record_i without "chain") )   # 64 lowercase hex
    chain_0 uses prev = ""                                                          # genesis
    JCS = RFC 8785 canonical JSON: keys sorted, no spaces, NFC-normalized, integers only.
    A single reserved 0x00 byte separates the previous link from the record.

CANONICAL NUMBER RULE: records carry INTEGERS ONLY, each within [-(2^53-1), 2^53-1].
Floats, non-finite values (NaN/Infinity, incl. overflow literals like 1e400), and
out-of-range integers are REJECTED — they do not round-trip identically across JSON
libraries. Duplicate keys are REJECTED. Any RFC 8785 canonicalizer, in any language,
reproduces these links byte-for-byte.

WHAT THIS PROVES (and what it does NOT) — read honestly:
  • It detects any INTERIOR tamper — modification, insertion, reordering, or
    deletion of a record that leaves at least one later record: the first broken
    link pinpoints where.
  • It does NOT, from the file ALONE, detect (a) truncation/rollback of the most
    recent records, (b) a fully emptied log, or (c) a completely rewritten history
    re-hashed from genesis. A forward hash chain leaves every prefix valid and uses
    no secret key. Use an EXTERNAL ANCHOR you recorded earlier — --expect-head H
    (and optionally --expect-count N). Anchoring needs --expect-head; --expect-count
    alone proves almost nothing (a full rewrite keeping the same count still passes).
    An anchor only protects records that existed as of the anchor you compare against:
    records appended AFTER your most recent recorded anchor can be rolled back to that
    anchored state undetectably. Anchor as close to real time as your threat model needs.
  • It commits to the parsed record CONTENT (canonical JSON, NFC-normalized), not the
    raw bytes. Duplicate keys and non-canonical numbers are rejected.
  • It proves append-only self-consistency, NOT which raw values did or did not leave
    the device (separate claim C2), and NOT authenticity of origin (any party who can
    write the file and knows this public rule can re-chain forged records — that is
    what a separate forward-secure seal / an external witness defends against). Like
    Certificate Transparency, adoption is meant to follow from independent
    re-verification; unlike CT, this profile has no signed tree heads or gossip yet,
    so it does not by itself hold the operator accountable — the anchor and the seal do.

Usage:  python3 swasena_verify.py <audit.jsonl> [--expect-head H] [--expect-count N]
Exit:   0 = self-consistent (INTACT) ;  1 = tampering/rejected ;  2 = usage/read error
"""
import sys, os, json, hashlib, unicodedata

_MAX_SAFE_INT = 2 ** 53 - 1


def _reject_const(tok):
    raise ValueError("non-JSON constant: %s" % tok)


def _reject_float(s):
    raise ValueError("non-integer number: %s" % s)


def _check_int(s):
    v = int(s)
    if abs(v) > _MAX_SAFE_INT:
        raise ValueError("integer out of canonical range: %s" % s)
    return v


def _no_dupes(pairs):
    seen, nfc_seen = {}, set()
    for k, v in pairs:
        if k in seen:
            raise ValueError("duplicate key: %s" % k)
        if any(ord(c) > 0xFFFF for c in k):
            # Keys MUST lie in the BMP: code-point sort then equals RFC 8785's
            # UTF-16 order (SPEC §4d); an astral key would break cross-language links.
            raise ValueError("non-BMP key: %r" % k)
        nk = unicodedata.normalize("NFC", k)
        if nk in nfc_seen:
            # NFC-equivalent keys collapse during canonicalization (SPEC §4e). Two
            # byte-distinct-but-NFC-equal keys would silently drop one value and let
            # divergent records share a head — reject them as duplicates.
            raise ValueError("NFC-colliding key: %r" % k)
        nfc_seen.add(nk)
        seen[k] = v
    return seen


def _parse(line):
    return json.loads(line, parse_constant=_reject_const, parse_float=_reject_float,
                      parse_int=_check_int, object_pairs_hook=_no_dupes)


def _nfc(obj):
    if isinstance(obj, str):
        return unicodedata.normalize("NFC", obj)
    if isinstance(obj, dict):
        return {unicodedata.normalize("NFC", k): _nfc(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_nfc(x) for x in obj]
    return obj


def _canonical(rec):
    # RFC 8785 (JCS) for this record profile (integers only, sorted keys, no spaces),
    # after NFC normalization. Excludes the record's own 'chain' field.
    r = _nfc({k: v for k, v in rec.items() if k != "chain"})
    return json.dumps(r, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def verify(path, expect_head=None, expect_count=None):
    prev, n = "", 0
    with open(path, "r", encoding="utf-8") as f:
        for i, line in enumerate(f):
            line = line.strip()
            if not line:
                continue
            try:
                rec = _parse(line)
            except (ValueError, RecursionError) as e:
                # Malformed input (incl. pathologically nested JSON) is a clean
                # rejection, never a traceback — SPEC §8.5.
                return {"ok": False, "reason": "bad_json", "index": i, "detail": str(e)[:80]}
            if not isinstance(rec, dict):
                return {"ok": False, "reason": "not_object", "index": i}
            if rec.get("v") != 1:
                return {"ok": False, "reason": "bad_version", "index": i, "detail": repr(rec.get("v"))[:40]}
            if "chain" not in rec:
                return {"ok": False, "reason": "missing_chain", "index": i}
            try:
                expected = hashlib.sha256((prev + "\x00" + _canonical(rec)).encode("utf-8")).hexdigest()
            except (ValueError, UnicodeError, RecursionError) as e:
                # A content fault (lone surrogate) or pathologically nested value is a
                # clean rejection, not a traceback — SPEC §8.5.
                return {"ok": False, "reason": "bad_json", "index": i, "detail": str(e)[:80]}
            if expected != rec.get("chain"):
                return {"ok": False, "reason": "chain_mismatch", "index": i,
                        "expected": expected, "found": str(rec.get("chain"))[:72]}
            prev, n = rec["chain"], n + 1

    if n == 0:
        return {"ok": False, "reason": "empty_log", "records": 0}

    if expect_count is not None and n != expect_count:
        return {"ok": False, "reason": "count_mismatch", "records": n,
                "expected_count": expect_count, "head": prev}
    if expect_head is not None and prev != expect_head:
        return {"ok": False, "reason": "head_mismatch", "records": n,
                "head": prev, "expected_head": expect_head}

    anchored_head = expect_head is not None
    return {"ok": True, "records": n, "head": prev,
            "anchored": anchored_head or (expect_count is not None),
            "anchored_head": anchored_head}


def _usage():
    print("usage: python3 swasena_verify.py <audit.jsonl> [--expect-head H] [--expect-count N]",
          file=sys.stderr)
    return 2


def main():
    args = sys.argv[1:]
    path, expect_head, expect_count = None, None, None
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--expect-head":
            i += 1
            if i >= len(args):
                return _usage()
            expect_head = args[i]
        elif a == "--expect-count":
            i += 1
            if i >= len(args):
                return _usage()
            try:
                expect_count = int(args[i])
            except ValueError:
                return _usage()
        elif a.startswith("-") and a != "-":
            return _usage()
        elif path is None:
            path = a
        else:
            return _usage()
        i += 1
    if path is None:
        return _usage()
    if not os.path.isfile(path):
        print(json.dumps({"ok": False, "reason": "read_error", "detail": "not a regular file"},
                         ensure_ascii=False))
        return 2

    try:
        res = verify(path, expect_head=expect_head, expect_count=expect_count)
    except (OSError, UnicodeError) as e:
        print(json.dumps({"ok": False, "reason": "read_error", "detail": str(e)[:80]}, ensure_ascii=False))
        return 2

    print(json.dumps(res, ensure_ascii=False, indent=2, allow_nan=False))
    if res["ok"]:
        print("\n✅ SELF-CONSISTENT — %d records, chain valid (head=%s)."
              % (res["records"], res["head"]), file=sys.stderr)
        if not res.get("anchored_head"):
            if res.get("anchored"):
                print("⚠️  --expect-count without --expect-head is weak: a full rewrite keeping the "
                      "same count also passes. Anchor with --expect-head.", file=sys.stderr)
            else:
                print("ℹ️  Not anchored: proves internal consistency only. To also detect "
                      "tail-truncation/rollback, re-run with --expect-head (from a value you "
                      "recorded earlier).", file=sys.stderr)
        return 0
    print("\n⛔ REJECTED at record #%s: %s."
          % (res.get("index", "—"), res.get("reason")), file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
