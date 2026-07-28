# The Swasena Sovereign Tamper-Evident Log

**Technical Specification — Version 1 (v1)**

Intended status: Informational / Standards-track candidate
Style: IETF Internet-Draft / IACR ePrint
Reference implementation: `swasena_verify.py` (this repository)

---

## Abstract

This document specifies the **Swasena Sovereign Log**, an append-only,
tamper-evident audit record produced locally on a user's own infrastructure.
Every record is a single-line JSON object that commits, via a **full 256-bit
SHA-256 hash chain**, to the entire prefix of records that precede it. Given the
log file **alone** — with no network access and no producer-supplied code — any
party, in any programming language, can recompute the chain and detect **any
interior** modification, deletion, insertion, or reordering of a past record,
and localize the first inconsistency.

The format is standardized and singular. Every record carries the version tag
`"v": 1` and is committed by the full SHA-256 digest (64 lowercase hexadecimal
characters). Canonicalization is **RFC 8785 (JSON Canonicalization Scheme, JCS)**
[RFC8785] **plus NFC Unicode normalization** applied to all string keys and
values before serialization. RFC 8785 itself does **not** perform Unicode
normalization; NFC is an addition of this profile. Consequently, a conforming
RFC 8785 canonicalizer, in any language, reproduces the committed bytes exactly
**only if it also applies NFC first**. Each chain link is domain-separated from
its predecessor by a single reserved `0x00` byte. Together these make v1
reproducible byte-for-byte across independent implementations that follow this
profile (JCS + NFC).

This is self-consistency verification. Unlike Certificate Transparency, the
file-alone Verifier does **not** by itself hold the producer accountable against
tail-truncation, total erasure, or a genesis rewrite — those require the
external `(head, count)` anchor specified herein, or the forward-secure seal
described as a future hardening path. This document defines the on-disk record
format, the canonicalization rule, the chain rule, the verification algorithm, a
set of **falsifiable** claims with their explicit refutation conditions, and an
honest account of the construction's limitations.

The design deliberately mirrors the self-verification pattern of **Certificate
Transparency** [RFC6962]: adoption is expected to follow from independent
re-verification, not from any request.

---

## 1. Terminology and Conventions

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**,
**SHOULD**, **SHOULD NOT**, **RECOMMENDED**, **MAY**, and **OPTIONAL** in this
document are to be interpreted as described in [RFC2119].

- **Producer**: the component that appends records to the log. This
  specification places no requirement on the Producer's internals; only the log
  format and chain rule are normative.
- **Verifier**: an independent program that recomputes the chain and reports
  intact/broken (`swasena_verify.py`). The Verifier **MUST NOT** depend on the
  Producer's code or on any network resource.
- **Record** (interchangeably **entry**): one JSON object serialized on a single
  line of the log file.
- **Log**: a UTF-8 text file in JSON Lines format (`.jsonl`) — one Record per
  line, appended in production order. Blank lines carry no semantic weight and
  are ignored by the Verifier.
- **Chain link** (`chain`): the SHA-256 digest committing a Record to its
  prefix, as 64 lowercase hexadecimal characters.
- **Genesis**: the first Record in a log; its predecessor link is the empty
  string `""`.
- **canonical(R)**: the canonical serialization (Section 4) of Record `R` with
  its own `chain` field removed.
- **Raw value**: a value that must not be written to the log. The
  Producer **MUST NOT** write any raw value into the log; only counts and
  placeholder previews are permitted (Section 3).

Byte lengths are given in bytes; hash outputs are described in bytes and in
hexadecimal characters (2 hex chars = 1 byte).

---

## 2. Overview and Scope

For each logged event, the Producer appends **one** Record to a local audit
log. That log is the subject of this specification.

This document specifies **integrity** of the log: that the ordered sequence of
records, as presented, has not been silently edited, reordered, or had records
inserted or deleted in its interior. (Truncation of the most recent records is
detected only with an external anchor — see Section 8.) It does **not**, on its
own, specify or prove which raw values did or did not leave the device; that is a
separate property (Claim C2, Section 7.2), out of scope for the Verifier defined
here and evaluated on its own terms.

The construction is intentionally minimal: standard-library SHA-256, an
internationally standardized JSON canonicalization (RFC 8785, plus NFC
normalization — see Section 4), and a linear scan. Simplicity is a security
property here — the Verifier is auditable by inspection.

---

## 3. Record Format

Each Record is a JSON object serialized on a single line. In v1 a Record
**MUST** contain the version tag `"v": 1` and the fields below. The Verifier
treats **all** present fields except `chain` as chain-committed (Section 4).

| Field | Type | Semantics | Constraint |
|---|---|---|---|
| `v` | integer | Format version. | REQUIRED. **MUST** equal the integer `1`. A Record whose version is not `1` is **REJECTED** (`bad_version`). |
| `ts` | integer | Unix epoch seconds at append time. | REQUIRED. Integer, not float. |
| `action` | string | An opaque event/label string (e.g. `"<label>"`). Opaque to the Verifier. | REQUIRED. |
| `category` | string | An opaque free-form reason code (e.g. `"<reason>"` or `-`), ignored by the Verifier. | REQUIRED. MAY be `-` when not applicable. |
| `secrets_kept_local` | integer | A non-negative integer count of redacted values for this event — a **count only**, never a raw value. | REQUIRED. MUST NOT be a raw value. |
| `obfuscated_preview` | string | A preview of the event, truncated. Contains only placeholder tokens (e.g. `<<ENTITY_1>>`, `<<ENTITY_2>>`), never raw values. | REQUIRED. At most 120 characters. |
| `chain` | string | The chain link for this Record (Section 5). 64 lowercase hexadecimal characters. | REQUIRED. Excluded from `canonical()`. |

**Version tag (normative).** `v` is the profile discriminator. A conforming
Verifier **MUST** reject any Record whose `v` is absent or not equal to the
integer `1` with reason `bad_version`, so that Producers and Verifiers of a
different profile never silently cross-verify.

**Privacy invariant (normative).** The Producer **MUST NOT** place any raw
value into any field. `obfuscated_preview` **MUST** contain only placeholder
tokens, never raw values. `secrets_kept_local` **MUST** be a count. A
conforming Producer that emits a raw value violates this specification
independently of any chain property.

**Extensibility.** Because the chain commits to `canonical(R)` over *all*
non-`chain` fields, any additional field a future profile introduces is
automatically covered by the integrity guarantee. Any change that alters
committed bytes **MUST** be introduced under a new value of `v`.

### 3.1 Reference record

This is the first line of `test_vectors/valid.jsonl`, verbatim, including its
correct 64-hex genesis chain link:

```json
{"ts": 1785000000, "action": "event", "category": "-", "secrets_kept_local": 2, "obfuscated_preview": "a message mentioning <<ENTITY_1>> and <<ENTITY_2>>", "v": 1, "chain": "b4e53f2cd667dbc0991ce01ef39642b65a0b4354235e9560288bd0e9578ce8ab"}
```

The `chain` value is the full 256-bit SHA-256 digest (64 hexadecimal
characters). The on-disk field order shown above is not significant: the
canonical form (Section 4) sorts keys, so link computation is independent of the
order in which fields are written to the file.

---

## 4. Canonicalization

To make chain links reproducible across independent implementations and
languages, a Record is reduced to a **canonical byte string** before hashing.
v1 adopts **RFC 8785, the JSON Canonicalization Scheme (JCS)** [RFC8785], on top
of JSON [RFC8259], **plus NFC Unicode normalization** applied to all string keys
and values before JCS serialization. NFC is an addition of this profile: RFC 8785
itself does **not** perform Unicode normalization.

**canonical(R)** is defined as:

1. Remove the field named `chain` from the object (if present).
2. Normalize every remaining string — both object keys and string values,
   recursively — to Unicode **NFC**.
3. Serialize the result as RFC 8785 canonical JSON: keys sorted by Unicode code
   point (ascending) — which, for the BMP-only keys this profile permits, is
   identical to RFC 8785's UTF-16 code-unit order (see (d)) — **no** insignificant
   whitespace (separators are exactly `,` and `:`, with no spaces), non-ASCII
   emitted literally as UTF-8, and the text encoded as **UTF-8**.

For this record profile — integers only, and keys within the Basic Multilingual
Plane — the result is exactly the output of any conforming RFC 8785 library
**provided that library is fed NFC-normalized input (or applies NFC itself)**.
RFC 8785 alone does not normalize, so a JCS canonicalizer reproduces the links
byte-for-byte only when NFC is applied first. Given that one addition, v1
canonicalization is reproducible in any language without a bespoke serializer.

In the reference implementation this is:

```python
r = _nfc({k: v for k, v in R.items() if k != "chain"})
json.dumps(r, ensure_ascii=False, sort_keys=True,
           separators=(",", ":"), allow_nan=False).encode("utf-8")
```

**Cross-language conformance (normative).** An independent implementation
**MUST** reproduce this byte string exactly. The following sub-rules fully
determine the bytes:

- **(a) Numbers — integers only.** Every number **MUST** be an **integer** within
  the inclusive range `[-(2^53 − 1), 2^53 − 1]`. Floats, exponent/scientific
  forms that denote non-integers (e.g. `3.14`), and non-finite values (`NaN`,
  `Infinity`, `-Infinity`, and overflow literals such as `1e400` that parse to
  `Infinity`) are **PROHIBITED**. This is **enforced by the Verifier**: a Record
  carrying any such value is **rejected** (`bad_json`), not merely canonicalized
  differently. Integers are emitted without quotes and without added precision.
- **(b) Unicode — NFC.** All string keys and values **MUST** be normalized to
  **NFC** before serialization. This closes the NFC↔NFD divergence in which two
  inputs differing only in normalization form would otherwise produce different
  links. Non-ASCII text is emitted literally as UTF-8 (not `\u`-escaped); an
  implementation that `\u`-escapes non-ASCII would compute different links and
  spuriously report tampering.
- **(c) String escaping.** Apply the **minimal** RFC 8259 escape set only
  (`\"`, `\\`, `\b`, `\f`, `\n`, `\r`, `\t`, and `\uXXXX` for other control
  characters), with `\uXXXX` in **lowercase** hex. The forward slash `/` is left
  **UNescaped**. No `NaN`/`Infinity` output is ever emitted (`allow_nan=False`).
- **(d) Key order.** Object keys are sorted by **Unicode code point** ascending,
  as the reference implementation does. Note that RFC 8785 §3.2.3 specifies
  sorting by **UTF-16 code units**, not by code point; this profile sorts by code
  point. For the **Basic-Multilingual-Plane (BMP) keys this profile permits**,
  code-point order is **identical to** RFC 8785's UTF-16 code-unit order — the two
  diverge only for astral (supplementary, `> U+FFFF`) keys. Because this profile
  does not use astral keys, all object keys **MUST** lie within the BMP
  (`≤ U+FFFF`); under that restriction, sorting by code point yields exactly the
  RFC 8785 ordering. An implementation **MUST** sort by Unicode code point (which,
  given the BMP restriction, coincides with RFC 8785's UTF-16 code-unit order).
- **(e) Duplicate keys.** A record line containing a duplicate object key
  (including within nested objects) is **rejected** (`bad_json`); it never
  reaches canonicalization. Two keys that are **NFC-equivalent** (byte-distinct
  but equal after NFC normalization, e.g. `U+00C5` and `U+0041 U+030A`) are
  likewise **rejected** as duplicates: because canonicalization NFC-normalizes
  keys, they would otherwise collapse to one entry, silently dropping a value and
  letting divergent records share a chain link.

The object is serialized **flat**, in sorted-key order, with no trailing newline
inside `canonical(R)` (the newline separating log lines is **not** part of any
Record).

Implementations **SHOULD** validate against the published test vectors
(Section 9) byte-for-byte before claiming conformance.

---

## 5. Chain Rule

Let `R_0, R_1, ..., R_{n-1}` be the Records in log order. Define the predecessor
link `prev_i`:

```
prev_0   = ""                       (genesis: empty string)
prev_i   = chain_{i-1}   for i > 0
```

The chain link of Record `R_i` is the **full 256-bit** SHA-256 digest:

```
chain_i = HEX( SHA256( UTF8(prev_i)  ||  0x00  ||  canonical(R_i) ) )
```

where:

- `||` denotes byte concatenation;
- `UTF8(prev_i)` is the predecessor link string encoded as UTF-8 (for genesis,
  the empty byte string);
- `0x00` is a **single reserved domain-separator byte** placed between the
  previous link and the record;
- `canonical(R_i)` is the UTF-8 canonical byte string of Section 4;
- `HEX(...)` is lowercase hexadecimal of the full 32-byte digest — **64
  hexadecimal characters (256 bits)**, not truncated.

The reserved `0x00` byte is an explicit domain separator: it makes the boundary
between `prev` and the record unambiguous regardless of how the record fields
evolve. Because a chain link is either empty or 64 hex characters (none of which
is `0x00`) and `canonical(R_i)` always begins with `{`, the separator can never
be confused with data on either side.

The reference implementation computes exactly:

```python
chain = hashlib.sha256((prev + "\x00" + canonical(rec)).encode("utf-8")).hexdigest()
```

---

## 6. Verification Algorithm

A Verifier **MUST** implement the following. It reads the log file only; it
opens no socket and loads no Producer code. The order of checks below matches
`swasena_verify.py`.

```
INPUT:  path to a JSONL log file; OPTIONAL --expect-head H, --expect-count N
OUTPUT: {ok: bool, ...} and process exit code (0 intact, 1 rejected, 2 error)

1.  prev := ""            # genesis predecessor
    n    := 0             # verified record count
2.  For each line, in file order, at zero-based index i:
      a. Strip surrounding whitespace. If empty, skip (blank lines ignored).
      b. Parse the line as JSON, strictly:
           - reject NaN/Infinity constants;
           - reject non-integer numbers (floats);
           - reject integers with magnitude > 2^53 − 1;
           - reject duplicate object keys (including nested).
         On any parse failure -> REJECT {reason: "bad_json", index: i}.
      c. If the parsed value is not a JSON object
         -> REJECT {reason: "not_object", index: i}.
      d. If record["v"] != 1 (absent or any other value)
         -> REJECT {reason: "bad_version", index: i}.
      e. If the object has no "chain" field
         -> REJECT {reason: "missing_chain", index: i}.
      f. expected := HEX(SHA256( UTF8(prev) || 0x00 || canonical(record) ))
      g. If expected != record["chain"]
         -> REJECT {reason: "chain_mismatch", index: i,
                    expected, found: record["chain"]}.
      h. prev := record["chain"]   # advance the chain
         n    := n + 1
3.  If n == 0 -> REJECT {reason: "empty_log", records: 0}.
4.  If --expect-count N was given and n != N
         -> REJECT {reason: "count_mismatch", records: n, ...}.
5.  If --expect-head H was given and prev != H
         -> REJECT {reason: "head_mismatch", head: prev, ...}.
6.  ACCEPT {ok: true, records: n, head: prev, anchored: ...}.
```

Notes:

- **First-break localization.** The algorithm stops at and reports the **first**
  inconsistent index, which pinpoints the earliest edit or insert. A deletion or
  reordering that leaves at least one later record shifts every subsequent
  `prev` and is detected at the first affected position. Deletion of the trailing
  record(s) leaves no later `prev` to disturb and is **not** detected from the
  file alone (see Section 8).
- **Head commitment.** On success the returned `head` (the final `chain`) is a
  commitment to the **entire** log. An auditor who records `head` at time `T` can
  later detect any change to any record produced at or before `T` by re-deriving
  `head`.
- **Fail-closed input validity.** The strict parse and the empty-log rejection
  make the Verifier strictly *stricter*, never more permissive, than the bare
  chain walk. A well-formed log is a non-empty sequence of JSON **objects**, each
  tagged `"v": 1`, obeying the canonical number rule (Section 4a) and free of
  duplicate keys (Section 4e).
- **Verifier scope vs. producer MUSTs.** The Verifier enforces the presence and
  validity of `v` (`= 1`) and `chain`, together with the canonical-number
  (Section 4a) and duplicate-key (Section 4e) rules; it does **not** enforce the
  presence of the other REQUIRED fields (`ts`, `action`, `category`,
  `secrets_kept_local`, `obfuscated_preview`) or the ≤120-character/privacy
  invariant — those are producer-side **MUSTs** (Section 3) outside the Verifier's
  integrity check. A record carrying only `v` and a correct `chain` therefore
  verifies as self-consistent; the integrity guarantee is about the chain, not
  schema completeness.

A conforming Verifier **MUST** reject a log that the normative algorithm rejects,
and **MUST** accept a log it accepts, for the same input bytes.

---

## 7. Claims (Falsifiable)

Each claim is stated with an explicit **refutation condition**: a concrete
experiment a competent adversary can run to disprove it. A claim that cannot be
refuted by experiment is a slogan and is excluded.

### 7.1 C1 — Append-only integrity (proven by this document)

> Given the log file **alone**, any party can recompute the chain and detect
> **any** interior modification, insertion, reordering, or deletion of a Record,
> and the first broken link localizes where.

**Out of the file-alone scope of C1.** Three tamper classes are **not** caught
by the file-alone Verifier and are therefore explicitly excluded from C1:
tail-truncation/rollback of the most recent records, total erasure of the log,
and a history rewritten from genesis. These are addressed by the **external
anchor** (recorded `head` + `count`, Section 8) and, prospectively, the
**forward-secure seal** (Section 7.3), not by recomputation of this file alone.

**Refutation.** Present a log with an **interior** tamper (a modified, inserted,
reordered, or interior-deleted record) that is nonetheless reported **INTACT**
(exit 0) by the normative Verifier; or exhibit two divergent logs sharing a
`head` that the Verifier does not distinguish. Any such instance falsifies C1.

**Basis.** SHA-256 preimage/second-preimage resistance plus the prefix
commitment of Section 5: altering `R_j` changes `canonical(R_j)`, hence
`chain_j`, hence `prev_{j+1}`, cascading to every later link, so the mismatch
surfaces at index `j`. With full 256-bit links, targeted second-preimage effort
is ≈ `2^256` (infeasible), and chance collision across any realistic log size is
negligible.

### 7.2 C2 — Non-disclosure of raw values (separate property; not proven here)

> C2 is the separate property of which raw values did or did not leave the
> device; it is out of scope for this Verifier and is evaluated on its own terms.

**Scope note (normative honesty).** C2 is **NOT** established by the log or the
Verifier in this document. The log records *counts* and *placeholder previews*
only; it is evidence *consistent with* C2 but is not a proof of C2. C2 is a
separate property and must be evaluated on its own terms. This specification
claims C1; it explicitly does **not** claim that C1 implies C2.

### 7.3 Forward-Secure Seal (future hardening; not yet claimed)

The current construction detects tampering by *any external party* but does not
by itself stop the log's **own owner** from discarding the entire log and
re-hashing a fully rewritten history from genesis (all links are recomputable
from record contents alone, using no secret key). A future mitigation is a
**forward-secure seal**: a one-way hash ratchet in which each append also
advances a sealing key `k_i = SHA256(domain || k_{i-1})` and the previous key
`k_{i-1}` is destroyed, with each Record additionally committing to (or MAC'd
under) the current key. Once `k_{i-1}` is erased, even the owner cannot recompute
a consistent seal for a rewritten prefix. An external anchor (periodic
publication of `head`, or co-signing by an independent witness, per the
Certificate Transparency model [RFC6962]) achieves the same end by a different
route.

Until implemented and independently tested, this is stated as a **future**
hardening path, not a claim in force. This document specifies its shape so the
upgrade is well-defined.

---

## 8. Security Considerations and Honest Limitations

This section is normative in its honesty: the following limitations **MUST** be
disclosed alongside any statement of the claims.

### 8.1 Rewrite from genesis by any writer

Because every link is a deterministic function of record contents and the empty
genesis predecessor, **any party who can write the file — not only the owner —
can append or re-chain self-consistent records, because the rule is keyless.**
Such a party can regenerate a wholly alternative but internally-consistent
history, and the Verifier will report it as INTACT, because it *is* internally
consistent — the Verifier proves *self-consistency*, not *authenticity of
origin*. This is addressed only by the forward-secure seal (Section 7.3) or an
external witness/anchor (Section 8.4). The guarantee is precisely: **an interior
tamper cannot be made undetectable against a recorded anchor, and the log's
self-consistency is checkable against any `(head, count)` anchor previously
published.**

### 8.2 C1 does not imply C2

Restated because it is the most common misreading: log integrity (C1) says
nothing on its own about what data left the device (C2). Do not let a green
Verifier be read as proof about what did or did not leave the device.

### 8.3 Confidentiality of the log

Links are not secret and reveal nothing beyond record contents. Records already
exclude raw values (Section 3). The log **MAY** still reveal *metadata* (event
timing via `ts`, opaque labels, counts); deployments needing metadata
privacy **SHOULD** treat the log as sensitive at rest.

### 8.4 External anchor: the file-alone defense against truncation/rollback

The file-alone Verifier cannot, from the log bytes alone, detect
tail-truncation/rollback of the most recent records, a fully emptied log, or a
history rewritten from genesis (Sections 7.1, 8.1). The **external anchor** is
the defense: the Verifier accepts an **OPTIONAL** `--expect-head H` and
`--expect-count N`, and when supplied it verifies that the recomputed `head`
equals `H` and the verified record count equals `N`.

**`--expect-head` is the real defense; `--expect-count` alone is
near-worthless.** `--expect-head` binds the entire history to a single
commitment: any change to any record at or before the anchored point alters
`head` and is caught. `--expect-count` alone is **not** a meaningful defense — an
adversary who rewrites the log to a *different* history with the **same record
count** passes a count-only check. Auditors **MUST** record and check `head`;
`count` is at best a corroborating signal, never a substitute.

**Freshness limitation (an anchor proves the past, not the present).** An anchor
proves that a past state *existed* at the time it was recorded; it does **not**
prove that the presented log is *current*. Records appended **after** the most
recent recorded anchor can be discarded and the log rolled back to the anchored
`(head, count)` state **undetectably** — that older state still matches the older
anchor. To bound this, an auditor **MUST** use the **latest** recorded anchor
(not an arbitrary earlier one) and **MUST** verify that the present count does
not regress: `count_now ≥ count_last`. This detects rollback to any state older
than the newest anchor but cannot detect loss of records appended since that
newest anchor; the anchoring interval bounds the maximum silently
rollback-able tail. Auditors **SHOULD** record `(head, count)` out-of-band at
each checkpoint, as frequently as the freshness requirement demands, and pass
the latest pair on re-verification.

### 8.5 Producer trust boundary and availability

A denial-of-logging (records silently not written) is **out of C1's scope**,
which concerns records that *are* present. The Verifier parses untrusted input;
it **MUST** treat malformed lines as rejection or skip-blank only, and **MUST
NOT** execute log content. The reference Verifier uses the JSON parser and
standard hashing only.

---

## 9. Test Vectors

Reference vectors live in `test_vectors/` (JSON Lines, one Record per line).
They are the byte-for-byte conformance target: any independent implementation
**MUST** accept the positive vector and **MUST** reject each negative vector with
the indicated reason code.

| File | Expected verdict | Reason code / note |
|---|---|---|
| `valid.jsonl` | **INTACT** (exit 0) | Self-consistent; 4 records; `head = 53d4072948f201db646862f16dfe1fa3296744b33efb077628352a7acbf5ade1`. |
| `tampered_edit.jsonl` | **REJECTED** (exit 1) | `chain_mismatch` at the edited index — a past record's content was altered. |
| `tampered_delete.jsonl` | **REJECTED** (exit 1) | `chain_mismatch` — an interior record was removed; chain break at the gap. |
| `tampered_insert.jsonl` | **REJECTED** (exit 1) | `chain_mismatch` — a forged record was inserted. |
| `tampered_truncate.jsonl` | **INTACT alone**; **REJECTED** with anchor | Self-consistent from the file alone (tail records removed leave no later `prev` to disturb); caught **only** with `--expect-head` (`head_mismatch`). See Sections 8.1, 8.4. |
| `tampered_dupkey.jsonl` | **REJECTED** (exit 1) | `bad_json`: duplicate object key (including nested). |
| `tampered_empty.jsonl` | **REJECTED** (exit 1) | `empty_log`: a zero-record file. |
| `tampered_nan.jsonl` | **REJECTED** (exit 1) | `bad_json`: `NaN` constant (non-finite). |
| `tampered_infinity.jsonl` | **REJECTED** (exit 1) | `bad_json`: overflow literal (`1e400`) parsing to `Infinity`. |
| `tampered_float.jsonl` | **REJECTED** (exit 1) | `bad_json`: non-integer (float) value. |
| `tampered_bigint.jsonl` | **REJECTED** (exit 1) | `bad_json`: integer magnitude out of range (`> 2^53 − 1`). |
| `tampered_nonobject.jsonl` | **REJECTED** (exit 1) | `not_object`: a JSON array/scalar line, not an object. |
| `tampered_bad_version.jsonl` | **REJECTED** (exit 1) | `bad_version`: a record whose `v` is not `1` (here, absent). |
| `tampered_astral_key.jsonl` | **REJECTED** (exit 1) | `bad_json`: a non-BMP object key (`> U+FFFF`); see Section 4d. |
| `tampered_deepnest.jsonl` | **REJECTED** (exit 1) | `bad_json`: pathologically nested JSON, rejected cleanly with no traceback; see Section 8.5. |
| `tampered_nfc_collision.jsonl` | **REJECTED** (exit 1) | `bad_json`: two NFC-equivalent object keys; see Section 4e. |

Regeneration and self-check: `python3 test_verify.py` (deterministic). New
vectors **SHOULD** be added as the format evolves, and each **MUST** be committed
with its expected verdict and, for negatives, the expected failing index and
reason code.

**Vector format.** Each vector is exactly the Record format of Section 3, one
JSON object per line, UTF-8, no trailing spaces. The chain-break negatives are
produced by taking a valid log and applying exactly one tamper operation (edit /
delete / insert) **without** recomputing downstream links. This models
accidental corruption or a naive edit. A motivated tamperer who knows this
public, keyless rule **CAN** recompute all downstream links and produce a
self-consistent forged log; that class of tamper is caught only by comparing
against an externally-recorded `(head, count)` anchor or by the future
forward-secure seal — **not** by this file-alone Verifier.

---

## 10. Precedent

The self-verification pattern here follows the same lineage that carried
**Certificate Transparency** [RFC6962] into deployment: an append-only,
tamper-evident log whose logic is independently checkable by recomputation. CT
was adopted because that logic was independently checkable, not because anyone
lobbied for it. This specification adopts that stance deliberately: publish the
format, the Verifier, and the vectors, and let independent re-verification — not
a request — drive adoption.

**Honest contrast (do not overclaim).** Unlike Certificate Transparency, this
format has **no** signed tree heads, **no** gossip, and **no** witness. Until an
external anchor (Section 8.4) or the forward-secure seal (Section 7.3) is in
place, it does **not** provide CT's integrity guarantee **against the operator**;
it re-verifies **self-consistency**. CT-style operator-accountability is a named,
future upgrade, not a property already in force.

The mental model of "transparent logs for skeptical clients" (Merkle-tree logs
with inclusion/consistency proofs) is the natural evolution path for this
construction; the present hash-*chain* is the linear special case, upgradable to
a Merkle *tree* to gain sublinear consistency proofs.

---

## 11. IANA Considerations

This document has no IANA actions in its current form. Should the format be
standardized, a registry for the `action` and `category` reason codes **SHOULD**
be requested. No new media type is registered here; the log uses
`application/jsonl` (or `application/x-ndjson`) by convention.

---

## 12. Standards Path (Informational)

A candidate route, entered as a contributor of proof, not a petitioner:

1. **IACR ePrint** deposit of this specification + Verifier + vectors, to
   timestamp priority.
2. Peer-reviewed venues with artifact evaluation (NDSS / USENIX Security /
   PoPETs) — the open Verifier and byte-exact vectors are the artifact.
3. **Real World Crypto** contributed talk — protocol/standards practitioners.
4. **IETF Individual Internet-Draft**, e.g.
   `draft-<lastname>-sovereign-tamper-evident-log-00`, submittable by any
   individual via the Datatracker — the same trajectory CT followed to become
   [RFC6962].
5. **NIST** privacy-engineering / PETs testbed as an independent test case.

Genuine follow-ups still open: publishing an externally-hosted, byte-exact
vector set (including a non-ASCII key vector) alongside the acceptance and
rejection boundaries; and specifying and independently testing the
forward-secure seal (Section 7.3). For scale, an optional Merkle-tree profile
providing logarithmic inclusion and consistency proofs in the [RFC6962] style is
a natural extension.

---

## 13. References

### 13.1 Normative

- [RFC2119] Bradner, S., "Key words for use in RFCs to Indicate Requirement
  Levels", BCP 14, RFC 2119, March 1997.
- [RFC8259] Bray, T., Ed., "The JavaScript Object Notation (JSON) Data
  Interchange Format", STD 90, RFC 8259, December 2017.
- [RFC8785] Rundgren, A., Jordan, B., Erdtman, S., "JSON Canonicalization Scheme
  (JCS)", RFC 8785, June 2020.

### 13.2 Informative

- [RFC6962] Laurie, B., Langley, A., Kasper, E., "Certificate Transparency",
  RFC 6962, June 2013.
- Swasena reference implementation (this repository): `swasena_verify.py`,
  `README.md`, and the public test vectors.

---

*Only proven claims are asserted here. Stated limits are stated on purpose — they
are the differentiator, not a footnote. Verify it yourself; do not trust us.*
