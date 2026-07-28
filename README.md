# Swasena Sovereign Log — Independent Verifier

**Verify it yourself — don't trust us.**

A self-contained tool and open specification for a **tamper-evident**, append-only sovereign
audit log. It re-verifies a log **without any network and without any Swasena code** — Python
standard library only, deterministic, and reproducible **in any language** because
canonicalization is the international standard **RFC 8785 (JSON Canonicalization Scheme)**.

Every claim below is **falsifiable**, and was **adversarially red-teamed before release** — we
narrowed our own wording where the attacks were right, and we state the limits first. That is the
confidence on offer: not that nothing can be questioned, but that **everything can be checked**.

> **Wording, on purpose:** this is *tamper-**evident*** (it makes tampering **detectable**), not
> *tamper-**proof*** (it does not **prevent** tampering). "Deterministic" describes the verifier
> (no randomness), not a promise to catch every possible tamper — see Limits.

---

### Run
```
python3 swasena_verify.py <audit.jsonl> [--expect-head H] [--expect-count N]
# exit 0 = self-consistent · 1 = tampering-rejected · 2 = usage/read error
```
`--expect-head` supplies an **external anchor** you recorded earlier; without it the file-alone
check cannot detect tail-truncation or a rewritten history (see Limits). `--expect-count` alone
is weak (a full rewrite keeping the same count still passes) — always anchor with `--expect-head`.

### Chain rule
```
chain_i = sha256( chain_{i-1}  ||  0x00  ||  canon(record_i without "chain") )    # full 256-bit, 64 hex
chain_0 uses prev = ""    (genesis)
canon = RFC 8785 (JCS) — keys sorted, no spaces, integers only — PLUS NFC normalization
        of all strings (NFC is not part of RFC 8785; see "Reproducing it in another language").
```
Each record carries `"v": 1`. A single reserved `0x00` byte separates the previous link from the
record; the **full 256-bit** digest is committed. The verifier commits to the **parsed record
content** (canonical, NFC-normalized), not the raw bytes, and **rejects**: duplicate JSON keys;
`NaN`/`Infinity`; non-canonical numbers (floats, overflow like `1e400`, integers outside
`[-(2^53-1), 2^53-1]`); and any record whose version is not `1`.

### Reproducing it in another language
Canonicalization is **RFC 8785 (JCS) plus one addition: NFC Unicode normalization**, applied to
all string keys and values before serializing. RFC 8785 does **not** normalize, so a plain JCS
library reproduces the links byte-for-byte **only if it also NFC-normalizes first** (`unicodedata.
normalize("NFC", …)` or your language's equivalent). Two more rules to respect:
- **Records carry integers only**, so decode numbers as integers (e.g. Go `json.Number`), never as
  floats — a float decoder would re-serialize `1785000000` as `1.785e+09` and wrongly report tamper.
- Keys are sorted **by Unicode code point**; this equals RFC 8785's UTF-16 code-unit order for the
  Basic-Multilingual-Plane keys this profile uses (they diverge only for astral (> U+FFFF) keys,
  which the format does not use).

### Claim C1 (falsifiable)
Given the log file alone, any party can recompute the chain and detect **any interior tamper —
modification, insertion, reordering, or deletion — of a record** (one that leaves at least one
later record). The first broken link pinpoints where. **Falsified** if such an interior tamper
ever verifies as self-consistent **while preserving the log's head** (or while passing a recorded
`(head, count)` anchor) — see §7.1 and the Challenge. Re-chaining forward changes the head, which
the anchor catches; that is the disclosed keyless limit, not a falsification.

Tail-truncation, a fully emptied log, and a history rewritten from genesis are **out of C1's
file-alone scope** — addressed by the anchor and by a separate forward-secure seal (see Limits).
An earlier draft said "detect **any** deletion"; a pre-publish red team showed that overstated the
tail cases, so we narrowed it. That correction is the point of publishing.

### Public test vectors (`test_vectors/`)
| File | Expected |
|---|---|
| `valid.jsonl` | **SELF-CONSISTENT** (exit 0); with correct `--expect-head/--expect-count` also anchored |
| `tampered_edit.jsonl` | **REJECTED** (a record's content was altered) |
| `tampered_delete.jsonl` | **REJECTED** (an interior record was removed) |
| `tampered_insert.jsonl` | **REJECTED** (a forged record was inserted) |
| `tampered_truncate.jsonl` | exit 0 **alone** (a valid prefix), **REJECTED** with `--expect-head` |
| `tampered_dupkey.jsonl` | **REJECTED** (duplicate JSON keys) |
| `tampered_empty.jsonl` | **REJECTED** (empty / fully-erased log) |
| `tampered_nan.jsonl` | **REJECTED** (`NaN` is not valid JSON) |
| `tampered_infinity.jsonl` | **REJECTED** (`1e400` overflow → `Infinity`) |
| `tampered_float.jsonl` | **REJECTED** (float — not cross-language reproducible) |
| `tampered_bigint.jsonl` | **REJECTED** (integer > 2^53 — loses precision in JS/Go) |
| `tampered_nonobject.jsonl` | **REJECTED** cleanly (a non-object line — no crash) |
| `tampered_bad_version.jsonl` | **REJECTED** (missing / unknown profile version) |
| `tampered_astral_key.jsonl` | **REJECTED** (a non-BMP object key) |
| `tampered_deepnest.jsonl` | **REJECTED** cleanly (pathologically nested JSON — no crash) |
| `tampered_nfc_collision.jsonl` | **REJECTED** (two NFC-equivalent object keys) |
| `tampered_bool_version.jsonl` | **REJECTED** (`"v": true` — the JSON boolean, not the integer 1) |
| `tampered_chain_type.jsonl` | **REJECTED** (`chain` is not a string) |

Reproduce + regenerate: `python3 test_verify.py` (deterministic — regenerates every vector and
asserts the expected exit codes).

### Honest limits
- **Tamper-evident, not tamper-proof.** It makes tampering detectable; it does not prevent it.
- **Tail-truncation / rollback / empty-out are not caught from the file alone.** A forward hash
  chain leaves every prefix valid. Detecting that requires an **external anchor** (`--expect-head`,
  the RFC 6962 witness idea). An empty log is **rejected**. `--expect-count` alone is near-worthless.
- **The anchor proves the past, not freshness.** A recorded `(head, count)` stays a valid witness
  for its checkpoint forever, so an attacker can roll back to **any previously anchored state** and
  pass that state's old anchor. Records appended after your most recent anchor can be rolled back
  undetectably. Anchor as close to real time as your threat model needs; verify `count_now ≥ count_last`.
- **No secret key ⇒ no proof of origin.** Any party who can write the file and knows this public
  rule can re-chain forged records. The verifier proves **self-consistency**, not **authenticity** —
  that is the job of a separate **forward-secure seal** (a hash ratchet that erases each key) or an
  external witness.
- **Separate claim C2.** This proves append-only integrity of the log **as presented**. It does
  **not** by itself prove which raw values did or did not leave the device (claim C2, out of scope).

### Precedent
This follows the **self-verification stance** of **RFC 6962 (Certificate Transparency)** — adopted
because anyone re-verifies it, not by anyone's request. **Unlike CT**, this profile has **no signed
tree heads, no gossip, and no witness** yet, so — until the forward-secure seal or an external
anchor is in place — it does **not** by itself hold the operator accountable. It re-verifies
self-consistency; CT-style operator-accountability is a named, planned upgrade.

### Anteriority
Each release is timestamped with **OpenTimestamps** (see [ANTERIORITY.md](ANTERIORITY.md)) so you
can confirm our priority without trusting us — the same stance as the verifier itself.

### Challenge
Think you can modify an **interior** record and still produce a log this verifier calls
self-consistent **with the same head** — or one that passes a `(head, count)` anchor you did not
choose? That would falsify C1 (§7.1). Note what does **not** count, because we disclose it as a
limit: simply re-chaining from your edit forward yields a **different head**, which any recorded
`--expect-head` anchor catches — that is the keyless-chain limit, not a break. We publish the
vectors and the code precisely so the real claim can be tested — openly, limits stated first.

_Only proven claims are published here; limits are stated first, on purpose — honesty is the
differentiator, not a footnote._
