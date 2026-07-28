# Anteriority — verify our priority yourself

We timestamp every release so its existence at a given date is provable by a third
party, without trusting us — the same stance as the verifier itself.

## What is committed
`MANIFEST.sha256` lists the SHA-256 of every published file. `MANIFEST.sha256.ots`
is an [OpenTimestamps](https://opentimestamps.org) proof over the manifest's hash.

OpenTimestamps is two-stage, and this proof is honest about which stage it is in:

1. **At publish time — a calendar commitment (pending).** The `.ots` carries
   attestations from independent calendar servers that have committed to include the
   hash in an upcoming Bitcoin block. This already fixes the content and the calendars'
   commitment; it is **not yet** a Bitcoin-block proof.
2. **After a few hours — a Bitcoin anchor.** Running `ots upgrade` attaches the
   `BitcoinBlockHeaderAttestation`, after which the proof stands entirely on the Bitcoin
   blockchain, needing neither the calendars nor us: **these exact bytes existed at or
   before that block's time.**

## Verify it (no trust in us required)
```
# 1) the manifest matches the files you have
shasum -a 256 -c MANIFEST.sha256

# 2) upgrade the proof to its Bitcoin anchor, then verify against a block
pip install opentimestamps-client
ots upgrade MANIFEST.sha256.ots     # attaches the Bitcoin attestation once mined
ots verify  MANIFEST.sha256.ots     # verifies against a Bitcoin block
ots info    MANIFEST.sha256.ots     # shows the attestations present
```
Until upgraded, `ots verify` reports the proof as **pending** — expected and correct for
a freshly published release, not a failure.

## Why
A global standard earns trust by being checkable, not by being asserted. Our priority,
like our integrity claim, is something you can confirm independently.
