---
name: deserialization
label: Unsafe deserialization (Java/PHP/Python/Ruby/.NET gadget chains, insecure formats)
triggers: [serialized-blob, base64-object, viewstate, php-serialized, pickle, java-rO0, dotnet-losformatter, cookie-object]
preconditions: []
scope: requests-only
safety: intrusive
severity_hint: critical
---

# Unsafe deserialization

## Overview
The app rebuilds a language-native object from attacker-controlled bytes (a cookie, param, header, or upload). If
the format carries type/callback metadata, a crafted graph runs code or magic methods during load. Confirmation is
rarely a single body match: benign proofs are a parser signature or a differential; RCE almost always needs an
out-of-band callback and is recorded as open_proof_gap until a hit lands. Never fire a destructive gadget.

## Attack surface
- Java: base64 starting `rO0AB` (ObjectInputStream), `AC ED 00 05` bytes, JSF/ViewState, RMI/JMX endpoints.
- PHP: `O:8:"stdClass"...`, `a:2:{...}` in cookies/params; anything hitting `unserialize()`.
- Python: pickle (`gASV`, `\x80\x04`), PyYAML `!!python/object`, jsonpickle.
- Ruby: Marshal blobs (`\x04\x08`), YAML `!ruby/object`.
- .NET: `__VIEWSTATE`, `LosFormatter`/`BinaryFormatter` blobs, base64 `AAEAAAD`.

## Hunt methodology
1. From recon (`katana-crawl`, `js-endpoints`), pull every request. Flag values that base64-decode to the magic
   bytes above, or that are already recognisable serialized text.
2. Fingerprint the format first (magic bytes / structure) - this alone is a strong lead.
3. Probe with a MALFORMED blob to force a parser error (benign), then a MINIMAL valid-but-altered object to prove
   the value is actually deserialized (differential).
4. Only escalate to a gadget that triggers an OOB DNS/HTTP callback; keep it non-destructive (no file write, no
   process spawn beyond the beacon). Record open_proof_gap until the callback is observed.

## Checks (predict -> send -> assert)
- technique: format fingerprint
  send: capture the suspect value; if base64, decode and inspect the leading bytes
  predict: {body_contains: "rO0AB"}   # adapt per language: O:, gASV, \x04\x08, AAEAAAD, __VIEWSTATE
  refute_if: {body_not_contains: "rO0AB"}
  fp_note: a magic-byte match proves the FORMAT is in use, not that it is unsafely deserialized. Continue.

- technique: parser-error probe
  send: replace the blob with truncated/corrupted bytes of the same format
  predict: {status_in: [500], body_contains: ["InvalidClassException", "unserialize", "pickle", "Marshal", "ViewState"]}
  refute_if: {status_in: [200, 400], body_not_contains: "serial"}
  fp_note: a generic 500 is not proof - the body must name the deserializer/driver. Some apps swallow errors; move to the differential.

- technique: benign field-swap differential
  send: re-emit a minimal valid object of the same format with one field changed (a role flag, a username, a count)
  predict: {status_in: [200], differs_from_control: true}   # control = the original blob's response
  refute_if: {differs_from_control: false}
  fp_note: the change must alter server BEHAVIOUR (state reflected back), proving the graph is rebuilt, not echoed.

- technique: RCE gadget via OOB
  send: a known gadget chain (ysoserial-style) whose only effect is a DNS/HTTP beacon to an attacker host
  predict: {}   # not harness-gradeable - confirm via out-of-band hit; record as open_proof_gap until observed
  fp_note: only a real callback from the target backend confirms code execution. Never use a filesystem/reverse-shell payload.

## Notes
Severity: critical on a confirmed OOB/RCE; high for a proven object-injection differential (auth/role tampering)
without code exec. Evidence = the decoded blob, the format signature, and either the differential pair or the
callback record. Do not claim RCE from a fingerprint alone - the open_proof_gap stays open until a beacon fires.
