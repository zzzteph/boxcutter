---
name: rce
label: Remote code / OS command injection
triggers: [shell-metachar-param, filename-param, ping/host/lookup, export/convert, ffmpeg/imagemagick, eval-param, deserialization-hint]
preconditions: []
scope: requests-only
safety: intrusive
severity_hint: critical
---

# Remote code / OS command injection

## Overview
User input reaches a shell, an interpreter, or a native tool argument and is executed. Prove it by making the
TARGET compute or reveal something only code execution can produce - a deterministic arithmetic marker, a
platform string, a command's read-only output - measured differentially (payload vs a benign control). A 500 or
an odd echo is a lead; the finding is a marker the app could not have produced without running your input.

## Attack surface
Params that flow into shell calls or tool arguments: `host`/`ip` in ping/nslookup/traceroute, `filename` in
convert/export/thumbnail (ImageMagick, ffmpeg, wkhtmltopdf), `cmd`/`exec`/`eval` fields, archive names, git/svn
refs, and any interpreter `eval`. `katana-crawl` + `js-endpoints` to map inputs; `api-map`/`swagger-specs` for
service params.

## Hunt methodology
1. Enumerate inputs with `katana-crawl`, `js-endpoints`, `api-map`, `swagger-specs`; pick params that smell like
   a command argument (host, file, format, template).
2. Run `fuzz` with `{FUZZ}` on one such param - its payload DB includes command-injection separators and it
   self-confirms against the unfuzzed baseline. Trust confirmed hits, then reproduce with `http-request`.
3. Prove with the least intrusive marker first: an arithmetic echo or a platform string. Escalate to reading a
   benign, universally-present token only if needed. NEVER run a destructive/state-changing command, spawn a
   shell, write files, or fetch remote payloads.
4. `nuclei` can corroborate known-CVE RCE on fingerprinted stacks; still confirm with your own differential.

## Checks (predict -> send -> assert)
- technique: inline command substitution (arithmetic marker)
  send: chain a benign expr into the param, e.g. `127.0.0.1; expr 7 \* 191` or `$(expr 7 \* 191)` / backticks
  predict: {status_in: [200], body_contains: "1337", differs_from_control: true}
  refute_if: {body_not_contains: "1337"}
  fp_note: `1337` must be COMPUTED - resend with a different pair (e.g. 13*17 -> 221) so a hardcoded page never
           fools you. Reflected literal `7*191` is not execution.

- technique: interpreter eval marker
  send: an expression in the interpreter's syntax (e.g. `#{7*191}`, `${T(java...)}`, `__import__('os')`-free math)
  predict: {status_in: [200], body_contains: "1337", differs_from_control: true}
  refute_if: {body_not_contains: "1337"}
  fp_note: confirm the number changes with the operands; a static value or a template-only eval is SSTI, not RCE.

- technique: platform/identity echo (read-only)
  send: `; uname -a` (or `& ver` on Windows) appended to a command param
  predict: {status_in: [200], body_contains: ["Linux", "GNU", "Windows"], differs_from_control: true}
  refute_if: {differs_from_control: false}
  fp_note: the string must be absent from the control response; match on a token the app would never print itself.

- technique: time-based blind (no output channel)
  send: `; sleep 5` (or `& timeout 5`) vs a `sleep 0` control
  predict: {latency_ms_gte: 4500, differs_from_control: true}
  refute_if: {latency_ms_lt: 1500}
  fp_note: the delay must TRACK the payload - re-fire sleep(5) vs sleep(0) to rule out a uniformly slow endpoint.

- technique: OOB (blind, no timing, no echo)
  send: a payload that makes the host resolve/fetch an attacker-controlled name (`; nslookup x.oob`, `$(curl ...)`)
  predict: {}    # not gradeable by the harness - confirm via an out-of-band hit; record as open_proof_gap until observed
  fp_note: only a real callback from the target's backend confirms it.

## Notes
Severity: critical. Command/code execution on the server is the top of the chain - once a marker is confirmed,
note reachable impact (file read, lateral access) but keep every proof read-only and benign. Evidence = the
computed-marker pair (payload vs control) or the tracked timing pair. Never destructive.
