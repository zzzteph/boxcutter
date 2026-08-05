"""Subdomain permutation - generate CLEVER candidate names from the subdomains a target ACTUALLY uses, not a blind
list. Given the discovered set (e.g. `lab-test.prod.example.com`), it derives the siblings a tester would guess:
env swaps (`.prod.`→`.stage.`/`.dev.`/`.qa.`), number walks (`app1`→`app2/3`), and env splices on the service word
(`api`→`api-dev`, `dev-api`, `dev.api`). Bounded + deduped; the caller resolves the output with dnsx (+ wildcard filter).
"""
from __future__ import annotations

import re

# deployment-environment tokens (NOT service words like api/admin - those are spliced separately)
_ENVS = ("dev", "development", "devel", "stage", "staging", "stg", "test", "testing", "tst", "qa", "uat",
         "prod", "production", "prd", "preprod", "pre", "sandbox", "sbx", "demo", "beta", "alpha", "live",
         "canary", "release", "rc", "int", "integration", "internal", "corp", "intranet", "new", "old", "legacy")

# a smaller, high-signal env set used for the (expensive) splice/cross passes
_ENV_CORE = ("dev", "staging", "stage", "test", "qa", "uat", "prod", "preprod", "sandbox", "demo", "internal", "int")


def _strip_digits(label: str) -> str:
    return re.sub(r"\d+$", "", label)


def mutations(hosts, base_domain: str, cap: int = 4000):
    """Return sorted candidate hostnames derived from `hosts` (all under `base_domain`), excluding the inputs."""
    base = (base_domain or "").lower().strip(".")
    if not base:
        return []
    have = {h.lower().strip(".") for h in hosts}
    subs = []                                            # the label-part before ".base" for each in-scope host
    for h in have:
        if h == base or not h.endswith("." + base):
            continue
        subs.append(h[: -(len(base) + 1)])
    if not subs:
        return []

    labels = set()
    for s in subs:
        labels.update(s.split("."))
    service_tokens = sorted({l for l in labels if l and not l.isdigit() and _strip_digits(l) not in _ENVS})

    out = set()

    def add(sub):
        out.add(f"{sub}.{base}")

    for s in subs:
        parts = s.split(".")
        for i, lab in enumerate(parts):
            stem_lab = _strip_digits(lab)
            # (1) ENV SWAP - a label that is (or is env+digits) an env -> swap to every other env, in place
            if lab in _ENVS or stem_lab in _ENVS:
                for env in _ENVS:
                    np = parts.copy(); np[i] = env
                    add(".".join(np))
            # (2) NUMBER WALK - label ends in a digit -> neighbouring indices
            m = re.search(r"(\d+)$", lab)
            if m:
                n = int(m.group(1)); stem = lab[: m.start()]
                for x in {1, 2, 3, max(0, n - 1), n + 1, n + 2}:
                    np = parts.copy(); np[i] = f"{stem}{x}"
                    add(".".join(np))
        # (3) ENV SPLICE on the leaf service word (found `api.x` -> `api-dev`, `dev-api`, `dev.api`, `api.dev`)
        leaf = parts[0]
        rest = ("." + ".".join(parts[1:])) if len(parts) > 1 else ""
        if leaf in service_tokens:
            for env in _ENV_CORE:
                add(f"{leaf}-{env}{rest}")
                add(f"{env}-{leaf}{rest}")
                add(f"{env}.{leaf}{rest}")
                add(f"{leaf}.{env}{rest}")
        # (4) HIERARCHY: prepend each core env as a new sub-zone over the whole observed sub
        for env in _ENV_CORE:
            add(f"{env}.{s}")

    # (5) CROSS-SEED: every observed service token under every core env (both orders) - the classic "they have
    #     api.prod, do they have api.dev / dev.api?" move, applied across all discovered service words.
    for svc in service_tokens[:80]:
        for env in _ENV_CORE:
            add(f"{svc}.{env}")
            add(f"{env}.{svc}")
            add(f"{svc}-{env}")
            add(f"{env}-{svc}")

    out -= have                                          # don't re-emit what we already found
    out.discard(base)
    return sorted(out)[:cap]
