"""fuzzer executor - an agent that runs the injection battery on its assigned endpoint(s)."""

from __future__ import annotations

from .base import Executor


class Fuzzer(Executor):
    name = "fuzz"
    description = "Run the injection battery on the assigned endpoint(s). args: {url} or {sweep:true}."
    tools = {"fuzz", "http-request"}
    max_steps = 12
    objective = (
        "You are the FUZZER agent. Use `fuzz` to confirm injection (sqli/xss/ssti/lfi/ssrf/xxe/nosql/error) on "
        "the endpoint(s) in your task. Fuzz EVERY query parameter and id-like path segment - be exhaustive on "
        "your target before stopping. If your task is a sweep, fuzz each UNTESTED endpoint listed in the state. "
        "Report each confirmed signal with the verbatim payload/evidence and the correct cls; hand any reflected "
        "credential to artifacts.tokens.")
