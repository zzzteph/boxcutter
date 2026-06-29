"""Executor roster - the agentic working agents (skills) ORCA dispatches. name -> Executor class."""

from __future__ import annotations

from .recon import Recon
from .fuzzer import Fuzzer
from .requester import Requester
from .injector import Injector
from .exposure import Exposure
from .authn import Authn
from .graphql import GraphQL
from .reporter import Reporter

EXECUTORS = {e.name: e for e in (Recon, Fuzzer, Requester, Injector, Exposure, Authn, GraphQL, Reporter)}


def roster() -> str:
    """One-line-per-executor manual for the planner's prompt."""
    return "\n".join(f"- {e.name}: {e.description}" for e in EXECUTORS.values())
