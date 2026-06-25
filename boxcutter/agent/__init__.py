"""bob - the boxcutter agentic bug-hunting engine.

A pipeline of adaptive, boxcutter-only LLM agents that share one engagement Context, harvest
credentials as they go, move laterally, and chase chains to demonstrable impact. Exposed to users as
the `boxcutter bob <target>` subcommand (see boxcutter/tools/bob.py); provider-agnostic and
requests-only (no LLM SDKs).
"""

from .context import Context, Finding
from .runner import InProcessRunner
from .providers import PROVIDERS
from .orchestrator import run_pipeline
from .agents import AGENTS, PIPELINE

__all__ = ["Context", "Finding", "InProcessRunner", "PROVIDERS", "run_pipeline", "AGENTS", "PIPELINE"]
