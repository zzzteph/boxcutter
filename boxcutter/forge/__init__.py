"""boxcutter-forge - a local, web-only, backend-agnostic bug-bounty conductor.

The conductor (``forge.conductor``) is deterministic: it maps web assets, runs
boxcutter workflows locally, and reports. The single point of LLM judgment goes
through a pluggable ORCA backend (``forge.orca``), chosen the same way
security-forge picks a backend: a console agent CLI by default, or a native
provider / LiteLLM when asked. None of it routes to the internal bob/caleb agents.
"""

from .orca import (
    CliOrca,
    MockOrca,
    Orca,
    ProviderOrca,
    add_orca_args,
    resolve_orca,
)

__all__ = [
    "Orca",
    "ProviderOrca",
    "CliOrca",
    "MockOrca",
    "resolve_orca",
    "add_orca_args",
]
