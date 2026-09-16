"""boxcutter-forge - a local, web-only, backend-agnostic bug-bounty conductor.

The conductor (``forge.conductor``) is deterministic: it maps web assets, runs
boxcutter workflows locally, and reports. The single point of LLM judgment goes
through a pluggable ORCA backend (``forge.orca``), chosen the same way
security-forge picks a backend: a console agent CLI by default, the internal
already-authenticated Claude Code CLI via ``--orca claude-code`` (no API key), or a
native provider / LiteLLM when asked. The backend can be PRECONFIGURED with env vars
(BOXCUTTER_FORGE_ORCA / BOXCUTTER_ORCA_MODEL / CLAUDE_BIN), the way security-forge
preconfigures it in config.yaml. None of it routes to the internal bob/caleb agents.
"""

from .orca import (
    ClaudeCodeOrca,
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
    "ClaudeCodeOrca",
    "CliOrca",
    "MockOrca",
    "resolve_orca",
    "add_orca_args",
]
