"""irvin agent roles.

After the conductor refactor, irvin drives the proven standalone agents (travis, bob, caleb) directly - see
irvin/pipeline.py. The only agents that live here now are the post-hunt CONTROL roles that operate on the
aggregated findings:

  Verifier     - independent existence re-check (drops findings whose page provably 404s)
  Consolidator - collapses provably-identical findings into one
  Reporter     - writes the CEO executive summary + technical findings report

They are imported straight from .control by the pipeline; this package no longer wires a suggester council or
an executor registry.
"""

from __future__ import annotations

from .control import Consolidator, Reporter, Verifier

__all__ = ["Consolidator", "Reporter", "Verifier"]
