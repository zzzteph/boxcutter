"""Advisor base - read-only observers of the state that SUGGEST next actions (never act)."""

from __future__ import annotations


class Advisor:
    name = "advisor"

    def suggest(self, state) -> list:
        """Return a list of Suggestion(action, args, reason, priority, by) from the current state."""
        return []
