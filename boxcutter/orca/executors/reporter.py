"""reporter executor - the one LLM executor: turn the findings into a professional report."""

from __future__ import annotations

from .base import Executor

_SYS = """You are ORCA's reporter. Write a concise professional pentest report from the verified state.
Group by severity (Critical/High/Medium/Low), and for each finding give: title, URL, vuln class, the
verbatim (redacted) evidence, and a one-line reproduce. End with a short 'kill chain' paragraph linking
the findings. Use ONLY what is in the state - never invent findings or evidence."""


class Reporter(Executor):
    name = "report"
    description = "Summarise the verified findings into a final report (LLM)."

    def run(self, state, task, runner, provider) -> None:
        user = (f"TARGET: {state.target}\n\nFINDINGS:\n{state.findings_report()}\n\n"
                f"RUN FACTS:\n{state.coverage_report()}")
        try:
            report = provider.chat(_SYS, user, max_tokens=2500)
        except Exception as exc:  # noqa: BLE001
            report = f"(report generation failed: {exc})\n\n{state.findings_report()}"
        print("\n" + (report or state.findings_report()))
