"""Agentic (LLM-driven) boxcutter tools - kept separate from the deterministic tools in ``boxcutter.tools``.

Each module here is a standalone agent exposed as ``boxcutter <name>`` (irvin, logio, prawlio, crawlio):
it needs a provider/API key and drives an LLM tool-calling loop. They are registered in
``boxcutter.tools.registry`` (the AI list) like any other command; only their SOURCE lives here, so the
non-agentic tools in ``boxcutter.tools`` stay uncluttered.
"""
