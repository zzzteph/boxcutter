"""Workflows: chains of tools that produce one merged, source-tagged report.

Every workflow is defined as YAML in ``workflows/library/*.yaml`` and run by the
YAML interpreter (``yaml_runner``). The genuinely code-heavy bits are ordinary
tools (e.g. ``swagger-endpoints`` turns an OpenAPI spec into endpoint URLs) and
list ``filters`` - not special workflow machinery.

Users can drop their own YAML into a directory pointed at by the
``BOXCUTTER_WORKFLOWS`` environment variable; those override built-ins by name.

Note: loading YAML needs PyYAML. Without it there are no workflows (the tools
still work). The image ships py3-yaml.
"""

from .yaml_runner import load_specs

WORKFLOWS = load_specs()
