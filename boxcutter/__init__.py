"""boxcutter - a containerised pentesting toolkit.

Each tool under :mod:`boxcutter.tools` wraps a single scanner (an external
binary such as nuclei/subfinder, or a pure-Python HTTP routine) and emits a
uniform JSON envelope ``{success, data, error}``. The tools are ported 1:1
from the ShrewdEye scanner's Laravel artisan commands.
"""

__version__ = "0.1.0"
