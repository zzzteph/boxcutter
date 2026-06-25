"""Agent registry — the ordered pipeline. Each agent is its own module above.

Order matters for chains: api/discovery run before fuzzer/access so a credential harvested early
(e.g. a JWT from a test endpoint) is in the shared Context as an identity by the time the
injection/access agents run; `lateral` runs last (before the reporter) to deep-dive with every
identity gathered so far.
"""

from .planner import Planner
from .auth import Auth
from .discovery import Discovery
from .fingerprint import Fingerprint
from .profile import Profile
from .api import Api
from .exposure import Exposure
from .fuzzer import Fuzzer
from .access import Access
from .lateral import Lateral
from .reporter import Reporter

PIPELINE = [Planner, Auth, Discovery, Fingerprint, Profile, Api, Exposure, Fuzzer, Access, Lateral, Reporter]
AGENTS = {cls.name: cls for cls in PIPELINE}
