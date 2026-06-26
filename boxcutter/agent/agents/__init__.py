"""Agent registry - the ordered pipeline. Each agent is its own module above.

The coordinator gates these by trigger predicate, so order is the *preferred* sequence, not a forced
one: producers (discovery/js-analyzer/recon-ranker/profile/api/graphql) run before consumers
(fuzzer/access/lateral) so harvested credentials and ranked surface are in the shared Context first;
the analysis tail (validator -> correlator -> reporter) always runs last.
"""

from .planner import Planner
from .auth import Auth
from .discovery import Discovery
from .browser import Browser
from .js_analyzer import JsAnalyzer
from .recon_ranker import ReconRanker
from .fingerprint import Fingerprint
from .profile import Profile
from .api import Api
from .graphql import GraphQL
from .exposure import Exposure
from .config_auditor import ConfigAuditor
from .visual import Visual
from .fuzzer import Fuzzer
from .access import Access
from .business_logic import BusinessLogic
from .lateral import Lateral
from .validator import Validator
from .correlator import Correlator
from .reporter import Reporter

PIPELINE = [
    Planner, Auth, Discovery, Browser, JsAnalyzer, ReconRanker, Fingerprint, Profile,
    Api, GraphQL, Exposure, ConfigAuditor, Visual, Fuzzer, Access, BusinessLogic, Lateral,
    Validator, Correlator, Reporter,
]
AGENTS = {cls.name: cls for cls in PIPELINE}
