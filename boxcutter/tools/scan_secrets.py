"""scan-secrets - fetch a URL and scan the body for exposed secrets.
Port of app:scan-secrets."""

from __future__ import annotations

import re

from ..core import http
from ..core.args import add_common_args
from ..core.envelope import output_result
from ..core.validators import is_valid_url

NAME = "scan-secrets"
KIND = "findings"
HELP = "Fetch a URL and scan the response body for exposed secrets/credentials."

# name -> regex, ported verbatim (matched with MULTILINE, full-match reported).
PATTERNS: list[tuple[str, str]] = [
    # Cloud providers
    ("AWS Access Key ID", r"(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}"),
    ("AWS Secret Access Key", r'(?i)aws[_\-\s]?secret[_\-\s]?(?:access[_\-\s]?)?key[\s]*[=:"\s]+([A-Za-z0-9/+=]{40})'),
    ("Google API Key", r"AIza[0-9A-Za-z\-_]{35}"),
    ("Google OAuth Client ID", r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com"),
    ("Azure Storage Account Key", r"AccountKey=[a-zA-Z0-9+/]{86}=="),
    # Source control
    ("GitHub Personal Access Token", r"ghp_[0-9a-zA-Z]{36}"),
    ("GitHub OAuth Token", r"gho_[0-9a-zA-Z]{36}"),
    ("GitHub App Install/User Token", r"gh[us]_[0-9a-zA-Z]{36}"),
    ("GitHub App Refresh Token", r"ghr_[0-9a-zA-Z]{76}"),
    ("GitHub Fine-Grained PAT", r"github_pat_[0-9a-zA-Z_]{82}"),
    ("GitLab Personal Access Token", r"glpat-[0-9a-zA-Z\-_]{20}"),
    # Payment
    ("Stripe Live Secret Key", r"sk_live_[0-9a-zA-Z]{24,}"),
    ("Stripe Test Secret Key", r"sk_test_[0-9a-zA-Z]{24,}"),
    ("Stripe Restricted Key", r"rk_live_[0-9a-zA-Z]{24,}"),
    ("PayPal Braintree Access Token", r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}"),
    ("Square OAuth Secret", r"q0csp-[0-9A-Za-z\-_]{43}"),
    ("Square Access Token", r"EAAAE[a-zA-Z0-9]{60,}"),
    # Messaging
    ("Slack Bot Token", r"xoxb-[0-9]{10,13}-[0-9]{10,13}-[0-9a-zA-Z]{24}"),
    ("Slack User Token", r"xoxp-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[0-9a-zA-Z]{32}"),
    ("Slack App-Level Token", r"xapp-\d-[A-Z0-9]+-\d+-[a-z0-9]+"),
    ("Slack Config Token", r"xoxe\.[a-zA-Z0-9\-]+"),
    ("Twilio API Key SID", r"SK[0-9a-fA-F]{32}"),
    ("SendGrid API Key", r"SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}"),
    ("Mailchimp API Key", r"[0-9a-f]{32}-us[0-9]{1,2}"),
    ("Mailgun API Key", r"key-[0-9a-zA-Z]{32}"),
    ("Telegram Bot Token", r"[0-9]{5,10}:[A-Za-z0-9_\-]{35}"),
    ("Discord Bot Token", r"[MN][A-Za-z\d]{23}\.[A-Za-z\d\-_]{6}\.[A-Za-z\d\-_]{27}"),
    # CI / DevOps
    ("Heroku API Key", r"[hH][eE][rR][oO][kK][uU][a-z0-9_ \t,\-]{0,25}[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}"),
    ("CircleCI Personal Token", r"circle-token-[0-9a-fA-F]{40}"),
    ("npm Access Token", r"npm_[A-Za-z0-9]{36}"),
    ("Databricks Access Token", r"dapi[a-h0-9]{32}"),
    ("DigitalOcean Personal Access Token", r"dop_v1_[a-f0-9]{64}"),
    ("Doppler Service Token", r"dp\.pt\.[a-zA-Z0-9]{43}"),
    ("Pulumi Access Token", r"pul-[a-f0-9]{40}"),
    ("Postman API Key", r"PMAK-[0-9a-fA-F]{24}-[0-9a-fA-F]{34}"),
    ("Linear API Key", r"lin_api_[a-zA-Z0-9]{40}"),
    ("Dynatrace Token", r"dt0[a-zA-Z]{1}[0-9]{2}\.[A-Z0-9]{8}\.[A-Z0-9]{64}"),
    ("New Relic License Key", r"NRAK-[A-Z0-9]{27}"),
    # AI / ML
    ("OpenAI API Key", r"sk-[A-Za-z0-9]{48}"),
    ("HuggingFace API Token", r"hf_[A-Za-z0-9]{34,}"),
    ("Anthropic API Key", r"sk-ant-[A-Za-z0-9\-_]{90,110}"),
    # E-commerce
    ("Shopify Private App Password", r"shppa_[a-fA-F0-9]{32}"),
    ("Shopify Shared Secret", r"shpss_[a-fA-F0-9]{32}"),
    ("Shopify Access Token", r"shpat_[a-fA-F0-9]{32}"),
    ("Shopify Custom App Token", r"shpca_[a-fA-F0-9]{32}"),
    # Infrastructure secrets
    ("HashiCorp Vault Token (v1.10+)", r"hvs\.[A-Za-z0-9_\-]{90,}"),
    ("Age Secret Key", r"AGE-SECRET-KEY-1[AC-HJ-NP-Z02-9]{58}"),
    ("Artifactory Access Token", r"AKC[a-zA-Z0-9]{10,}"),
    ("Cloudinary URL", r"cloudinary://[0-9]{10,20}:[0-9A-Za-z]+@[a-z]+"),
    ("Typeform API Token", r"tfp_[a-zA-Z0-9_\-]{59}"),
]

_COMPILED = [(name, re.compile(pat, re.M)) for name, pat in PATTERNS]


def add_arguments(parser) -> None:
    parser.add_argument("target", help="Target URL")
    add_common_args(parser)


def scan_body(body: str, url: str = "") -> list[dict]:
    """Run all secret patterns over ``body`` and return finding dicts."""
    findings: list[dict] = []
    seen: set[str] = set()
    for name, regex in _COMPILED:
        for match in regex.finditer(body):
            value = match.group(0)
            key = f"{name}|{value}"
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                {
                    "severity": "medium",
                    "title": name,
                    "info": f"discovered {name} - key = {value}",
                    "url": url,
                }
            )
    return findings


def run(args) -> int:
    target = args.target.strip()

    if not is_valid_url(target):
        output_result([], args.output, "Invalid URL.")
        return 1

    try:
        response = http.with_retries(
            lambda: http.get(target, timeout=30, verify=True), retries=3, sleep_ms=200
        )
    except Exception as exc:
        output_result([], args.output, str(exc))
        return 1

    output_result(scan_body(response.text, target), args.output)
    return 0
