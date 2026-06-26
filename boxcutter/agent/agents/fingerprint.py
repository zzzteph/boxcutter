"""Fingerprint - identifies the stack from concrete signatures, then probes its known leak points.

The signature table is extracted from hexstrike's TechnologyDetector (header/content patterns),
trimmed to the web-relevant categories (boxcutter is web/API only - ports/databases-by-port dropped).
"""

from ..base import Agent

# header/content substrings -> technology. Adapted from hexstrike's TechnologyDetector.detection_patterns.
SIGNATURES = """web servers:  apache=[Apache, httpd] | nginx=[nginx] | iis=[Microsoft-IIS] | tomcat=[Tomcat, Apache-Coyote] | jetty=[Jetty]
frameworks:   django=[Django, csrftoken] | flask=[Flask, Werkzeug] | express=[Express, X-Powered-By: Express] | laravel=[Laravel, laravel_session] | symfony=[Symfony] | rails=[Ruby on Rails, _session_id] | spring=[Spring, JSESSIONID] | struts=[Struts]
cms:          wordpress=[wp-content, wp-includes, /wp-admin/] | drupal=[Drupal, /sites/default/, X-Drupal-Cache] | joomla=[Joomla, /administrator/, com_content] | magento=[Magento, Mage.Cookies] | prestashop=[PrestaShop] | opencart=[OpenCart]
languages:    php=[PHP, .php, X-Powered-By: PHP] | python=[Python, .py] | java=[.jsp, .do, JSESSIONID] | dotnet=[ASP.NET, .aspx, X-AspNet-Version] | nodejs=[Node.js, Express] | ruby=[Ruby, .rb]
security/waf: cloudflare=[cf-ray, CloudFlare] | incapsula=[incapsula, X-Iinfo] | sucuri=[Sucuri] | akamai=[Akamai] | f5=[BigIP, F5]"""

# stack -> high-value paths to probe directly with http-request
KNOWN_LEAKS = {
    "spring": "/actuator, /actuator/env, /actuator/health, /actuator/heapdump, /actuator/mappings",
    "nextjs/react": "/_next/data/<buildId>/<page>.json, /static/*.js (then js-endpoints)",
    "wordpress": "/wp-json/wp/v2/users, /xmlrpc.php, /wp-content/debug.log",
    "laravel": "/.env, /telescope, /_ignition/health-check",
    "django": "/admin/, debug pages (DEBUG=True tracebacks)",
    "drupal": "/CHANGELOG.txt, /sites/default/files/, /user/register",
    "graphql": "introspection query, /graphiql",
}


class Fingerprint(Agent):
    name = "fingerprint"
    tools = {"httpx", "http-request", "screenshot", "browser-crawl"}
    max_steps = 12

    def objective(self, ctx):
        leaks = "\n".join(f"  {k}: {v}" for k, v in KNOWN_LEAKS.items())
        return (
            "You are FINGERPRINT (technology detection). Identify the stack from concrete evidence, then probe "
            "its known leak points.\n\n"
            "1) `http-request <base>` (and `screenshot` if useful); match the response headers + body against "
            "these signatures (substring -> technology):\n" + SIGNATURES + "\n\n"
            "2) For the detected stack, probe these KNOWN high-value exposure points with `http-request` and "
            "report any that return real data (redact secrets):\n" + leaks + "\n\n"
            "3) Hand off the detected stack + the nuclei `-tags` to use (default exposure,misconfig,cve,kev,panel "
            "plus a stack tag like wordpress/springboot/laravel) in artifacts.notes, and add a `profile` field "
            '{"tech":"<stack>"} so the model is shared. Put any exposure you find in findings.\n'
            "Clever: pivot the detected version to its known default paths; from Next.js read "
            "__NEXT_DATA__.buildId -> /_next/data routes; infer the backend from session cookies "
            "(JSESSIONID=Java, laravel_session=PHP, .AspNet=.NET) and probe that stack's defaults.")
