#!/usr/bin/env bash
# _run.sh <url> [outdir] — NON-INTERACTIVE caleb-lite: run the DETECTION scanners on ONE target, store every tool's
# JSON output, then build report.md. Single-pass, unauthenticated, non-destructive. NO auth / identities / lateral
# movement / chaining / exploitation / destructive writes. Authorization is assumed (operator-owned target); it never
# prompts. Heavy scanners are time-bounded. Usage: _run.sh https://target [/out/dir]
set -u
URL="${1:?usage: _run.sh <url> [outdir]}"
DOCKER="${DOCKER:-sudo docker}"
SELF_DIR="$(cd "$(dirname "$0")" && pwd)"
HOST=$(printf '%s' "$URL" | sed -E 's#^https?://##; s#[/?].*##')
OUT="${2:-/tmp/caleb-lite/$HOST}"
BASE="${URL%%\?*}"
mkdir -p "$OUT" || exit 1
echo "caleb-lite: $URL -> $OUT"
step(){ echo "  [$(date +%H:%M:%S)] $*"; }

step "fetch (http-request)"
$DOCKER run --rm boxcutter http-request "$URL" > "$OUT/fetch.json" 2>"$OUT/fetch.err"

step "path-bust (exposed files/dirs)"
timeout 360 $DOCKER run --rm boxcutter path-bust "$URL" > "$OUT/pathbust.json" 2>"$OUT/pathbust.err" || true

step "nuclei (cve,exposure,misconfiguration,ssl,tech — non-intrusive)"
timeout 900 $DOCKER run --rm boxcutter nuclei "$URL" \
    --tags cve,exposure,misconfiguration,ssl,tech --severity low,medium,high,critical \
    > "$OUT/nuclei.json" 2>"$OUT/nuclei.err" || true

step "scan-secrets"
timeout 300 $DOCKER run --rm boxcutter scan-secrets "$URL" > "$OUT/secrets.json" 2>"$OUT/secrets.err" || true

step "extract observed params + fuzz each (detection only, {FUZZ})"
python3 - "$URL" "$OUT/fetch.json" > "$OUT/params.txt" <<'PY'
import sys, json, re
url, fetch = sys.argv[1], sys.argv[2]
params = set()
q = re.search(r'\?(.+)$', url)
if q:
    for kv in q.group(1).split('&'):
        k = kv.split('=')[0].strip()
        if k: params.add(k)
try:
    body = (json.load(open(fetch)).get('data') or [{}])[0].get('content') or ''
except Exception:
    body = ''
params.update(re.findall(r'<input[^>]+name=["\']([^"\']+)["\']', body, re.I))
params.update(re.findall(r'[?&]([A-Za-z0-9_]{1,40})=', body))
for p in sorted(params)[:12]:   # cap: observed params only, never blind spraying
    print(p)
PY
: > "$OUT/fuzz.jsonl"
while IFS= read -r p; do
  [ -n "$p" ] || continue
  case "$BASE" in *\?*) T="$BASE&$p={FUZZ}";; *) T="$BASE?$p={FUZZ}";; esac
  timeout 180 $DOCKER run --rm boxcutter fuzz "$T" 2>/dev/null \
    | python3 -c "import sys,json;
d=json.load(sys.stdin); print(json.dumps({'param':'$p','data':d.get('data') or []}))" \
    >> "$OUT/fuzz.jsonl" 2>/dev/null || true
done < "$OUT/params.txt"

step "screenshot (context)"
timeout 90 $DOCKER run --rm boxcutter screenshot "$URL" 2>/dev/null \
  | python3 -c "import sys,json,base64;
d=(json.load(sys.stdin).get('data') or [{}])[0]; b=d.get('image') or '';
open('$OUT/shot.png','wb').write(base64.b64decode(b)) if b else None" 2>/dev/null || true

step "report"
python3 "$SELF_DIR/_report.py" "$URL" "$OUT"
echo "done -> $OUT/report.md"
