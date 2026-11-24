# boxcutter - ONE image, three modes: the scanning engine (default CLI), the web server (`boxcutter serve`),
# and a scale-out scanner agent (`boxcutter agent`). One build, one __version__ for all three - so a push
# rebuilds everything together and an agent can never disagree with the engine it runs.

# ---- stage: build the Vue SPA for `boxcutter serve` (served same-origin, under /api) ----
FROM node:26-alpine AS web
WORKDIR /web
COPY web/package*.json ./
RUN npm ci --no-audit --no-fund
COPY web/ ./
RUN npm run build

FROM alpine:3.24 AS base
RUN apk add --no-cache \
        bash ca-certificates bind-tools nmap wget curl git \
        python3 py3-pip py3-requests py3-yaml \
        libstdc++ libgcc \
        tini \
    && update-ca-certificates

# ProjectDiscovery scanners used by the bundled workflows
COPY --from=projectdiscovery/subfinder:v2.17.0 /usr/local/bin/subfinder /usr/local/bin/subfinder
COPY --from=projectdiscovery/dnsx:v1.2.2       /usr/local/bin/dnsx      /usr/local/bin/dnsx
COPY --from=projectdiscovery/katana:v1.8.0     /usr/local/bin/katana    /usr/local/bin/katana
COPY --from=projectdiscovery/nuclei:v3.11.1    /usr/local/bin/nuclei    /usr/local/bin/nuclei
COPY --from=projectdiscovery/httpx:v1.12.0     /usr/local/bin/httpx     /usr/local/bin/httpx
# secrets scanning: trufflehog's curated + verifiable detectors (scan-secrets uses it when present, else falls
# back to its built-in regex)
COPY --from=trufflesecurity/trufflehog:3.100.1 /usr/bin/trufflehog      /usr/local/bin/trufflehog

RUN nuclei -update-templates || true

RUN git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git /usr/share/sqlmap

WORKDIR /work
# tini as PID 1 = a real init that REAPS orphaned processes. `boxcutter agent` runs as the container's main
# process and spawns per-job boxcutter subprocesses that themselves spawn tools (chromium, sqlmap, ...). A tool
# that outlives its parent gets reparented to PID 1; with no init to reap it, it lingers as a zombie and eats
# the process/thread budget until the agent can no longer fork(). tini reaps those orphans and forwards signals.
ENTRYPOINT ["/sbin/tini", "--", "python3", "/opt/boxcutter/boxcutter.py"]
CMD ["--help"]

FROM base AS full
# headless Chromium for the browser crawler (harvest), driven over the Chrome DevTools Protocol with the
# pure-Python websocket-client (installs fine on musl, unlike Playwright).
RUN apk add --no-cache chromium nss freetype harfbuzz ttf-freefont \
    && { [ -e /usr/bin/chromium-browser ] || ln -s /usr/bin/chromium /usr/bin/chromium-browser; }
RUN pip3 install --no-cache-dir --break-system-packages websocket-client
ENV CHROMIUM_PATH=/usr/bin/chromium-browser \
    HTTPX_NO_COLOR=1

COPY boxcutter /opt/boxcutter/boxcutter
COPY boxcutter.py /opt/boxcutter/boxcutter.py

# --- `boxcutter serve`: the web server's dependencies live in a DEDICATED venv so the lean engine's
# system-python imports stay untouched (the base marks system python externally-managed, PEP 668). `serve`
# execs this venv for uvicorn; the scanning tools still run under the on-PATH engine python.
COPY requirements.txt /opt/boxcutter/requirements.txt
COPY server /opt/boxcutter/server
RUN python3 -m venv /opt/srv \
 && /opt/srv/bin/pip install --no-cache-dir -r /opt/boxcutter/requirements.txt
COPY --from=web /web/dist /opt/boxcutter/server/web_dist
# DB + the built-in agent's config persist here; mount a named volume to keep them across restarts.
ENV DATA_DIR=/data \
    DATABASE_URL=sqlite:////data/boxcutter.db \
    RUNNER_CONFIG=/data/runner-config.json \
    PYTHONUNBUFFERED=1
VOLUME ["/data"]
# 8000 = web UI (`boxcutter serve`); 7070 = a scanner's local control UI (`boxcutter agent`)
EXPOSE 8000 7070
