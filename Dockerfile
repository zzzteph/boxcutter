# boxcutter - ONE image, three modes: the scanning engine (default CLI), the web server (`boxcutter serve`),
# and a scale-out scanner agent (`boxcutter agent`). One build, one __version__ for all three - so a push
# rebuilds everything together and an agent can never disagree with the engine it runs.

# ---- stage: build the Vue SPA for `boxcutter serve` (VITE_API_BASE unset -> same-origin/relative API) ----
FROM node:20-alpine AS web
WORKDIR /web
COPY web/package*.json ./
RUN npm install
COPY web/ ./
RUN npm run build

FROM alpine:3.20 AS base
RUN apk add --no-cache \
        bash ca-certificates bind-tools nmap wget curl unzip git \
        python3 py3-pip py3-requests py3-yaml \
        libpcap libstdc++ libgcc \
        tini \
    && update-ca-certificates

COPY --from=projectdiscovery/subfinder:v2.12.0 /usr/local/bin/subfinder /usr/local/bin/subfinder
COPY --from=projectdiscovery/dnsx:v1.2.2       /usr/local/bin/dnsx      /usr/local/bin/dnsx
COPY --from=projectdiscovery/naabu:v2.5.0      /usr/local/bin/naabu     /usr/local/bin/naabu
COPY --from=projectdiscovery/katana:v1.5.0     /usr/local/bin/katana    /usr/local/bin/katana
COPY --from=projectdiscovery/nuclei:v3.7.1     /usr/local/bin/nuclei    /usr/local/bin/nuclei
COPY --from=projectdiscovery/httpx:v1.9.0      /usr/local/bin/httpx     /usr/local/bin/httpx
# secrets scanning: trufflehog's curated + verifiable detectors (scan-secrets uses it when present, else falls
# back to its built-in regex). Pin to a specific release tag (e.g. 3.90.x) for fully reproducible builds.
COPY --from=trufflesecurity/trufflehog:latest  /usr/bin/trufflehog      /usr/local/bin/trufflehog

RUN nuclei -update-templates || true

RUN git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git /usr/share/sqlmap
RUN git clone --depth 1 https://github.com/maurosoria/dirsearch.git /usr/share/dirsearch && \
    pip3 install --no-cache-dir --break-system-packages -r /usr/share/dirsearch/requirements.txt

WORKDIR /work
# tini as PID 1 = a real init that REAPS orphaned processes. `boxcutter agent` runs as the container's main
# process and spawns per-job boxcutter subprocesses that themselves spawn tools (chromium, ZAP/java, sqlmap…).
# A tool that outlives its parent gets reparented to PID 1; with no init to reap it, it lingers as a zombie and
# eats the process/thread budget until the agent can no longer fork()/start a thread ([Errno 11] / "can't start
# new thread"). tini reaps those orphans and forwards signals; it only reaps what the app's own subprocess.wait
# doesn't, so it's safe for every mode (engine/serve/agent).
ENTRYPOINT ["/sbin/tini", "--", "python3", "/opt/boxcutter/boxcutter.py"]
CMD ["--help"]

FROM base AS full
RUN apk add --no-cache \
        openjdk17-jre \
        chromium chromium-chromedriver firefox geckodriver \
        libpcap-dev nss freetype harfbuzz ttf-freefont
ENV HTTPX_NO_COLOR=1

# Browser-driven tools (harvest/login/actions) drive the system chromium above over the Chrome DevTools
# Protocol (boxcutter/core/cdp.py) using the pure-Python websocket-client lib - which installs fine on musl,
# unlike Playwright (no Alpine/musl wheel). The tools import it lazily and degrade gracefully if it is absent.
RUN pip3 install --no-cache-dir --break-system-packages websocket-client
ENV CHROMIUM_PATH=/usr/bin/chromium-browser

ARG ZAP_VERSION=2.17.0
RUN mkdir -p /usr/share/zaproxy /tmp/zap && \
    wget -O /tmp/zap.zip "https://github.com/zaproxy/zaproxy/releases/download/v${ZAP_VERSION}/ZAP_${ZAP_VERSION}_Crossplatform.zip" && \
    unzip /tmp/zap.zip -d /tmp/zap && \
    ZAP_DIR="$(find /tmp/zap -mindepth 1 -maxdepth 1 -type d | head -n 1)" && \
    mv "${ZAP_DIR}"/* /usr/share/zaproxy/ && \
    chmod +x /usr/share/zaproxy/zap.sh && \
    ln -sf /usr/share/zaproxy/zap.sh /usr/local/bin/zap.sh && \
    rm -rf /tmp/zap /tmp/zap.zip
ENV ZAP_HOME=/usr/share/zaproxy

RUN apk add --no-cache --virtual .dirb-build gcc make curl-dev musl-dev libcurl linux-headers && \
    mkdir /build && cd /build && \
    wget -q https://downloads.sourceforge.net/project/dirb/dirb/2.22/dirb222.tar.gz -O - | tar -xz --strip-components=1 -f - && \
    chmod -R a+x wordlists configure && \
    ./configure CFLAGS="-O2 -g -fcommon" && make && make install && \
    mkdir -p /usr/share/dirb && cp -aR wordlists /usr/share/dirb && \
    cd / && apk del --no-cache .dirb-build && rm -rf /build

COPY boxcutter /opt/boxcutter/boxcutter
COPY boxcutter.py /opt/boxcutter/boxcutter.py

# Password wordlists for login brute-force / spraying (recovered-hash cracking, credential-reuse chains) ship in
# boxcutter/data/ (passwords_10k.txt ~10k, passwords.txt ~2.3M) and are copied in by the `COPY boxcutter` above -
# no build-time download. Documented in the agent wordlist inventory (ai/joseph.py) so a run points a
# script/--wordlist at a REAL path, never an invented one.

# crack-js (github.com/zzzteph/crack-js) - a pure-JS hashcat-mode hash cracker, wired as a Node LIBRARY plus a
# thin CLI wrapper (docker/crack.js). It lets an operator crack a RECOVERED hash (a SQLi credential dump, a
# leaked shadow/htpasswd line, an HS256 JWT secret) against the password wordlists above and feed the plaintext
# into a credential-reuse chain. node is added only in this full image. NODE_PATH lets any node script (not just
# the wrapper) `require('crack-js')`. Usage is documented in the agent wordlist inventory (ai/joseph.py).
RUN apk add --no-cache nodejs npm && \
    mkdir -p /usr/share/crack-js && cd /usr/share/crack-js && \
    npm init -y >/dev/null 2>&1 && \
    npm install --no-audit --no-fund crack-js
COPY docker/crack.js /usr/share/crack-js/crack.js
ENV NODE_PATH=/usr/share/crack-js/node_modules

# Internal, authenticated Claude Code CLI - the `--orca claude-code` backend for `boxcutter forge` (the same
# backend security-forge runs by default). node+npm are already present (crack-js above), so this is just a
# global npm install that puts `claude` on PATH. NO API key is baked in: you AUTHORIZE ONCE inside the running
# container - `docker exec -it <container> claude` then `/login` - and the session PERSISTS because
# CLAUDE_CONFIG_DIR lives on the /data volume (mount a named volume to keep it across restarts). This image is
# Alpine/musl but Claude Code targets glibc, so we add gcompat (glibc shim) + a musl-native ripgrep and set
# USE_BUILTIN_RIPGREP=0 so it uses that instead of its bundled glibc build. Gate off with
# `--build-arg INSTALL_CLAUDE_CODE=false` to keep the image lean.
ARG INSTALL_CLAUDE_CODE=true
ENV CLAUDE_CONFIG_DIR=/data/.claude \
    USE_BUILTIN_RIPGREP=0
RUN if [ "$INSTALL_CLAUDE_CODE" = "true" ]; then \
        apk add --no-cache ripgrep gcompat && \
        npm install -g --no-audit --no-fund @anthropic-ai/claude-code && \
        npm cache clean --force && \
        claude --version ; \
    fi

# --- web server mode (`boxcutter serve`): FastAPI API + the built SPA + a built-in agent ---
# Server deps go in a DEDICATED venv so the lean engine's system-python imports stay untouched (the base marks
# system python externally-managed, PEP 668). `boxcutter serve` execs this venv for uvicorn; the engine and
# `boxcutter agent` keep using the on-PATH python. The agent mode needs no extra deps - it is stdlib + the engine.
COPY server /opt/boxcutter/server
RUN python3 -m venv /opt/srv \
 && /opt/srv/bin/pip install --no-cache-dir -r /opt/boxcutter/server/requirements.txt
COPY --from=web /web/dist /opt/boxcutter/server/web_dist
# DB + JWT secret + built-in-agent config persist here; mount a named volume to keep them across restarts.
ENV DATA_DIR=/data \
    DATABASE_URL=sqlite:////data/boxcutter_ui.db \
    RUNNER_CONFIG=/data/runner-config.json \
    PYTHONUNBUFFERED=1
VOLUME ["/data"]
# 8000 = web UI/API (`boxcutter serve`); 7070 = a scanner's local control UI (`boxcutter agent`)
EXPOSE 8000 7070
