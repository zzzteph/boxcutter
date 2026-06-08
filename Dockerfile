FROM alpine:3.20 AS base
RUN apk add --no-cache \
        bash ca-certificates bind-tools wget curl unzip git \
        python3 py3-pip py3-requests py3-yaml \
        libpcap libstdc++ libgcc \
    && update-ca-certificates

COPY --from=projectdiscovery/subfinder:v2.12.0 /usr/local/bin/subfinder /usr/local/bin/subfinder
COPY --from=projectdiscovery/dnsx:v1.2.2       /usr/local/bin/dnsx      /usr/local/bin/dnsx
COPY --from=projectdiscovery/naabu:v2.5.0      /usr/local/bin/naabu     /usr/local/bin/naabu
COPY --from=projectdiscovery/katana:v1.5.0     /usr/local/bin/katana    /usr/local/bin/katana
COPY --from=projectdiscovery/nuclei:v3.7.1     /usr/local/bin/nuclei    /usr/local/bin/nuclei
COPY --from=projectdiscovery/httpx:v1.9.0      /usr/local/bin/httpx     /usr/local/bin/httpx

RUN nuclei -update-templates || true

RUN git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git /usr/share/sqlmap
RUN git clone --depth 1 https://github.com/maurosoria/dirsearch.git /usr/share/dirsearch && \
    pip3 install --no-cache-dir --break-system-packages -r /usr/share/dirsearch/requirements.txt

WORKDIR /work
ENTRYPOINT ["python3", "/opt/boxcutter/boxcutter.py"]
CMD ["--help"]

FROM base AS slim
COPY boxcutter /opt/boxcutter/boxcutter
COPY boxcutter.py /opt/boxcutter/boxcutter.py

FROM base AS full
RUN apk add --no-cache \
        openjdk17-jre \
        chromium chromium-chromedriver firefox geckodriver \
        libpcap-dev nss freetype harfbuzz ttf-freefont
ENV HTTPX_NO_COLOR=1

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
