# syntax=docker/dockerfile:1
#
# Multi-stage build: `docker compose up -d --build` (or `docker build .`) produces
# the complete image from source. No prebuilt binary in the build context is needed,
# so a fresh `git clone` builds — dist/ is git-ignored and is no longer required.
#
#   frontend (web) -> Go binary with embedded UI (build) -> runtime image
#
# The Go binary is produced by build.sh with the same flags the release workflow's
# binaries job uses, so the image binary and the published release binary come from
# one source.

# ---------------------------------------------------------------- frontend ---
# Pinned to the Node 22 line the CI/release workflows use. On the build platform
# only; the frontend static export is architecture-independent.
FROM --platform=$BUILDPLATFORM node:22-bookworm-slim AS web
ARG NPM_REGISTRY=""
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN set -eux; \
    reg="${NPM_REGISTRY}"; \
    if [ -z "$reg" ]; then \
      reg="$(node -e 'const urls=["https://registry.npmjs.org","https://registry.yarnpkg.com","https://registry.npmmirror.com","https://mirrors.cloud.tencent.com/npm"];Promise.any(urls.map(u=>fetch(u+"/typescript",{signal:AbortSignal.timeout(3000)}).then(r=>r.ok?u:Promise.reject()))).then(u=>process.stdout.write(u)).catch(()=>process.stdout.write("https://registry.npmjs.org"))')"; \
    fi; \
    echo "[npm] selected fastest registry: $reg"; \
    npm config set registry "$reg"; \
    npm ci --ignore-scripts
COPY web/ ./
RUN npm run build:static

# ------------------------------------------------------------- Go binary ---
# Pinned to the Go 1.26 line (matches go.mod and the release binaries job). The
# binary is CGO-free, so this stage runs on the build platform and cross-compiles
# to $TARGETARCH without QEMU.
FROM --platform=$BUILDPLATFORM golang:1.26-bookworm AS build
ARG GOPROXY=""
WORKDIR /src
COPY go.mod go.sum ./
RUN set -eux; \
    gp="${GOPROXY}"; \
    if [ -z "$gp" ]; then \
      best="$({ for u in "https://proxy.golang.org" "https://goproxy.io" "https://goproxy.cn" "https://mirrors.aliyun.com/goproxy"; do \
        ( t="$(curl -fsSL -o /dev/null --connect-timeout 2 --max-time 3 -w "%{time_total}" "$u" 2>/dev/null)" && echo "$t $u" ) & \
      done; wait; } | sort -n | awk 'NR==1{print $2}')"; \
      gp="${best:-https://proxy.golang.org},https://proxy.golang.org,direct"; \
    fi; \
    echo "[go] selected GOPROXY chain: $gp"; \
    GOPROXY="$gp" go mod download
COPY . .
# Reuse the frontend built above; build.sh skips its own frontend step.
COPY --from=web /src/web/out ./server/webui/dist
ARG ARTEX_VERSION=dev
ARG TARGETOS
ARG TARGETARCH
# Same flags as the release binaries job (ARTEX_COMPRESS=0, -trimpath,
# -X main.version), driven through build.sh so there is one build path.
RUN ARTEX_SKIP_FRONTEND=1 \
    ARTEX_SKIP_NPM_CI=1 \
    ARTEX_COMPRESS=0 \
    ARTEX_OUTPUT=/out/artex \
    ARTEX_BUILD_VERSION="${ARTEX_VERSION}" \
    bash ./build.sh --target "${TARGETOS:-linux}/${TARGETARCH:-amd64}"

# ------------------------------------------------------- third-party tools ---
# Web-recon toolbox (drost-community take 1, #100): pinned release binaries, staged
# on the build platform and copied into /usr/local/bin of the runtime image so hunt
# workers can run them directly through their Bash tool. Versions pinned per tool;
# upgrade deliberately. Each archive is verified against the checksums file of its
# own GitHub release (exact asset name, sha256). That file comes from the same
# release channel as the archive, so it catches corrupted or swapped downloads and
# moved tags, not a compromised publisher. sqlmap has no release binaries: it is a
# shallow clone of a pinned tag, checked against the expected commit.
FROM --platform=$BUILDPLATFORM debian:bookworm-slim AS tools
ARG TARGETARCH
ARG NUCLEI_VERSION=v3.11.1
ARG NUCLEI_TEMPLATES_VERSION=v10.1.3
ARG HTTPX_VERSION=v1.12.0
ARG SUBFINDER_VERSION=v2.17.0
ARG KATANA_VERSION=v1.8.0
ARG FFUF_VERSION=v2.3.0
ARG DALFOX_VERSION=v3.2.4
ARG SQLMAP_VERSION=1.9.9
ARG SQLMAP_COMMIT=cceda39208b5aad478de2c3f731df4239d9881f6
ARG CHISEL_VERSION=v1.10.1
ARG KUBECTL_VERSION=v1.31.4
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl git unzip \
    && rm -rf /var/lib/apt/lists/*
RUN set -eux; \
    case "${TARGETARCH:-amd64}" in \
      amd64) PD_ARCH=amd64; FFUF_ARCH=amd64; DALFOX_ARCH=x86_64 ;; \
      arm64) PD_ARCH=arm64; FFUF_ARCH=arm64; DALFOX_ARCH=aarch64 ;; \
      *) echo "unsupported architecture: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    mkdir -p /out; \
    fetch() { base="$1"; asset="$2"; sums="$3"; name="$4"; \
      rm -rf /tmp/t; mkdir -p /tmp/t/x; \
      curl -fsSL "$base/$asset" -o "/tmp/t/$asset"; \
      curl -fsSL "$base/$sums" -o /tmp/t/sums.txt; \
      want="$(awk -v a="$asset" '$2 == a || $2 == "*" a { print $1 }' /tmp/t/sums.txt)"; \
      if [ -z "$want" ]; then echo "no checksum entry for $asset" >&2; exit 1; fi; \
      got="$(sha256sum "/tmp/t/$asset" | cut -d' ' -f1)"; \
      if [ "$want" != "$got" ]; then echo "checksum mismatch for $asset: want $want got $got" >&2; exit 1; fi; \
      case "$asset" in *.zip) unzip -q "/tmp/t/$asset" -d /tmp/t/x ;; *) tar -xzf "/tmp/t/$asset" -C /tmp/t/x ;; esac; \
      find /tmp/t/x -type f -name "$name" -exec install -m 0755 {} /out/ \; ; \
      [ -x "/out/$name" ] || { echo "$name not found in $asset" >&2; exit 1; }; \
      rm -rf /tmp/t; }; \
    gh="https://github.com"; \
    fetch "$gh/projectdiscovery/nuclei/releases/download/$NUCLEI_VERSION" \
      "nuclei_${NUCLEI_VERSION#v}_linux_${PD_ARCH}.zip" "nuclei_${NUCLEI_VERSION#v}_checksums.txt" nuclei; \
    fetch "$gh/projectdiscovery/httpx/releases/download/$HTTPX_VERSION" \
      "httpx_${HTTPX_VERSION#v}_linux_${PD_ARCH}.zip" "httpx_${HTTPX_VERSION#v}_checksums.txt" httpx; \
    fetch "$gh/projectdiscovery/subfinder/releases/download/$SUBFINDER_VERSION" \
      "subfinder_${SUBFINDER_VERSION#v}_linux_${PD_ARCH}.zip" "subfinder_${SUBFINDER_VERSION#v}_checksums.txt" subfinder; \
    fetch "$gh/projectdiscovery/katana/releases/download/$KATANA_VERSION" \
      "katana_${KATANA_VERSION#v}_linux_${PD_ARCH}.zip" "katana-${KATANA_VERSION#v}-checksums.txt" katana; \
    fetch "$gh/ffuf/ffuf/releases/download/$FFUF_VERSION" \
      "ffuf_${FFUF_VERSION#v}_linux_${FFUF_ARCH}.tar.gz" "ffuf_${FFUF_VERSION#v}_checksums.txt" ffuf; \
    fetch "$gh/hahwul/dalfox/releases/download/$DALFOX_VERSION" \
      "dalfox-${DALFOX_VERSION}-linux-${DALFOX_ARCH}-musl.tar.gz" "dalfox-${DALFOX_VERSION}-linux-${DALFOX_ARCH}-musl.tar.gz.sha256" dalfox; \
    ch_asset="chisel_${CHISEL_VERSION#v}_linux_${PD_ARCH}.gz"; \
    curl -fsSL "$gh/jpillora/chisel/releases/download/${CHISEL_VERSION}/${ch_asset}" -o "/tmp/${ch_asset}"; \
    curl -fsSL "$gh/jpillora/chisel/releases/download/${CHISEL_VERSION}/chisel_${CHISEL_VERSION#v}_checksums.txt" -o /tmp/chisel_sums.txt; \
    want="$(awk -v a="$ch_asset" '$2 == a { print $1 }' /tmp/chisel_sums.txt)"; \
    if [ -z "$want" ]; then echo "no checksum entry for $ch_asset" >&2; exit 1; fi; \
    got="$(sha256sum "/tmp/${ch_asset}" | cut -d' ' -f1)"; \
    if [ "$want" != "$got" ]; then echo "checksum mismatch for $ch_asset: want $want got $got" >&2; exit 1; fi; \
    gzip -dc "/tmp/${ch_asset}" > /out/chisel && chmod 0755 /out/chisel; \
    rm -f "/tmp/${ch_asset}" /tmp/chisel_sums.txt; \
    curl -fsSL "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/${PD_ARCH}/kubectl" -o /out/kubectl; \
    curl -fsSL "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/${PD_ARCH}/kubectl.sha256" -o /tmp/kubectl.sha256; \
    echo "$(cat /tmp/kubectl.sha256)  /out/kubectl" | sha256sum -c -; \
    chmod 0755 /out/kubectl && rm -f /tmp/kubectl.sha256; \
    git clone --quiet --depth 1 --branch "$SQLMAP_VERSION" https://github.com/sqlmapproject/sqlmap /opt/sqlmap; \
    commit="$(git -C /opt/sqlmap rev-parse HEAD)"; \
    if [ "$commit" != "$SQLMAP_COMMIT" ]; then echo "sqlmap commit mismatch: want $SQLMAP_COMMIT got $commit" >&2; exit 1; fi; \
    rm -rf /opt/sqlmap/.git; \
    curl -fsSL "https://github.com/projectdiscovery/nuclei-templates/archive/refs/tags/${NUCLEI_TEMPLATES_VERSION}.tar.gz" -o /tmp/nt.tar.gz; \
    mkdir -p /opt/nuclei-templates; \
    tar -xzf /tmp/nt.tar.gz -C /opt/nuclei-templates --strip-components=1; \
    rm -rf /tmp/nt.tar.gz /opt/nuclei-templates/.git /opt/nuclei-templates/.github

# ---------------------------------------------------------------- runtime ---
FROM python:3.12-slim-bookworm
ARG TARGETARCH
# Common tools: ripgrep / curl / vim, plus recon and MLPS service-audit staples (add/remove as needed).
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates ripgrep curl wget vim git jq unzip xz-utils \
      dnsutils iputils-ping netcat-openbsd inetutils-telnet whois nmap \
      hydra sslscan smbclient redis-tools postgresql-client default-mysql-client \
      openssh-client proxychains4 socat \
      ldap-utils krb5-user snmp cups-client iproute2 \
    && rm -rf /var/lib/apt/lists/*
# Node 22 from the official nodejs.org tarball, verified against its SHASUMS256.txt:
# bookworm's apt nodejs is 18, Playwright requires >=20, and 20 is end-of-life.
# 22 matches the CI and release workflows.
ARG NODE_VERSION=22.23.4
RUN set -eux; \
    case "${TARGETARCH:-amd64}" in \
      amd64) NODE_ARCH=x64 ;; \
      arm64) NODE_ARCH=arm64 ;; \
      *) echo "unsupported architecture: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    base="https://nodejs.org/dist/v${NODE_VERSION}"; \
    asset="node-v${NODE_VERSION}-linux-${NODE_ARCH}.tar.xz"; \
    curl -fsSL "$base/$asset" -o "/tmp/$asset"; \
    curl -fsSL "$base/SHASUMS256.txt" -o /tmp/SHASUMS256.txt; \
    want="$(awk -v a="$asset" '$2 == a { print $1 }' /tmp/SHASUMS256.txt)"; \
    if [ -z "$want" ]; then echo "no checksum entry for $asset" >&2; exit 1; fi; \
    got="$(sha256sum "/tmp/$asset" | cut -d' ' -f1)"; \
    if [ "$want" != "$got" ]; then echo "checksum mismatch for $asset: want $want got $got" >&2; exit 1; fi; \
    tar -xJf "/tmp/$asset" -C /usr/local --strip-components=1 --no-same-owner; \
    rm -f "/tmp/$asset" /tmp/SHASUMS256.txt; \
    node --version; npm --version
# Pinned, checksum-verified recon binaries, sqlmap, and offline nuclei-templates from the tools stage.
COPY --from=tools /out/ /usr/local/bin/
COPY --from=tools /opt/sqlmap /opt/sqlmap
COPY --from=tools /opt/nuclei-templates /opt/nuclei-templates
ENV NUCLEI_TEMPLATES_DIR=/opt/nuclei-templates \
    ARTEX_NUCLEI_TEMPLATES_DIR=/opt/nuclei-templates
RUN set -eux; \
    ln -s /opt/sqlmap/sqlmap.py /usr/local/bin/sqlmap; \
    ln -sfn /opt/nuclei-templates /root/nuclei-templates; \
    nuclei -version >/dev/null; httpx -version; subfinder -version; katana -version; \
    ffuf -V >/dev/null; dalfox --version >/dev/null; sqlmap --version >/dev/null

# Auto-select the fastest global/regional PyPI mirror (Americas/Global Fastly,
# Europe SUNET, and APAC/CN TUNA/Aliyun/Tencent/USTC) via parallel latency probe,
# writing /etc/pip.conf with extra-index-url fallback so both bbot and pentest-tools
# venv builds run at peak speed regardless of where the user's host is located.
ARG PIP_INDEX_URL=""
ARG NPM_REGISTRY=""
RUN set -eux; \
    primary="${PIP_INDEX_URL}"; \
    fallback="https://pypi.org/simple"; \
    if [ -z "$primary" ]; then \
      ranked="$({ for u in \
        "https://pypi.org/simple" \
        "https://mirror.accum.se/mirror/pypi.org/simple" \
        "https://mirrors.aliyun.com/pypi/simple" \
        "https://mirrors.cloud.tencent.com/pypi/simple" \
        "https://pypi.tuna.tsinghua.edu.cn/simple" \
        "https://pypi.mirrors.ustc.edu.cn/simple"; do \
        ( t="$(curl -fsSL -o /dev/null --connect-timeout 2 --max-time 3 -w "%{time_total}" "$u/pip/" 2>/dev/null)" && echo "$t $u" ) & \
      done; wait; } | sort -n | awk '{print $2}')"; \
      primary="$(printf '%s\n' "$ranked" | sed -n '1p')"; \
      second="$(printf '%s\n' "$ranked" | sed -n '2p')"; \
      primary="${primary:-https://pypi.org/simple}"; \
      if [ -n "$second" ] && [ "$second" != "$primary" ]; then \
        fallback="$second https://pypi.org/simple"; \
      fi; \
    fi; \
    echo "[pip] selected fastest PyPI mirror: $primary (fallback: $fallback)"; \
    printf '[global]\nindex-url = %s\nextra-index-url = %s\ntimeout = 30\nretries = 5\n' "$primary" "$fallback" > /etc/pip.conf; \
    reg="${NPM_REGISTRY}"; \
    if [ -z "$reg" ]; then \
      best_npm="$({ for u in \
        "https://registry.npmjs.org" \
        "https://registry.yarnpkg.com" \
        "https://registry.npmmirror.com" \
        "https://mirrors.cloud.tencent.com/npm"; do \
        ( t="$(curl -fsSL -o /dev/null --connect-timeout 2 --max-time 3 -w "%{time_total}" "$u/typescript" 2>/dev/null)" && echo "$t $u" ) & \
      done; wait; } | sort -n | awk 'NR==1{print $2}')"; \
      reg="${best_npm:-https://registry.npmjs.org}"; \
    fi; \
    echo "[npm] selected fastest registry: $reg"; \
    npm config set registry "$reg"

# bbot recursive recon orchestrator (#117): blacklanternsecurity/bbot, AGPL-3.0
# (same license as ARTEX; standalone CLI dependency, not linked code). Pinned
# version, own venv to isolate from the image python. Core Python module
# dependencies (wafw00f, paramminer, lightfuzz, sslcert) are pre-warmed directly;
# browser screenshots are provided by playwright-cli below.
ARG BBOT_VERSION=3.0.2
RUN set -eux; \
    python -m venv /opt/bbot; \
    /opt/bbot/bin/pip install --no-cache-dir "bbot==${BBOT_VERSION}" wafw00f; \
    ln -s /opt/bbot/bin/bbot /usr/local/bin/bbot; \
    bbot --version >/dev/null; \
    bbot -y --ignore-failed-deps --dry-run -t example.com -m wafw00f,paramminer_getparams,lightfuzz,sslcert >/dev/null 2>&1 || true; \
    bbot --no-deps --ignore-failed-deps --dry-run -t example.com -m wafw00f,paramminer_getparams,lightfuzz,sslcert --no-color >/tmp/bbot-dry.log 2>&1 || true; \
    ! grep -qE "CRITICAL" /tmp/bbot-dry.log || { cat /tmp/bbot-dry.log; exit 1; }; \
    rm -f /tmp/bbot-dry.log

# Post-exploitation, Active Directory, lateral-movement, and static code-audit CLI
# toolkits in isolated venvs to prevent dependency version conflicts:
#   - /opt/pentest-tools: impacket, bloodhound, certipy-ad, adidnsdump (PyPI)
#   - /opt/semgrep:       semgrep static code analyzer (PyPI)
#   - /opt/netexec:       NetExec (nxc / netexec, from GitHub tarball + HTTP/1.1 git)
# Guarded at runtime by lateral_gate, electronic fence, and prod_safe_mode.
RUN set -eux; \
    git config --global http.version HTTP/1.1; \
    git config --global http.postBuffer 524288000; \
    apt-get update && apt-get install -y --no-install-recommends gcc g++ libffi-dev libssl-dev libkrb5-dev; \
    python -m venv /opt/pentest-tools; \
    /opt/pentest-tools/bin/pip install --no-cache-dir \
      impacket bloodhound certipy-ad adidnsdump; \
    python -m venv /opt/semgrep; \
    /opt/semgrep/bin/pip install --no-cache-dir semgrep; \
    for bin in /opt/pentest-tools/bin/impacket-* /opt/pentest-tools/bin/bloodhound-python \
               /opt/pentest-tools/bin/certipy /opt/pentest-tools/bin/adidnsdump \
               /opt/semgrep/bin/semgrep; do \
      if [ -e "$bin" ]; then ln -sf "$bin" "/usr/local/bin/$(basename "$bin")"; fi; \
    done; \
    semgrep --version >/dev/null

ARG NETEXEC_VERSION=v1.5.1
RUN set -eux; \
    python -m venv /opt/netexec; \
    curl --http1.1 -fsSL --retry 5 --retry-all-errors --retry-delay 3 \
      "https://github.com/Pennyw0rth/NetExec/archive/refs/tags/${NETEXEC_VERSION}.tar.gz" -o /tmp/netexec.tar.gz; \
    mkdir -p /tmp/netexec-src; \
    tar -xzf /tmp/netexec.tar.gz -C /tmp/netexec-src --strip-components=1; \
    ok=0; \
    for attempt in 1 2 3; do \
      if POETRY_DYNAMIC_VERSIONING_BYPASS="${NETEXEC_VERSION#v}" /opt/netexec/bin/pip install --no-cache-dir /tmp/netexec-src; then ok=1; break; fi; \
      echo "[netexec] pip install attempt ${attempt} failed, retrying in 5s..." >&2; \
      sleep 5; \
    done; \
    [ "$ok" = "1" ]; \
    rm -rf /tmp/netexec.tar.gz /tmp/netexec-src; \
    for bin in /opt/netexec/bin/nxc /opt/netexec/bin/netexec; do \
      if [ -e "$bin" ]; then ln -sf "$bin" "/usr/local/bin/$(basename "$bin")"; fi; \
    done; \
    apt-get purge -y --auto-remove gcc g++ libffi-dev libssl-dev libkrb5-dev; \
    rm -rf /var/lib/apt/lists/*; \
    chisel --help >/dev/null; kubectl version --client >/dev/null; nxc --version >/dev/null


# Preinstall Playwright MCP and CLI (globally) so no npx network download is needed at runtime.
# @playwright/mcp: browser MCP runs directly via `npx @playwright/mcp` (installed globally, no -y/@latest needed).
# @playwright/cli: provides playwright-cli, verified with --help right after install.
# Then install playwright (browser management) and preinstall chromium plus its system
# dependencies via --with-deps, so MCP/CLI work on first start inside the container
# without downloading browsers over the network. All three are pinned; upgrade deliberately.
ARG PLAYWRIGHT_MCP_VERSION=0.0.83
ARG PLAYWRIGHT_CLI_VERSION=0.1.22
ARG PLAYWRIGHT_VERSION=1.64.1
RUN npm install -g "@playwright/mcp@${PLAYWRIGHT_MCP_VERSION}" "@playwright/cli@${PLAYWRIGHT_CLI_VERSION}" "playwright@${PLAYWRIGHT_VERSION}" \
    && playwright-cli --help \
    && playwright install --with-deps chromium \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
# Binary compiled from source in the build stage above.
COPY --from=build /out/artex /app/artex
# Daemon startup script: relaunches the process after a crash and forwards SIGTERM
# to artex — docker stop only signals PID 1; without forwarding, artex never receives it,
# cannot shut down gracefully, and is hard-killed by SIGKILL after 10 seconds.
COPY start.sh /app/start.sh
RUN chmod +x /app/artex /app/start.sh && mkdir -p /app/keys
COPY skills/ /app/skills/
COPY pocs/ /app/pocs/
ENV ARTEX_POCS_DIR=/app/pocs
# persistence points: data/ (SQLite, task files) and keys/ (jwt.key, via ARTEX_JWT_KEY_DIR)
VOLUME ["/app/data", "/app/keys"]
EXPOSE 8787 8788
ENTRYPOINT ["/app/start.sh"]
CMD ["-addr", ":8787", "-proxy", ":8788"]
