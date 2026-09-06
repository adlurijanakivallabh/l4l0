# L4L0 runtime image — the disposable per-scan container's filesystem.
#
# Ships a broad best-in-class arsenal so the agent can work offline; the agent
# can still `apt/pip/go/cargo install` anything else at runtime (in-container
# root + network). Host isolation is enforced at `docker run` time by the
# RuntimeContainer flags (cap-drop, no mounts, no socket) — NOT here.
#
# This image is large (multi-GB) and slow to build; build on demand:
#   docker build -t lalo-runtime:latest -f docker/lalo-runtime.Dockerfile .
FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive \
    GOBIN=/usr/local/bin \
    PATH="/usr/local/bin:/root/.cargo/bin:${PATH}"

# --- OS + language toolchains + apt-available security tools ---
# metasploit-framework: Phase 1, cai pass — cai integrates Metasploit directly
# (a `pymetasploit3` RPC-client dependency in its own host-side devcontainer
# requirements.txt). That RPC-client shape is the wrong fit here: it would mean
# L4L0's own host process holding a network client into an exploitation
# framework, when the whole point of this project's containment model is that
# risky work happens *inside* the disposable container via the free shell, not
# from a host-side client library. The transferable idea is narrower and
# simpler: the arsenal was missing the single most standard exploitation
# framework for network-service RCE proof/chaining, so the agent can just
# `msfconsole -q -x '...'` like any other installed tool — no RPC daemon, no
# host reach, no hardcoded credentials (cai's own devcontainer ships an
# msfrpcd listener with a hardcoded password on container start; not adopted).
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl wget git jq unzip build-essential pkg-config \
      python3 python3-pip python3-venv pipx \
      golang-go cargo \
      nmap netcat-traditional dnsutils whois \
      nikto sqlmap whatweb wafw00f hydra medusa \
      radare2 gdb binwalk \
      metasploit-framework \
      seclists wordlists \
    && rm -rf /var/lib/apt/lists/*

# --- Go-based recon/exploitation tools (ProjectDiscovery + others) ---
RUN for pkg in \
      github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
      github.com/projectdiscovery/httpx/cmd/httpx@latest \
      github.com/projectdiscovery/dnsx/cmd/dnsx@latest \
      github.com/projectdiscovery/naabu/v2/cmd/naabu@latest \
      github.com/projectdiscovery/katana/cmd/katana@latest \
      github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
      github.com/ffuf/ffuf/v2@latest \
      github.com/hahwul/dalfox/v2@latest \
      github.com/lc/gau/v2/cmd/gau@latest \
      github.com/tomnomnom/waybackurls@latest \
      github.com/PentestPad/subzy@latest \
      github.com/sensepost/gowitness@latest \
    ; do go install "$pkg" || echo "WARN: go install $pkg failed"; done \
    && nuclei -update-templates || true

# --- Rust: feroxbuster (recursive content discovery) ---
RUN cargo install feroxbuster || echo "WARN: feroxbuster install failed"

# --- Python tooling via pipx (isolated) ---
RUN for tool in \
      arjun corsy oralyzer sstimap \
      scoutsuite prowler pacu \
      netexec bloodhound-ce-python \
      trufflehog3 semgrep \
      graphw00f clairvoyance \
    ; do pipx install "$tool" || echo "WARN: pipx install $tool failed"; done \
    && pipx install --include-deps pwntools || true

# --- Standalone binaries (SCA / secrets / TLS) ---
RUN curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh \
      | sh -s -- -b /usr/local/bin || echo "WARN: grype install failed" \
 && curl -sSfL https://raw.githubusercontent.com/google/osv-scanner/main/install.sh \
      | sh -s -- -b /usr/local/bin || echo "WARN: osv-scanner install failed"

WORKDIR /work
