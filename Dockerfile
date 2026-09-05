# L4L0 disposable runtime container image (src/lalo/runtime/container.py's
# RuntimeContainer default: "lalo-runtime:latest"). This image never reaches
# the host: no bind-mounts, no Docker socket, --cap-drop ALL by default
# (container.py enforces this at the run-flag level, not this file).
#
# CLAUDE.md's own convention: "the arsenal is a curated starting image; the
# agent can install anything else at runtime" (free shell, root, apt/pip/go
# install all work inside this disposable container). This is deliberately a
# lean starting set, not an attempt to replicate a reference agent's much
# larger, slower-to-build tool roster (nuclei/trufflehog/trivy/semgrep/browser
# automation, ...) - those are exactly the kind of thing the agent installs
# itself, on demand, only when a mission actually calls for them, rather than
# paying their build/pull cost on every disposable container's startup.
#
# Kali's own repos are the base specifically for nmap/sqlmap being current,
# maintained, best-in-class builds rather than whatever's in a generic distro's
# repos - the "best-in-class tools" convention, applied to the base image
# choice itself.
FROM kalilinux/kali-rolling:latest

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        curl \
        wget \
        ca-certificates \
        dnsutils \
        netcat-traditional \
        nmap \
        sqlmap \
        jq \
        git \
        python3 \
        python3-pip \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

WORKDIR /work
