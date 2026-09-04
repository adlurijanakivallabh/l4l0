# ReachAgent agent sandbox (v4 R4) — a disposable, per-scan container the
# autonomous loop can run genuinely arbitrary commands in. No flag allowlist,
# no per-tool wrapper deciding what's "safe" — the containment IS the safety
# boundary (no host filesystem mount, never --network host, and — via
# agent_shell.py's own post-start iptables setup inside this container's
# network namespace — outbound egress firewalled to the scan's own
# ScopeGuard-allowed hosts), not a restriction on what runs inside it.
# `iptables` below is that firewall tool, applied by the Python side after
# the container starts — not used at build time.
#
# Kali base: the same distribution this project's own dev environment already
# runs, so every tool named below is a real, already-known-working `apt`
# package — no bespoke binary downloads, no version drift from what's already
# proven to work on this host.
FROM kalilinux/kali-rolling

RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    feroxbuster \
    hydra \
    john \
    ffuf \
    sqlmap \
    curl \
    python3 \
    python3-pip \
    git \
    seclists \
    ca-certificates \
    iptables \
    && rm -rf /var/lib/apt/lists/*

# Full, uncurated PayloadsAllTheThings — deliberately NOT the project's own
# curated third_party/ snapshot (that stays serving the separate internal
# deterministic-driver payload resolver). The model gets the complete
# upstream repo here, technique write-ups included, to read and use freely.
RUN git clone --depth 1 https://github.com/swisskyrepo/PayloadsAllTheThings.git \
    /opt/PayloadsAllTheThings

# SecLists is already installed in full via the `seclists` apt package above
# (lands at /usr/share/seclists/ — the same real path already proven working
# on the host this image is modeled on).

WORKDIR /work
CMD ["sleep", "infinity"]
