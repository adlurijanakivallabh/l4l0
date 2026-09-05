"""Payload intelligence — a tagged corpus + resolver + context-aware mutation.

Self-owned, inspectable payloads (never fetch-and-run external exploit code).
OOB payloads carry an ``{{OAST_URL}}`` / ``{{OAST_DOMAIN}}`` placeholder resolved
against the self-hosted OAST server for blind detection.
"""

from .corpus import CORPUS, Payload
from .resolver import mutate, resolve_value, select

__all__ = ["CORPUS", "Payload", "mutate", "resolve_value", "select"]
