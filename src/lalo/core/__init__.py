"""Core primitives shared across every L4L0 subsystem.

Nothing here does I/O against a target. This package holds the typed error
hierarchy, structured+redacting logging, the shared secret-redaction module
(the single source of truth every other subsystem imports — no subsystem rolls
its own regex set), configuration, and the multi-provider model router.
"""
