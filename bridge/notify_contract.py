"""Shared, non-secret contract values for the notify readiness IPC."""

READINESS_PROFILES = frozenset({"default", "om73"})
READINESS_SOCKET_PATH = "/run/hermes-multica-notify-readiness/readiness.sock"
