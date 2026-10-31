"""Safe, model-facing bridge errors."""

from __future__ import annotations


class BridgeError(Exception):
    """An expected failure with a stable, non-sensitive error code."""

    def __init__(self, code: str, message: str, *, retryable: bool = False):
        super().__init__(message)
        self.code = code
        self.message = message
        self.retryable = retryable
