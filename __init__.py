"""Hermes plugin entry point for the restricted Multica bridge."""

from __future__ import annotations

try:
    from .bridge.tool import register
except ImportError:  # Support standalone validators that import this file as __init__.
    from bridge.tool import register

__all__ = ["register"]
