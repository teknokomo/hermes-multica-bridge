"""Hermes plugin entry point for the restricted Multica bridge."""

from __future__ import annotations

from pathlib import Path

try:
    from .bridge.tool import register as _register_tools
except ImportError:  # Support standalone validators that import this file as __init__.
    from bridge.tool import register as _register_tools


def register(ctx) -> None:
    """Register bridge tools and the packaged operator-bounded usage skill."""
    _register_tools(ctx)
    register_skill = getattr(ctx, "register_skill", None)
    if not callable(register_skill):
        return
    skill_path = Path(__file__).resolve().parent / "skills" / "hermes-multica-bridge" / "SKILL.md"
    register_skill("hermes-multica-bridge", skill_path)

__all__ = ["register"]
