"""Hermes plugin entry point for the restricted Multica bridge."""

from __future__ import annotations

import sys
from pathlib import Path

# Directory plugins also expose sibling packages used by the CLI distribution.
_plugin_root = str(Path(__file__).resolve().parent)
if _plugin_root not in sys.path:
    sys.path.insert(0, _plugin_root)

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
