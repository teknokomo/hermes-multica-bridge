"""Local, deterministic runtime routing for canonical Multica agents."""

from .config import RouterConfig, RouterConfigError
from .policy import Resolution, ResolutionError, resolve_runtime

__all__ = [
    "Resolution",
    "ResolutionError",
    "RouterConfig",
    "RouterConfigError",
    "resolve_runtime",
]
