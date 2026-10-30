"""Narrow Multica read client plus the credential needed for its WebSocket auth frame."""

from __future__ import annotations

from .workspace_api import WorkspaceApiClient


class WatcherApiClient(WorkspaceApiClient):
    def __init__(self, origin: str, pat: str, workspace_id: str, *, timeout: float):
        super().__init__(origin, pat, workspace_id, timeout=timeout)
        self.websocket_token = pat


def watcher_api(origin: str, pat: str, workspace_id: str, *, timeout: float) -> WatcherApiClient:
    return WatcherApiClient(origin, pat, workspace_id, timeout=timeout)
