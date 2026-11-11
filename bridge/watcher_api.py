"""Narrow Multica read client plus the credential needed for its WebSocket auth frame."""

from __future__ import annotations

import re
from urllib.parse import quote

from .errors import BridgeError
from .workspace_api import WorkspaceApiClient


class WatcherApiClient(WorkspaceApiClient):
    def __init__(self, origin: str, pat: str, workspace_id: str, *, timeout: float):
        super().__init__(origin, pat, workspace_id, timeout=timeout)
        self.websocket_token = pat
        self._workspace_slug: str | None = None

    def issue_link(self, identifier: str) -> str:
        if self._workspace_slug is None:
            result = self._request("GET", f"/api/workspaces/{quote(self.workspace_id, safe='')}", expected="workspace")
            if (not isinstance(result, dict) or result.get("id") != self.workspace_id
                    or not isinstance(result.get("slug"), str)
                    or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}", result["slug"])):
                raise BridgeError("invalid_api_response", "Multica returned an invalid workspace link context.")
            self._workspace_slug = result["slug"]
        return f"{self.origin}/{quote(self._workspace_slug, safe='')}/issues/{quote(identifier, safe='')}"


def watcher_api(origin: str, pat: str, workspace_id: str, *, timeout: float) -> WatcherApiClient:
    return WatcherApiClient(origin, pat, workspace_id, timeout=timeout)
