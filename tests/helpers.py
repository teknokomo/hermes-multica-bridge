from __future__ import annotations

from bridge.configuration import ConnectionConfig
from bridge.routes import BridgeConfig, IsolatedCredentials
from bridge.webhook import webhook_url_fingerprint

TEST_ORIGIN = "https://multica.example.org"
TEST_WEBHOOK_URL = f"{TEST_ORIGIN}/api/webhooks/autopilots/awt_{'A' * 43}"
TEST_HMAC_SECRET = "fake-hmac-secret-for-offline-tests"
TEST_PAT = "fake-read-only-pat"
TEST_GATEWAY_UNIT = "hermes-gateway.service"
TEST_ROUTE_ID = "018f0000-0000-7000-8000-000000000001"
TEST_CONNECTION_ID = "018f0000-0000-7000-8000-000000000002"
TEST_WORKSPACE_KEY = "018f0000-0000-7000-8000-000000000003"
TEST_INSTANCE_ID = "r-" + TEST_ROUTE_ID.replace("-", "")
TEST_ROUTE_POLICY_FINGERPRINT = "route-policy-" + ("a" * 64)


def sample_request(
    *,
    board: str = "example-board",
    task_id: str = "task_12345678",
    run_id: str = "12",
    title: str = "Example task",
    body: str = "Do the example work.",
) -> dict:
    return {
        "source": {
            "system": "hermes",
            "board": board,
            "task_id": task_id,
            "run_id": run_id,
        },
        "task": {"title": title, "body": body},
    }


def standard_connection(**overrides) -> ConnectionConfig:
    values = {
        "security_mode": "standard",
        "enabled": True,
        "multica_origin": TEST_ORIGIN,
        "workspace_id": "workspace-example",
        "autopilot_id": "autopilot-example",
        "trigger_id": "trigger-example",
        "event": "hermes.task.dispatched",
        "source_boards": ("example-board",),
        "request_timeout_seconds": 10,
        "max_response_bytes": 16_384,
        "max_payload_bytes": 65_536,
        "max_requests_per_window": 5,
        "window_seconds": 600,
        "max_attempts_per_request": 2,
        "result_tracking_enabled": True,
        "hmac_enabled": True,
        "isolated_instance_id": "",
    }
    values.update(overrides)
    return ConnectionConfig(**values)


def isolated_bridge_config(**connection_overrides) -> BridgeConfig:
    connection = standard_connection(
        security_mode="isolated",
        isolated_instance_id=TEST_INSTANCE_ID,
        **connection_overrides,
    )
    return BridgeConfig(
        allowed_peer_uids=frozenset({12345}),
        trusted_gateway_unit=TEST_GATEWAY_UNIT,
        route_id=TEST_ROUTE_ID,
        connection_id=TEST_CONNECTION_ID,
        workspace_key=TEST_WORKSPACE_KEY,
        route_policy_fingerprint=TEST_ROUTE_POLICY_FINGERPRINT,
        connection=connection,
        credentials=IsolatedCredentials(
            webhook_url_ref="HMB_WEBHOOK_URL",
            webhook_sha256=webhook_url_fingerprint(TEST_WEBHOOK_URL, TEST_ORIGIN),
            hmac_signing_secret_ref="HMB_HMAC_SIGNING_SECRET",
            multica_pat_ref="HMB_MULTICA_PAT",
        ),
    )


def isolated_config_text(
    *,
    enabled: bool = False,
    result_tracking: bool = False,
    include_hmac_ref: bool = True,
    include_pat_ref: bool = True,
) -> str:
    hmac_ref = '"HMB_HMAC_SIGNING_SECRET"' if include_hmac_ref else '""'
    multica_pat_ref = '"HMB_MULTICA_PAT"' if result_tracking and include_pat_ref else '""'
    return f"""default_deny = true

[ipc]
allowed_peer_uids = [12345]
trusted_gateway_unit = "{TEST_GATEWAY_UNIT}"

[route]
route_id = "{TEST_ROUTE_ID}"
connection_id = "{TEST_CONNECTION_ID}"
workspace_key = "{TEST_WORKSPACE_KEY}"
route_policy_fingerprint = "{TEST_ROUTE_POLICY_FINGERPRINT}"

[connection]
security_mode = "isolated"
enabled = {"true" if enabled else "false"}
multica_origin = "{TEST_ORIGIN}"
workspace_id = "workspace-example"
autopilot_id = "autopilot-example"
trigger_id = "trigger-example"
event = "hermes.task.dispatched"
source_boards = ["example-board"]
request_timeout_seconds = 10
max_response_bytes = 16384
max_payload_bytes = 65536
max_requests_per_window = 5
window_seconds = 600
max_attempts_per_request = 2
result_tracking_enabled = {"true" if result_tracking else "false"}
hmac_enabled = true
isolated_instance_id = "{TEST_INSTANCE_ID}"

[credentials]
webhook_url_ref = "HMB_WEBHOOK_URL"
webhook_sha256 = "{webhook_url_fingerprint(TEST_WEBHOOK_URL, TEST_ORIGIN)}"
hmac_signing_secret_ref = {hmac_ref}
multica_pat_ref = {multica_pat_ref}
"""
