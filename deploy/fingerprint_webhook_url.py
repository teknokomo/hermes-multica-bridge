#!/usr/bin/env python3
"""Print only the SHA-256 fingerprint of a hidden, validated Multica webhook URL."""

from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from bridge.errors import BridgeError
from bridge.webhook import webhook_url_fingerprint


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Fingerprint one verified Multica trigger URL")
    parser.add_argument("--origin", required=True, help="Expected HTTPS Multica origin")
    args = parser.parse_args(argv)
    if not sys.stdin.isatty():
        print("A local interactive terminal is required.", file=sys.stderr)
        return 1
    value = getpass.getpass("Paste the verified Multica trigger URL (input hidden): ").strip()
    try:
        fingerprint = webhook_url_fingerprint(value, args.origin)
    except BridgeError:
        print("The URL is invalid or does not belong to the configured Multica origin/path.", file=sys.stderr)
        return 1
    print(fingerprint)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
