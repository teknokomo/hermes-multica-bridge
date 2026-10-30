#!/usr/bin/env python3
"""Rotate one Isolated instance webhook URL after validating its pinned fingerprint."""

from __future__ import annotations

import argparse
import fcntl
import getpass
import json
import os
import re
import stat
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from bridge.configuration import INSTANCE_ID_RE
from bridge.errors import BridgeError
from bridge.routes import load_config
from bridge.webhook import webhook_url_fingerprint
from deploy.configure_isolated_instance import (
    _atomic_write,
    _configuration_journal_path,
    _recover_pending_configuration,
    _validate_directory_chain,
)

CONFIG_ROOT = Path("/etc/hermes-multica-bridge")
WEBHOOK_PIN_RE = re.compile(r'(?m)^webhook_sha256 = "([0-9a-f]{64})"$')
MAX_ROTATION_JOURNAL_BYTES = 100_000


def _instance_paths(instance: str, *, config_root: Path = CONFIG_ROOT) -> tuple[Path, Path]:
    """Build paths only for one validated Isolated instance identifier."""
    if not isinstance(instance, str) or not INSTANCE_ID_RE.fullmatch(instance):
        raise BridgeError("configuration_invalid", "The Isolated instance identifier is invalid.")
    config_root = config_root.resolve()
    credential_root = (config_root / "credentials").resolve()
    config_path = config_root / f"{instance}.toml"
    destination = credential_root / instance / "webhook-url"
    if not destination.resolve(strict=False).is_relative_to(credential_root):
        raise BridgeError("configuration_invalid", "The credential path escapes its trusted root.")
    return config_path, destination


def _replace_webhook_pin(config_text: str, expected: str, replacement: str) -> str:
    matches = list(WEBHOOK_PIN_RE.finditer(config_text))
    if len(matches) != 1 or matches[0].group(1) != expected:
        raise BridgeError("configuration_invalid", "The configured webhook fingerprint could not be updated safely.")
    match = matches[0]
    return config_text[: match.start(1)] + replacement + config_text[match.end(1) :]


def _rotation_journal_path(config_path: Path) -> Path:
    return config_path.with_name(f".{config_path.name}.rotation-journal")


@contextmanager
def _instance_rotation_lock(
    config_path: Path,
    *,
    trusted_root: Path,
    expected_owner_uid: int,
) -> Iterator[None]:
    """Serialize recovery and credential rotation for one Isolated instance."""
    lock_path = config_path.with_name(f".{config_path.name}.rotation.lock")
    _validate_directory_chain(lock_path.parent, trusted_root, expected_owner_uid)
    flags = (
        os.O_CREAT
        | os.O_RDWR
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    try:
        fd = os.open(lock_path, flags, 0o600)
    except OSError as exc:
        raise BridgeError("rotation_lock_unavailable", "The webhook rotation lock is unavailable.") from exc
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != expected_owner_uid
            or info.st_mode & 0o077
            or info.st_nlink != 1
        ):
            raise BridgeError("rotation_lock_invalid", "The webhook rotation lock is unsafe or invalid.")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
        except OSError as exc:
            raise BridgeError("rotation_lock_unavailable", "The webhook rotation lock could not be acquired.") from exc
        yield
    finally:
        os.close(fd)


def _read_webhook_credential(path: Path, *, expected_owner_uid: int) -> str:
    fd: int | None = None
    try:
        fd = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0),
        )
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != expected_owner_uid
            or info.st_mode & 0o077
            or info.st_size > 4096
        ):
            raise BridgeError("credential_invalid", "The current webhook credential is unsafe or invalid.")
        with os.fdopen(fd, "rb") as stream:
            fd = None
            value = stream.read(4097)
        if len(value) > 4096:
            raise BridgeError("credential_invalid", "The current webhook credential is too large.")
        decoded = value.decode("utf-8").strip()
        if not decoded:
            raise BridgeError("credential_invalid", "The current webhook credential is empty.")
        return decoded
    except BridgeError:
        raise
    except (OSError, UnicodeError) as exc:
        raise BridgeError("credential_invalid", "The current webhook credential is unavailable.") from exc
    finally:
        if fd is not None:
            os.close(fd)


def _read_rotation_journal(
    path: Path,
    *,
    instance: str,
    trusted_root: Path,
    expected_owner_uid: int,
) -> dict[str, str] | None:
    try:
        _validate_directory_chain(path.parent, trusted_root, expected_owner_uid)
        fd = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0),
        )
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise BridgeError("rotation_recovery_required", "A pending webhook rotation journal is unsafe or unavailable.") from exc

    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != expected_owner_uid
            or info.st_mode & 0o077
            or info.st_size > MAX_ROTATION_JOURNAL_BYTES
        ):
            raise BridgeError("rotation_recovery_required", "A pending webhook rotation journal is unsafe or invalid.")
        with os.fdopen(fd, "rb") as stream:
            fd = -1
            raw = stream.read(MAX_ROTATION_JOURNAL_BYTES + 1)
        if len(raw) > MAX_ROTATION_JOURNAL_BYTES:
            raise BridgeError("rotation_recovery_required", "A pending webhook rotation journal is too large.")
        record = json.loads(raw)
    except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        raise BridgeError("rotation_recovery_required", "A pending webhook rotation journal is invalid.") from exc
    finally:
        if fd >= 0:
            os.close(fd)

    expected_fields = {"instance", "previous_config", "previous_webhook_url"}
    if (
        not isinstance(record, dict)
        or set(record) != expected_fields
        or record.get("instance") != instance
        or not isinstance(record.get("previous_config"), str)
        or len(record["previous_config"]) > 65_536
        or not isinstance(record.get("previous_webhook_url"), str)
        or not record["previous_webhook_url"]
        or len(record["previous_webhook_url"].encode("utf-8")) > 4096
    ):
        raise BridgeError("rotation_recovery_required", "A pending webhook rotation journal is invalid.")
    return {
        "previous_config": record["previous_config"],
        "previous_webhook_url": record["previous_webhook_url"],
    }


def _remove_rotation_journal(path: Path, *, trusted_root: Path, expected_owner_uid: int) -> None:
    _validate_directory_chain(path.parent, trusted_root, expected_owner_uid)
    path.unlink()
    directory_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0))
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def _recover_pending_rotation(
    config_path: Path,
    destination: Path,
    journal_path: Path,
    *,
    instance: str,
    trusted_root: Path,
    expected_owner_uid: int,
) -> bool:
    record = _read_rotation_journal(
        journal_path,
        instance=instance,
        trusted_root=trusted_root,
        expected_owner_uid=expected_owner_uid,
    )
    if record is None:
        return False
    _atomic_write(
        destination,
        record["previous_webhook_url"].encode("utf-8"),
        0o600,
        trusted_root=trusted_root,
        expected_owner_uid=expected_owner_uid,
    )
    _atomic_write(
        config_path,
        record["previous_config"].encode("utf-8"),
        0o644,
        trusted_root=trusted_root,
        expected_owner_uid=expected_owner_uid,
    )
    _remove_rotation_journal(journal_path, trusted_root=trusted_root, expected_owner_uid=expected_owner_uid)
    return True


def _rotate_instance(instance: str, root: Path, owner_uid: int, config_path: Path, destination: Path) -> int:
    journal_path = _rotation_journal_path(config_path)
    try:
        if _recover_pending_configuration(
            _configuration_journal_path(config_path),
            instance=instance,
            trusted_root=root,
            expected_owner_uid=owner_uid,
        ):
            print("Recovered a previous interrupted Isolated instance update.")
        if _recover_pending_rotation(
            config_path,
            destination,
            journal_path,
            instance=instance,
            trusted_root=root,
            expected_owner_uid=owner_uid,
        ):
            print("Recovered a previous interrupted webhook rotation.")
        config = load_config(config_path, expected_owner_uid=owner_uid)
        expected = config.credentials.webhook_sha256
        if not expected:
            raise BridgeError("configuration_incomplete", "No webhook fingerprint is pinned.")
        previous_config = config_path.read_text(encoding="utf-8")
        previous_webhook_url = _read_webhook_credential(destination, expected_owner_uid=owner_uid)
        if webhook_url_fingerprint(previous_webhook_url, config.connection.multica_origin) != expected:
            raise BridgeError("credential_mismatch", "The current webhook credential does not match its pinned fingerprint.")
        value = getpass.getpass("New Multica webhook URL (hidden): ").strip()
        actual = webhook_url_fingerprint(value, config.connection.multica_origin)
        updated_config = _replace_webhook_pin(previous_config, expected, actual)
    except (BridgeError, OSError) as exc:
        print(f"Credential rotation rejected: {exc}", file=sys.stderr)
        return 1

    try:
        journal = {
            "instance": instance,
            "previous_config": previous_config,
            "previous_webhook_url": previous_webhook_url,
        }
        _atomic_write(
            journal_path,
            json.dumps(journal, ensure_ascii=True).encode("utf-8"),
            0o600,
            trusted_root=root,
            expected_owner_uid=owner_uid,
        )
    except OSError:
        print("Could not create a protected recovery journal; no rotation was applied.", file=sys.stderr)
        return 1

    try:
        _atomic_write(
            destination,
            value.encode("utf-8"),
            0o600,
            trusted_root=root,
            expected_owner_uid=owner_uid,
        )
        _atomic_write(
            config_path,
            updated_config.encode("utf-8"),
            0o644,
            trusted_root=root,
            expected_owner_uid=owner_uid,
        )
    except (BridgeError, OSError):
        try:
            _recover_pending_rotation(
                config_path,
                destination,
                journal_path,
                instance=instance,
                trusted_root=root,
                expected_owner_uid=owner_uid,
            )
        except (BridgeError, OSError):
            print("Rotation was interrupted; the protected recovery journal was retained.", file=sys.stderr)
            return 1
        print("Rotation failed; the previous credential and fingerprint were restored.", file=sys.stderr)
        return 1

    try:
        _remove_rotation_journal(journal_path, trusted_root=root, expected_owner_uid=owner_uid)
    except OSError:
        print("Rotation state is saved, but the recovery journal could not be cleared.", file=sys.stderr)
        return 1

    print(f"Webhook credential rotated and fingerprint updated: {actual}")
    print("The credential value was not displayed.")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Rotate an Isolated webhook credential")
    parser.add_argument("--instance", required=True)
    parser.add_argument("--root", default="/", help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    root = Path(args.root).resolve()
    if root == Path("/") and os.geteuid() != 0:
        print("This helper must run as root.", file=sys.stderr)
        return 1
    if not sys.stdin.isatty():
        print("A local interactive terminal is required.", file=sys.stderr)
        return 1

    try:
        config_root = CONFIG_ROOT if root == Path("/") else root / "etc" / "hermes-multica-bridge"
        config_path, destination = _instance_paths(args.instance, config_root=config_root)
        owner_uid = os.geteuid()
        with _instance_rotation_lock(
            config_path,
            trusted_root=root,
            expected_owner_uid=owner_uid,
        ):
            return _rotate_instance(args.instance, root, owner_uid, config_path, destination)
    except (BridgeError, OSError) as exc:
        print(f"Credential rotation rejected: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
