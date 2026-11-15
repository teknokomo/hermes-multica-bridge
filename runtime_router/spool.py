"""Private durable attachment spool used by router requests."""

from __future__ import annotations

import fcntl
import hashlib
import os
import re
import stat
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from pathlib import Path

from .config import RouterConfigError


class AttachmentSpool:
    def __init__(self, root: str | Path):
        self.root = Path(root)
        if not self.root.is_absolute():
            raise RouterConfigError("attachment spool path must be absolute")
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = self.root.lstat()
        if (
            not stat.S_ISDIR(info.st_mode)
            or stat.S_ISLNK(info.st_mode)
            or info.st_uid != os.geteuid()
            or info.st_mode & 0o077
        ):
            raise RouterConfigError("attachment spool permissions are unsafe")

    @contextmanager
    def locked(self) -> Iterator[None]:
        """Serialize blob publication and reference-aware deletion across processes."""
        lock_path = self.root / ".spool.lock"
        flags = (
            os.O_CREAT
            | os.O_RDWR
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
        try:
            fd = os.open(lock_path, flags, 0o600)
        except OSError:
            raise RouterConfigError("attachment_spool_lock_unavailable") from None
        try:
            info = os.fstat(fd)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o600
            ):
                raise RouterConfigError("attachment_spool_lock_unsafe")
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)

    def store(
        self, attachments: Iterable[tuple[str, str, str, bytes]], *, maximum_total: int
    ) -> list[dict[str, str | int]]:
        with self.locked():
            return self.store_locked(attachments, maximum_total=maximum_total)

    def store_locked(
        self, attachments: Iterable[tuple[str, str, str, bytes]], *, maximum_total: int
    ) -> list[dict[str, str | int]]:
        """Publish content-addressed blobs while the caller holds ``locked()``."""
        result: list[dict[str, str | int]] = []
        total = 0
        created: list[Path] = []
        try:
            for name, content_type, expected_hash, data in attachments:
                total += len(data)
                if total > maximum_total or not data:
                    raise RouterConfigError("attachment_invalid")
                digest = hashlib.sha256(data).hexdigest()
                if digest != expected_hash:
                    raise RouterConfigError("attachment_invalid")
                path = self.root / digest
                flags = (
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
                )
                try:
                    fd = os.open(path, flags, 0o600)
                except FileExistsError:
                    read_fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
                    try:
                        info = os.fstat(read_fd)
                        if (
                            not stat.S_ISREG(info.st_mode)
                            or info.st_uid != os.geteuid()
                            or info.st_mode & 0o077
                            or info.st_size != len(data)
                        ):
                            raise RouterConfigError("attachment_spool_conflict")
                        existing_hash = hashlib.sha256()
                        while block := os.read(read_fd, 65536):
                            existing_hash.update(block)
                        if existing_hash.hexdigest() != digest:
                            raise RouterConfigError("attachment_spool_conflict")
                    finally:
                        os.close(read_fd)
                else:
                    created.append(path)
                    try:
                        view = memoryview(data)
                        while view:
                            written = os.write(fd, view)
                            view = view[written:]
                        os.fsync(fd)
                    finally:
                        os.close(fd)
                result.append(
                    {
                        "path": str(path),
                        "name": name,
                        "content_type": content_type,
                        "sha256": digest,
                        "size": len(data),
                    }
                )
            dir_fd = os.open(self.root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
            return result
        except Exception:
            for path in created:
                try:
                    path.unlink()
                except OSError:
                    pass
            raise

    def cleanup(self, attachments: Iterable[dict[str, str | int]]) -> int:
        with self.locked():
            return self.cleanup_locked(attachments)

    def cleanup_locked(self, attachments: Iterable[dict[str, str | int]]) -> int:
        """Remove verified blobs while the caller holds ``locked()``."""
        removed = 0
        for attachment in attachments:
            raw_path, digest = attachment.get("path"), attachment.get("sha256")
            if (
                not isinstance(raw_path, str)
                or not isinstance(digest, str)
                or not re.fullmatch(r"[0-9a-f]{64}", digest)
            ):
                continue
            path = Path(raw_path)
            if path.parent != self.root or path.name != digest or len(digest) != 64:
                continue
            try:
                info = path.lstat()
                if (
                    stat.S_ISREG(info.st_mode)
                    and not stat.S_ISLNK(info.st_mode)
                    and info.st_uid == os.geteuid()
                    and not info.st_mode & 0o077
                ):
                    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
                    try:
                        opened = os.fstat(fd)
                        if (
                            not stat.S_ISREG(opened.st_mode)
                            or opened.st_ino != info.st_ino
                        ):
                            continue
                        hasher = hashlib.sha256()
                        while block := os.read(fd, 65536):
                            hasher.update(block)
                    finally:
                        os.close(fd)
                    if hasher.hexdigest() != digest:
                        continue
                    path.unlink()
                    removed += 1
            except OSError:
                continue
        return removed
