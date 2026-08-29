"""Artifact store implementation for Laptop Control.

This module implements a minimal ArtifactStore for Phase 2 integration per
the Artifact Transport ADR. It handles creating artifacts from binary
streams, storing metadata in SQLite, atomic file writes, checksum
verification, TTL expiration, and strict filesystem permissions.

Notes:
- Uses WAL mode for SQLite to improve durability under concurrent access.
- Writes files to a configurable ARTIFACT_ROOT (defaults to ~/.laptop_control/artifacts).
- Enforces 0o700 on directories and 0o600 on files.
- Does not expose filesystem paths to callers; only returns opaque UUID artifact IDs.
"""
from __future__ import annotations

import hashlib
import os
import sqlite3
import tempfile
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import BinaryIO, Dict, List, Optional


DEFAULT_ARTIFACT_ROOT = os.path.expanduser("~/.laptop_control/artifacts")
DEFAULT_DB_PATH = os.path.join(DEFAULT_ARTIFACT_ROOT, "artifacts.db")
DEFAULT_MAX_ARTIFACT_BYTES = 50 * 1024 * 1024  # 50 MiB per artifact default


@dataclass
class ArtifactMetadata:
    artifact_id: str
    owner: str
    tool_name: str
    mime_type: str
    size: int
    created_at: float
    expires_at: Optional[float]
    status: str
    checksum_sha256: str
    summary: Optional[str]


class ArtifactNotFoundError(Exception):
    pass


class ArtifactAccessDeniedError(Exception):
    pass


class ArtifactIntegrityError(Exception):
    pass


class ArtifactTooLargeError(Exception):
    pass


class ArtifactStorageUnavailableError(Exception):
    pass


class ArtifactStore:
    def __init__(
        self,
        root: str = DEFAULT_ARTIFACT_ROOT,
        db_path: str = DEFAULT_DB_PATH,
        max_artifact_bytes: int = DEFAULT_MAX_ARTIFACT_BYTES,
    ) -> None:
        self.root = root
        self.db_path = db_path
        self.max_artifact_bytes = max_artifact_bytes

        os.makedirs(self.root, exist_ok=True)
        os.chmod(self.root, 0o700)

        self._init_db()

    def _init_db(self) -> None:
        # Ensure db directory exists
        db_dir = os.path.dirname(self.db_path)
        if db_dir and not os.path.exists(db_dir):
            os.makedirs(db_dir, exist_ok=True)
            os.chmod(db_dir, 0o700)

        conn = sqlite3.connect(self.db_path)
        try:
            # Enable WAL for better concurrency/durability
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS artifacts (
                    artifact_id TEXT PRIMARY KEY,
                    owner TEXT NOT NULL,
                    tool_name TEXT NOT NULL,
                    mime_type TEXT NOT NULL,
                    size INTEGER NOT NULL,
                    created_at REAL NOT NULL,
                    expires_at REAL,
                    status TEXT NOT NULL,
                    checksum_sha256 TEXT NOT NULL,
                    summary TEXT
                )
                """
            )
            conn.commit()
        finally:
            conn.close()

    def _db_connect(self):
        return sqlite3.connect(self.db_path)

    def create_artifact(
        self,
        owner: str,
        tool_name: str,
        stream: BinaryIO,
        mime_type: str,
        ttl_seconds: Optional[int] = None,
        summary: Optional[str] = None,
    ) -> ArtifactMetadata:
        artifact_id = str(uuid.uuid4())
        temp_fd, temp_path = tempfile.mkstemp(dir=self.root)
        os.close(temp_fd)

        hasher = hashlib.sha256()
        total = 0

        try:
            with open(temp_path, "wb") as f:
                # Read stream in chunks
                while True:
                    chunk = stream.read(8192)
                    if not chunk:
                        break
                    if not isinstance(chunk, (bytes, bytearray)):
                        raise TypeError("stream must yield bytes")
                    total += len(chunk)
                    if total > self.max_artifact_bytes:
                        raise ArtifactTooLargeError(f"Artifact exceeds size limit: {total} bytes")
                    f.write(chunk)
                    hasher.update(chunk)

            # Set strict permissions
            os.chmod(temp_path, 0o600)

            # Atomic move to final path (filename is artifact_id)
            final_path = os.path.join(self.root, artifact_id)
            os.replace(temp_path, final_path)

            created_at = time.time()
            expires_at = None
            if ttl_seconds is not None:
                expires_at = created_at + float(ttl_seconds)

            checksum = hasher.hexdigest()

            meta = ArtifactMetadata(
                artifact_id=artifact_id,
                owner=owner,
                tool_name=tool_name,
                mime_type=mime_type,
                size=total,
                created_at=created_at,
                expires_at=expires_at,
                status="ACTIVE",
                checksum_sha256=checksum,
                summary=summary,
            )

            # Persist metadata
            conn = self._db_connect()
            try:
                conn.execute(
                    "INSERT INTO artifacts (artifact_id, owner, tool_name, mime_type, size, created_at, expires_at, status, checksum_sha256, summary) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        meta.artifact_id,
                        meta.owner,
                        meta.tool_name,
                        meta.mime_type,
                        meta.size,
                        meta.created_at,
                        meta.expires_at,
                        meta.status,
                        meta.checksum_sha256,
                        meta.summary,
                    ),
                )
                conn.commit()
            finally:
                conn.close()

            return meta

        except Exception:
            # Clean up temp file if exists
            try:
                if os.path.exists(temp_path):
                    os.remove(temp_path)
            except Exception:
                pass
            raise

    def _fetch_metadata_row(self, artifact_id: str):
        conn = self._db_connect()
        try:
            cur = conn.execute("SELECT artifact_id, owner, tool_name, mime_type, size, created_at, expires_at, status, checksum_sha256, summary FROM artifacts WHERE artifact_id = ?", (artifact_id,))
            row = cur.fetchone()
            return row
        finally:
            conn.close()

    def get_metadata(self, artifact_id: str, owner: str) -> ArtifactMetadata:
        row = self._fetch_metadata_row(artifact_id)
        if not row:
            raise ArtifactNotFoundError()
        # row indices correspond to select order
        stored_owner = row[1]
        if stored_owner != owner:
            raise ArtifactAccessDeniedError()

        meta = ArtifactMetadata(
            artifact_id=row[0],
            owner=row[1],
            tool_name=row[2],
            mime_type=row[3],
            size=row[4],
            created_at=row[5],
            expires_at=row[6],
            status=row[7],
            checksum_sha256=row[8],
            summary=row[9],
        )

        # Check expiration
        if meta.expires_at is not None and time.time() > meta.expires_at:
            # Mark as expired in DB
            conn = self._db_connect()
            try:
                conn.execute("UPDATE artifacts SET status = ? WHERE artifact_id = ?", ("EXPIRED", artifact_id))
                conn.commit()
            finally:
                conn.close()
            raise ArtifactNotFoundError("Artifact expired")

        return meta

    def open_artifact(self, artifact_id: str, owner: str) -> BinaryIO:
        meta = self.get_metadata(artifact_id, owner)
        path = os.path.join(self.root, artifact_id)
        if not os.path.exists(path):
            raise ArtifactNotFoundError()

        # Verify checksum
        hasher = hashlib.sha256()
        with open(path, "rb") as f:
            while True:
                chunk = f.read(8192)
                if not chunk:
                    break
                hasher.update(chunk)
        if hasher.hexdigest() != meta.checksum_sha256:
            raise ArtifactIntegrityError()

        # Return a file-like object opened for reading in binary mode
        return open(path, "rb")

    def delete_artifact(self, artifact_id: str, owner: str) -> None:
        meta = self.get_metadata(artifact_id, owner)
        path = os.path.join(self.root, artifact_id)
        # Remove file and update DB
        if os.path.exists(path):
            os.remove(path)
        conn = self._db_connect()
        try:
            conn.execute("UPDATE artifacts SET status = ? WHERE artifact_id = ?", ("DELETED", artifact_id))
            conn.commit()
        finally:
            conn.close()

    def sweep_expired(self) -> List[str]:
        now = time.time()
        conn = self._db_connect()
        expired_ids: List[str] = []
        try:
            cur = conn.execute("SELECT artifact_id FROM artifacts WHERE expires_at IS NOT NULL AND expires_at < ? AND status = ?", (now, "ACTIVE"))
            rows = cur.fetchall()
            for (artifact_id,) in rows:
                path = os.path.join(self.root, artifact_id)
                try:
                    if os.path.exists(path):
                        os.remove(path)
                except Exception:
                    pass
                conn.execute("UPDATE artifacts SET status = ? WHERE artifact_id = ?", ("EXPIRED", artifact_id))
                expired_ids.append(artifact_id)
            conn.commit()
        finally:
            conn.close()
        return expired_ids

    def list_artifacts(self, owner: str) -> List[ArtifactMetadata]:
        conn = self._db_connect()
        try:
            cur = conn.execute("SELECT artifact_id, owner, tool_name, mime_type, size, created_at, expires_at, status, checksum_sha256, summary FROM artifacts WHERE owner = ?", (owner,))
            rows = cur.fetchall()
            metas: List[ArtifactMetadata] = []
            for row in rows:
                metas.append(
                    ArtifactMetadata(
                        artifact_id=row[0],
                        owner=row[1],
                        tool_name=row[2],
                        mime_type=row[3],
                        size=row[4],
                        created_at=row[5],
                        expires_at=row[6],
                        status=row[7],
                        checksum_sha256=row[8],
                        summary=row[9],
                    )
                )
            return metas
        finally:
            conn.close()
