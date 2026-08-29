*** Begin Patch
*** Update File: laptop_control/artifacts/store.py
@@
-from typing import BinaryIO, Dict, List, Optional
+from typing import BinaryIO, Dict, List, Optional, Set
+from laptop_control.security.authorization import AuthorizationManager
+from laptop_control.core.exceptions import AuthorizationError
@@
-class ArtifactStore:
-    def __init__(
-        self,
-        root: str = DEFAULT_ARTIFACT_ROOT,
-        db_path: str = DEFAULT_DB_PATH,
-        max_artifact_bytes: int = DEFAULT_MAX_ARTIFACT_BYTES,
-    ) -> None:
-        self.root = root
-        self.db_path = db_path
-        self.max_artifact_bytes = max_artifact_bytes
-
-        os.makedirs(self.root, exist_ok=True)
-        os.chmod(self.root, 0o700)
-
-        self._init_db()
+class ArtifactStore:
+    def __init__(
+        self,
+        root: str = DEFAULT_ARTIFACT_ROOT,
+        db_path: str = DEFAULT_DB_PATH,
+        max_artifact_bytes: int = DEFAULT_MAX_ARTIFACT_BYTES,
+        authorizer: Optional[AuthorizationManager] = None,
+        allowed_mime_types: Optional[Set[str]] = None,
+    ) -> None:
+        self.root = root
+        self.db_path = db_path
+        self.max_artifact_bytes = max_artifact_bytes
+        self.authorizer = authorizer
+        self.allowed_mime_types = allowed_mime_types or {
+            "image/png",
+            "image/jpeg",
+            "image/webp",
+            "application/zip",
+        }
+
+        os.makedirs(self.root, exist_ok=True)
+        os.chmod(self.root, 0o700)
+
+        self._init_db()
+
+    def _detect_mime_type_from_bytes(self, buf: bytes) -> Optional[str]:
+        # Try python-magic if available
+        try:
+            import magic
+
+            mime = magic.from_buffer(buf, mime=True)
+            return mime
+        except Exception:
+            # Fallback to manual magic-byte checks for supported types
+            if buf.startswith(b"\x89PNG\r\n\x1a\n"):
+                return "image/png"
+            if buf.startswith(b"\xff\xd8\xff"):
+                return "image/jpeg"
+            if len(buf) >= 12 and buf[:4] == b"RIFF" and buf[8:12] == b"WEBP":
+                return "image/webp"
+            if buf.startswith(b"PK\x03\x04"):
+                return "application/zip"
+        return None
@@
-    def create_artifact(
-        self,
-        owner: str,
-        tool_name: str,
-        stream: BinaryIO,
-        mime_type: str,
-        ttl_seconds: Optional[int] = None,
-        summary: Optional[str] = None,
-    ) -> ArtifactMetadata:
-        artifact_id = str(uuid.uuid4())
-        temp_fd, temp_path = tempfile.mkstemp(dir=self.root)
-        os.close(temp_fd)
-
-        hasher = hashlib.sha256()
-        total = 0
-
-        try:
-            with open(temp_path, "wb") as f:
-                # Read stream in chunks
-                while True:
-                    chunk = stream.read(8192)
-                    if not chunk:
-                        break
-                    if not isinstance(chunk, (bytes, bytearray)):
-                        raise TypeError("stream must yield bytes")
-                    total += len(chunk)
-                    if total > self.max_artifact_bytes:
-                        raise ArtifactTooLargeError(f"Artifact exceeds size limit: {total} bytes")
-                    f.write(chunk)
-                    hasher.update(chunk)
-
-            # Set strict permissions
-            os.chmod(temp_path, 0o600)
-
-            # Atomic move to final path (filename is artifact_id)
-            final_path = os.path.join(self.root, artifact_id)
-            os.replace(temp_path, final_path)
-
-            created_at = time.time()
-            expires_at = None
-            if ttl_seconds is not None:
-                expires_at = created_at + float(ttl_seconds)
-
-            checksum = hasher.hexdigest()
-
-            meta = ArtifactMetadata(
-                artifact_id=artifact_id,
-                owner=owner,
-                tool_name=tool_name,
-                mime_type=mime_type,
-                size=total,
-                created_at=created_at,
-                expires_at=expires_at,
-                status="ACTIVE",
-                checksum_sha256=checksum,
-                summary=summary,
-            )
-
-            # Persist metadata
-            conn = self._db_connect()
-            try:
-                conn.execute(
-                    "INSERT INTO artifacts (artifact_id, owner, tool_name, mime_type, size, created_at, expires_at, status, checksum_sha256, summary) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
-                    (
-                        meta.artifact_id,
-                        meta.owner,
-                        meta.tool_name,
-                        meta.mime_type,
-                        meta.size,
-                        meta.created_at,
-                        meta.expires_at,
-                        meta.status,
-                        meta.checksum_sha256,
-                        meta.summary,
-                    ),
-                )
-                conn.commit()
-            finally:
-                conn.close()
-
-            return meta
-
-        except Exception:
-            # Clean up temp file if exists
-            try:
-                if os.path.exists(temp_path):
-                    os.remove(temp_path)
-            except Exception:
-                pass
-            raise
+    def create_artifact(
+        self,
+        caller_user_id: int,
+        tool_name: str,
+        stream: BinaryIO,
+        mime_type_hint: Optional[str] = None,
+        ttl_seconds: Optional[int] = None,
+        summary: Optional[str] = None,
+    ) -> ArtifactMetadata:
+        # Authorization: ensure caller is authorized
+        if self.authorizer is None:
+            raise RuntimeError("ArtifactStore requires an AuthorizationManager for secure operations")
+        self.authorizer.require_authorized(caller_user_id)
+
+        artifact_id = str(uuid.uuid4())
+        temp_fd, temp_path = tempfile.mkstemp(dir=self.root)
+        os.close(temp_fd)
+
+        # Read initial head for MIME sniffing
+        head = stream.read(4096)
+        if not isinstance(head, (bytes, bytearray)):
+            try:
+                if os.path.exists(temp_path):
+                    os.remove(temp_path)
+            except Exception:
+                pass
+            raise TypeError("stream must yield bytes")
+
+        detected_mime = self._detect_mime_type_from_bytes(head)
+        if detected_mime is None and mime_type_hint is not None:
+            detected_mime = mime_type_hint
+
+        if detected_mime is None or detected_mime not in self.allowed_mime_types:
+            try:
+                if os.path.exists(temp_path):
+                    os.remove(temp_path)
+            except Exception:
+                pass
+            raise ValueError(f"Disallowed or unknown MIME type: {detected_mime}")
+
+        hasher = hashlib.sha256()
+        total = 0
+
+        try:
+            with open(temp_path, "wb") as f:
+                # Write the head first
+                f.write(head)
+                hasher.update(head)
+                total += len(head)
+                if total > self.max_artifact_bytes:
+                    raise ArtifactTooLargeError(f"Artifact exceeds size limit: {total} bytes")
+
+                # Continue reading remaining stream in chunks
+                while True:
+                    chunk = stream.read(8192)
+                    if not chunk:
+                        break
+                    if not isinstance(chunk, (bytes, bytearray)):
+                        raise TypeError("stream must yield bytes")
+                    total += len(chunk)
+                    if total > self.max_artifact_bytes:
+                        raise ArtifactTooLargeError(f"Artifact exceeds size limit: {total} bytes")
+                    f.write(chunk)
+                    hasher.update(chunk)
+
+            # Set strict permissions
+            os.chmod(temp_path, 0o600)
+
+            # Atomic move to final path (filename is artifact_id)
+            final_path = os.path.join(self.root, artifact_id)
+            os.replace(temp_path, final_path)
+
+            created_at = time.time()
+            expires_at = None
+            if ttl_seconds is not None:
+                expires_at = created_at + float(ttl_seconds)
+
+            checksum = hasher.hexdigest()
+
+            owner = str(caller_user_id)
+
+            meta = ArtifactMetadata(
+                artifact_id=artifact_id,
+                owner=owner,
+                tool_name=tool_name,
+                mime_type=detected_mime,
+                size=total,
+                created_at=created_at,
+                expires_at=expires_at,
+                status="ACTIVE",
+                checksum_sha256=checksum,
+                summary=summary,
+            )
+
+            # Persist metadata
+            conn = self._db_connect()
+            try:
+                conn.execute(
+                    "INSERT INTO artifacts (artifact_id, owner, tool_name, mime_type, size, created_at, expires_at, status, checksum_sha256, summary) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
+                    (
+                        meta.artifact_id,
+                        meta.owner,
+                        meta.tool_name,
+                        meta.mime_type,
+                        meta.size,
+                        meta.created_at,
+                        meta.expires_at,
+                        meta.status,
+                        meta.checksum_sha256,
+                        meta.summary,
+                    ),
+                )
+                conn.commit()
+            finally:
+                conn.close()
+
+            return meta
+
+        except Exception:
+            # Clean up temp file if exists
+            try:
+                if os.path.exists(temp_path):
+                    os.remove(temp_path)
+            except Exception:
+                pass
+            raise
@@
-    def _fetch_metadata_row(self, artifact_id: str):
+    def _fetch_metadata_row(self, artifact_id: str):
         conn = self._db_connect()
         try:
             cur = conn.execute("SELECT artifact_id, owner, tool_name, mime_type, size, created_at, expires_at, status, checksum_sha256, summary FROM artifacts WHERE artifact_id = ?", (artifact_id,))
             row = cur.fetchone()
             return row
         finally:
             conn.close()
@@
-    def get_metadata(self, artifact_id: str, owner: str) -> ArtifactMetadata:
-        row = self._fetch_metadata_row(artifact_id)
-        if not row:
-            raise ArtifactNotFoundError()
-        # row indices correspond to select order
-        stored_owner = row[1]
-        if stored_owner != owner:
-            raise ArtifactAccessDeniedError()
-
-        meta = ArtifactMetadata(
-            artifact_id=row[0],
-            owner=row[1],
-            tool_name=row[2],
-            mime_type=row[3],
-            size=row[4],
-            created_at=row[5],
-            expires_at=row[6],
-            status=row[7],
-            checksum_sha256=row[8],
-            summary=row[9],
-        )
-
-        # Check expiration
-        if meta.expires_at is not None and time.time() > meta.expires_at:
-            # Mark as expired in DB
-            conn = self._db_connect()
-            try:
-                conn.execute("UPDATE artifacts SET status = ? WHERE artifact_id = ?", ("EXPIRED", artifact_id))
-                conn.commit()
-            finally:
-                conn.close()
-            raise ArtifactNotFoundError("Artifact expired")
-
-        return meta
+    def get_metadata(self, artifact_id: str, caller_user_id: int) -> ArtifactMetadata:
+        row = self._fetch_metadata_row(artifact_id)
+        if not row:
+            raise ArtifactNotFoundError()
+        # row indices correspond to select order
+        stored_owner = row[1]
+
+        # Authorization check
+        if self.authorizer is None:
+            raise RuntimeError("ArtifactStore requires an AuthorizationManager for secure operations")
+        self.authorizer.require_authorized(caller_user_id)
+        if str(caller_user_id) != stored_owner:
+            raise ArtifactAccessDeniedError()
+
+        meta = ArtifactMetadata(
+            artifact_id=row[0],
+            owner=row[1],
+            tool_name=row[2],
+            mime_type=row[3],
+            size=row[4],
+            created_at=row[5],
+            expires_at=row[6],
+            status=row[7],
+            checksum_sha256=row[8],
+            summary=row[9],
+        )
+
+        # Check expiration
+        if meta.expires_at is not None and time.time() > meta.expires_at:
+            # Mark as expired in DB
+            conn = self._db_connect()
+            try:
+                conn.execute("UPDATE artifacts SET status = ? WHERE artifact_id = ?", ("EXPIRED", artifact_id))
+                conn.commit()
+            finally:
+                conn.close()
+            raise ArtifactNotFoundError("Artifact expired")
+
+        return meta
@@
-    def open_artifact(self, artifact_id: str, owner: str) -> BinaryIO:
-        meta = self.get_metadata(artifact_id, owner)
-        path = os.path.join(self.root, artifact_id)
+    def open_artifact(self, artifact_id: str, caller_user_id: int) -> BinaryIO:
+        meta = self.get_metadata(artifact_id, caller_user_id)
+        path = os.path.join(self.root, artifact_id)
         if not os.path.exists(path):
             raise ArtifactNotFoundError()
*** End Patch
