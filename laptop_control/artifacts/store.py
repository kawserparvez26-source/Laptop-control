*** Begin Patch
*** Update File: laptop_control/artifacts/store.py
@@
-from typing import BinaryIO, Dict, List, Optional, Set
-from laptop_control.security.authorization import AuthorizationManager
-from laptop_control.core.exceptions import AuthorizationError
+from typing import BinaryIO, Dict, List, Optional, Set
+from laptop_control.security.authorization import AuthorizationManager
+from laptop_control.core.exceptions import AuthorizationError, EmergencyStopTriggered
+from laptop_control.security.audit import AuditLogger
+from laptop_control.core.types import OperationStatus, RiskLevel
+from laptop_control.security.emergency_stop import EmergencyStop
@@
-    def __init__(
-        self,
-        root: str = DEFAULT_ARTIFACT_ROOT,
-        db_path: str = DEFAULT_DB_PATH,
-        max_artifact_bytes: int = DEFAULT_MAX_ARTIFACT_BYTES,
-        authorizer: Optional[AuthorizationManager] = None,
-        allowed_mime_types: Optional[Set[str]] = None,
-    ) -> None:
+    def __init__(
+        self,
+        root: str = DEFAULT_ARTIFACT_ROOT,
+        db_path: str = DEFAULT_DB_PATH,
+        max_artifact_bytes: int = DEFAULT_MAX_ARTIFACT_BYTES,
+        authorizer: Optional[AuthorizationManager] = None,
+        allowed_mime_types: Optional[Set[str]] = None,
+        emergency_stop: Optional[EmergencyStop] = None,
+        audit_logger: Optional[AuditLogger] = None,
+    ) -> None:
         self.root = root
         self.db_path = db_path
         self.max_artifact_bytes = max_artifact_bytes
         self.authorizer = authorizer
         self.allowed_mime_types = allowed_mime_types or {
             "image/png",
             "image/jpeg",
             "image/webp",
             "application/zip",
         }
+        self.emergency_stop = emergency_stop
+        self.audit_logger = audit_logger
@@
-        # Read initial head for MIME sniffing
-        head = stream.read(4096)
+        # Emergency stop: ensure not active before starting
+        if self.emergency_stop is not None:
+            self.emergency_stop.require_not_stopped()
+
+        # Read initial head for MIME sniffing
+        head = stream.read(4096)
@@
-                # Continue reading remaining stream in chunks
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
+                # Continue reading remaining stream in chunks
+                while True:
+                    # Cooperative emergency-stop check between chunk reads
+                    if self.emergency_stop is not None and self.emergency_stop.is_active():
+                        # Clean up temp and raise
+                        raise EmergencyStopTriggered("Emergency stop activated during artifact creation")
+
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
@@
-            return meta
+            # Emit audit event for artifact_created (metadata only)
+            if self.audit_logger is not None:
+                try:
+                    self.audit_logger.log_operation(
+                        user_id=int(caller_user_id),
+                        operation="artifact_created",
+                        tool=tool_name,
+                        status=OperationStatus.SUCCESS,
+                        risk_level=RiskLevel.MEDIUM,
+                        details={
+                            "artifact_id": meta.artifact_id,
+                            "mime_type": meta.mime_type,
+                            "size": meta.size,
+                            "expires_at": meta.expires_at,
+                        },
+                    )
+                except Exception:
+                    # Audit failures should not prevent operation; log and continue
+                    pass
+
+            return meta
@@
-        row = self._fetch_metadata_row(artifact_id)
+        row = self._fetch_metadata_row(artifact_id)
         if not row:
             raise ArtifactNotFoundError()
         # row indices correspond to select order
         stored_owner = row[1]
 
         # Authorization check
         if self.authorizer is None:
             raise RuntimeError("ArtifactStore requires an AuthorizationManager for secure operations")
         self.authorizer.require_authorized(caller_user_id)
-        if str(caller_user_id) != stored_owner:
-            raise ArtifactAccessDeniedError()
+        if str(caller_user_id) != stored_owner:
+            # Log access denied event
+            if self.audit_logger is not None:
+                try:
+                    self.audit_logger.log_operation(
+                        user_id=int(caller_user_id),
+                        operation="artifact_access_denied",
+                        tool="artifact_store",
+                        status=OperationStatus.FAILED,
+                        risk_level=RiskLevel.HIGH,
+                        details={"artifact_id": artifact_id, "owner": stored_owner},
+                    )
+                except Exception:
+                    pass
+            raise ArtifactAccessDeniedError()
@@
     def open_artifact(self, artifact_id: str, caller_user_id: int) -> BinaryIO:
         meta = self.get_metadata(artifact_id, caller_user_id)
         path = os.path.join(self.root, artifact_id)
         if not os.path.exists(path):
             raise ArtifactNotFoundError()
@@
-        # Return a file-like object opened for reading in binary mode
-        return open(path, "rb")
+        # Emit audit event for artifact_accessed
+        if self.audit_logger is not None:
+            try:
+                self.audit_logger.log_operation(
+                    user_id=int(caller_user_id),
+                    operation="artifact_accessed",
+                    tool="artifact_store",
+                    status=OperationStatus.SUCCESS,
+                    risk_level=RiskLevel.MEDIUM,
+                    details={
+                        "artifact_id": meta.artifact_id,
+                        "mime_type": meta.mime_type,
+                        "size": meta.size,
+                    },
+                )
+            except Exception:
+                pass
+
+        # Return a file-like object opened for reading in binary mode
+        return open(path, "rb")
@@
     def delete_artifact(self, artifact_id: str, owner: str) -> None:
-        meta = self.get_metadata(artifact_id, owner)
+        # Note: preserve API backwards-compatibility for callers using owner param
+        # but map to caller_user_id for authorization path
+        caller_user_id = int(owner) if isinstance(owner, (str, int)) else owner
+        meta = self.get_metadata(artifact_id, caller_user_id)
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
+        # Emit audit event for artifact_deleted
+        if self.audit_logger is not None:
+            try:
+                self.audit_logger.log_operation(
+                    user_id=int(caller_user_id),
+                    operation="artifact_deleted",
+                    tool="artifact_store",
+                    status=OperationStatus.SUCCESS,
+                    risk_level=RiskLevel.MEDIUM,
+                    details={"artifact_id": artifact_id, "size": meta.size},
+                )
+            except Exception:
+                pass
@@
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
+                # Emit audit event for artifact_expired
+                if self.audit_logger is not None:
+                    try:
+                        self.audit_logger.log_operation(
+                            user_id=0,
+                            operation="artifact_expired",
+                            tool="artifact_store",
+                            status=OperationStatus.SUCCESS,
+                            risk_level=RiskLevel.MEDIUM,
+                            details={"artifact_id": artifact_id},
+                        )
+                    except Exception:
+                        pass
             conn.commit()
         finally:
             conn.close()
         return expired_ids
*** End Patch
