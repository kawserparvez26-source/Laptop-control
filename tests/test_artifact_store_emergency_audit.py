*** Begin Patch
*** Add File: tests/test_artifact_store_emergency_audit.py
+import io
+import os
+
+import pytest
+
+from laptop_control.artifacts.store import ArtifactStore
+from laptop_control.security.authorization import AuthorizationManager
+from laptop_control.security.emergency_stop import EmergencyStop
+from laptop_control.security.audit import AuditLogger
+from laptop_control.core.exceptions import EmergencyStopTriggered
+
+
+class TriggerStream(io.BytesIO):
+    """Stream that activates emergency stop after reading a threshold."""
+
+    def __init__(self, data: bytes, emergency_stop: EmergencyStop, trigger_after: int = 1):
+        super().__init__(data)
+        self.emergency_stop = emergency_stop
+        self.trigger_after = trigger_after
+        self.read_bytes = 0
+
+    def read(self, n=-1):
+        chunk = super().read(n)
+        self.read_bytes += len(chunk)
+        if self.read_bytes >= self.trigger_after and not self.emergency_stop.is_active():
+            # Activate emergency stop mid-stream
+            self.emergency_stop.activate(reason="test-trigger")
+        return chunk
+
+
+def test_emergency_stop_interrupts_write_and_cleans_temp(tmp_path):
+    root = str(tmp_path / "artifacts")
+    stop_file = str(tmp_path / "stop.file")
+    emergency = EmergencyStop(stop_file=stop_file)
+    auth = AuthorizationManager({1001})
+    audit = AuditLogger(str(tmp_path / "audit.log"), fail_on_write=False)
+    store = ArtifactStore(root=root, db_path=os.path.join(root, "artifacts.db"), authorizer=auth, emergency_stop=emergency, audit_logger=audit)
+
+    data = b"\x89PNG\r\n\x1a\n" + b"A" * 1024
+    stream = TriggerStream(data, emergency, trigger_after=10)
+
+    with pytest.raises(EmergencyStopTriggered):
+        store.create_artifact(caller_user_id=1001, tool_name="test_tool", stream=stream, mime_type_hint="image/png")
+
+    # Ensure no artifact files remain in artifact root
+    files = list((tmp_path / "artifacts").glob("*")) if (tmp_path / "artifacts").exists() else []
+    # Allow for the DB file; artifact files (UUIDs) should not persist
+    assert all(f.name == "artifacts.db" for f in files) or len(files) == 0
+
+
+def test_audit_events_logged_for_create_and_access(tmp_path):
+    root = str(tmp_path / "artifacts")
+    auth = AuthorizationManager({1001})
+    audit = AuditLogger(str(tmp_path / "audit.log"), fail_on_write=False)
+    store = ArtifactStore(root=root, db_path=os.path.join(root, "artifacts.db"), authorizer=auth, audit_logger=audit)
+
+    data = b"\x89PNG\r\n\x1a\n" + b"abc"
+    stream = io.BytesIO(data)
+    meta = store.create_artifact(caller_user_id=1001, tool_name="test_tool", stream=stream, mime_type_hint="image/png")
+
+    # Access artifact
+    f = store.open_artifact(meta.artifact_id, caller_user_id=1001)
+    _ = f.read()
+    f.close()
+
+    # Read audit records and ensure artifact_created and artifact_accessed are present
+    records = audit.read_records()
+    ops = [r.get("operation") for r in records]
+    assert "artifact_created" in ops
+    assert "artifact_accessed" in ops
+
*** End Patch
