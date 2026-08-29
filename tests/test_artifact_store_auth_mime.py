*** Begin Patch
*** Add File: tests/test_artifact_store_auth_mime.py
+import io
+import os
+
+import pytest
+
+from laptop_control.artifacts.store import ArtifactStore, ArtifactAccessDeniedError, ArtifactNotFoundError, ArtifactTooLargeError
+from laptop_control.security.authorization import AuthorizationManager
+from laptop_control.core.exceptions import AuthorizationError
+
+
+def test_create_requires_authorization(tmp_path):
+    root = str(tmp_path / "artifacts")
+    auth = AuthorizationManager(set())  # no users authorized
+    store = ArtifactStore(root=root, db_path=os.path.join(root, "artifacts.db"), authorizer=auth)
+
+    data = b"\x89PNG\r\n\x1a\n" + b"a" * 10
+    stream = io.BytesIO(data)
+
+    with pytest.raises(AuthorizationError):
+        store.create_artifact(caller_user_id=1234, tool_name="test_tool", stream=stream, mime_type_hint="image/png")
+
+
+def test_authorized_create_and_open(tmp_path):
+    root = str(tmp_path / "artifacts")
+    auth = AuthorizationManager({1001})
+    store = ArtifactStore(root=root, db_path=os.path.join(root, "artifacts.db"), authorizer=auth)
+
+    data = b"\x89PNG\r\n\x1a\n" + b"abc"
+    stream = io.BytesIO(data)
+    meta = store.create_artifact(caller_user_id=1001, tool_name="test_tool", stream=stream, mime_type_hint="image/png")
+
+    f = store.open_artifact(meta.artifact_id, caller_user_id=1001)
+    read = f.read()
+    f.close()
+    assert read.startswith(b"\x89PNG")
+
+
+def test_cross_owner_access_denied(tmp_path):
+    root = str(tmp_path / "artifacts")
+    auth = AuthorizationManager({1001, 1002})
+    store = ArtifactStore(root=root, db_path=os.path.join(root, "artifacts.db"), authorizer=auth)
+
+    data = b"\x89PNG\r\n\x1a\n" + b"abc"
+    stream = io.BytesIO(data)
+    meta = store.create_artifact(caller_user_id=1001, tool_name="test_tool", stream=stream, mime_type_hint="image/png")
+
+    with pytest.raises(ArtifactAccessDeniedError):
+        store.open_artifact(meta.artifact_id, caller_user_id=1002)
+
+
+def test_mime_rejection_for_fake_png(tmp_path):
+    root = str(tmp_path / "artifacts")
+    auth = AuthorizationManager({1001})
+    store = ArtifactStore(root=root, db_path=os.path.join(root, "artifacts.db"), authorizer=auth)
+
+    # Payload does not have PNG magic bytes
+    data = b"NOTPNG" + b"a" * 10
+    stream = io.BytesIO(data)
+
+    with pytest.raises(ValueError):
+        store.create_artifact(caller_user_id=1001, tool_name="test_tool", stream=stream, mime_type_hint="image/png")
+
*** End Patch
