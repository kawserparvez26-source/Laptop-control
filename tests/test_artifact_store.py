*** Begin Patch
*** Add File: tests/test_artifact_store.py
+import io
+import os
+import tempfile
+
+from laptop_control.artifacts.store import ArtifactStore, ArtifactNotFoundError, ArtifactTooLargeError
+
+
+def test_create_and_open_artifact(tmp_path):
+    root = str(tmp_path / "artifacts")
+    store = ArtifactStore(root=root, db_path=os.path.join(root, "artifacts.db"), max_artifact_bytes=1024 * 1024)
+
+    data = b"hello world"
+    stream = io.BytesIO(data)
+    meta = store.create_artifact(owner="user1", tool_name="test_tool", stream=stream, mime_type="application/octet-stream")
+
+    assert meta.size == len(data)
+
+    f = store.open_artifact(meta.artifact_id, owner="user1")
+    read = f.read()
+    f.close()
+    assert read == data
+
+
+def test_size_limit(tmp_path):
+    root = str(tmp_path / "artifacts")
+    store = ArtifactStore(root=root, db_path=os.path.join(root, "artifacts.db"), max_artifact_bytes=10)
+
+    data = b"a" * 20
+    stream = io.BytesIO(data)
+    try:
+        store.create_artifact(owner="user1", tool_name="test_tool", stream=stream, mime_type="application/octet-stream")
+        assert False, "Expected ArtifactTooLargeError"
+    except ArtifactTooLargeError:
+        pass
+
*** End Patch
