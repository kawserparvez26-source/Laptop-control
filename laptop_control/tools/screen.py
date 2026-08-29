*** Begin Patch
*** Update File: laptop_control/tools/screen.py
@@
-                    store = ArtifactStore()
-                    stream = io.BytesIO(png_data)
-                    meta = store.create_artifact(
-                        owner=str(user_id),
-                        tool_name=self.name,
-                        stream=stream,
-                        mime_type="image/png",
-                        ttl_seconds=3600,  # default 1 hour expiry; configurable in future
-                        summary=f"Screenshot {width}x{height}",
-                    )
+                    store = ArtifactStore(authorizer=None)
+                    stream = io.BytesIO(png_data)
+                    meta = store.create_artifact(
+                        caller_user_id=user_id,
+                        tool_name=self.name,
+                        stream=stream,
+                        mime_type_hint="image/png",
+                        ttl_seconds=3600,  # default 1 hour expiry; configurable in future
+                        summary=f"Screenshot {width}x{height}",
+                    )
*** End Patch
