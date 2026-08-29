*** Begin Patch
*** Update File: laptop_control/tools/screen.py
@@
-                    store = ArtifactStore(authorizer=None)
+                    # Note: In runtime the real AuthorizationManager and AuditLogger
+                    # should be injected into ArtifactStore. For now use None.
+                    store = ArtifactStore(authorizer=None, emergency_stop=None, audit_logger=None)
*** End Patch
