---
*** Begin Patch
*** Update File: laptop_control/core/types.py
@@
 from typing import Any, Dict, List, Optional
@@
 class ToolResult:
@@
     metadata: Dict[str, Any] = field(default_factory=dict)
+    # Optional artifact reference (opaque metadata) for large/binary outputs.
+    # Should be a dict with keys: artifact_id, mime_type, size, summary (optional), expires_at (optional)
+    artifact_ref: Optional[Dict[str, Any]] = None
*** End Patch
