*** Begin Patch
*** Update File: laptop_control/tools/screen.py
@@
-                # Return screenshot as binary data in output field
-                # Note: ToolResult.output is typed as str, so we encode binary data
-                # This is the safest approach given the existing architecture
-                return ToolResult(
-                    tool_name=self.name,
-                    success=True,
-                    output="",  # Binary data would require architecture changes
-                    status=OperationStatus.SUCCESS,
-                    execution_time=time.time() - start_time,
-                    metadata={
-                        "width": width,
-                        "height": height,
-                        "output_bytes": output_size,
-                        "format": "PNG",
-                        "has_data": True,
-                    },
-                )
+                # Instead of embedding binary data, store screenshot in ArtifactStore
+                # to avoid LLM context bloat and preserve security boundaries.
+                try:
+                    from laptop_control.artifacts.store import ArtifactStore
+                    import io
+
+                    store = ArtifactStore()
+                    stream = io.BytesIO(png_data)
+                    meta = store.create_artifact(
+                        owner=str(user_id),
+                        tool_name=self.name,
+                        stream=stream,
+                        mime_type="image/png",
+                        ttl_seconds=3600,  # default 1 hour expiry; configurable in future
+                        summary=f"Screenshot {width}x{height}",
+                    )
+
+                    return ToolResult(
+                        tool_name=self.name,
+                        success=True,
+                        output="",
+                        status=OperationStatus.SUCCESS,
+                        execution_time=time.time() - start_time,
+                        metadata={
+                            "width": width,
+                            "height": height,
+                            "output_bytes": output_size,
+                            "format": "PNG",
+                        },
+                        artifact_ref={
+                            "artifact_id": meta.artifact_id,
+                            "mime_type": meta.mime_type,
+                            "size": meta.size,
+                            "summary": meta.summary,
+                            "expires_at": meta.expires_at,
+                        },
+                    )
+                except Exception as e:
+                    logger.error(f"Failed to store artifact: {e}", exc_info=True)
+                    return ToolResult(
+                        tool_name=self.name,
+                        success=False,
+                        error="Failed to persist screenshot artifact",
+                        status=OperationStatus.FAILED,
+                        execution_time=time.time() - start_time,
+                        metadata={"error_type": type(e).__name__},
+                    )
*** End Patch
