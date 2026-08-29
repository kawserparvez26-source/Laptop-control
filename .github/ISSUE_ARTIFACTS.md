---
layout: pacific
title: "Artifact Store hardening: Authorization & MIME validation"
---

This issue tracks the next-phase hardening tasks for the ArtifactStore feature added on the `feature/artifact-store-adr` branch.

Priority Follow-Up Checklist

- [ ] Authorization Integration
  - Hook ArtifactStore methods (create_artifact, open_artifact, delete_artifact) into the existing `laptop_control/security/authorization.py` module.
  - Ensure create_artifact records and binds the verified session/user ID as the strict owner.
  - Enforce that open_artifact and delete_artifact validate the caller's session against the owner or an authorized administrator role.
  - Add unit tests for access-denied and cross-owner scenarios.
- [ ] MIME Magic-Byte Validation
  - Incorporate `python-magic` when available with a robust fallback.
  - Enforce a strict whitelist: `image/png`, `image/jpeg`, `image/webp`, `application/zip` by default.
  - Reject payloads whose magic bytes don't match declared/expected content type.
  - Unit tests verifying rejection of mismatched payloads.
- [ ] Emergency Stop & Audit Wiring (future)
  - Interrupt active artifact writes when emergency stop is triggered and ensure cleanup of partial files.
  - Emit audit events: `artifact_created`, `artifact_accessed`, `artifact_deleted`, `artifact_expired`, `artifact_access_denied` (no binary contents logged).
- [ ] Operator CLI & Integration Tests (future)
  - CLI: list, fetch, purge expired, admin-only.
  - Integration tests with mocked capture backend to verify end-to-end flow.

References

- Branch: `feature/artifact-store-adr`
- Commit: 5f39205bd920c053cee14552025b2b9b0483f570
- ADR: Artifact Transport Architecture Decision Record

Next steps

1. Implement authorization checks in `laptop_control/artifacts/store.py`, adding an optional `authorizer: AuthorizationManager` parameter to the `ArtifactStore` constructor and enforcing checks in public methods.
2. Add `python-magic`-based MIME sniffing during `create_artifact` with a fallback to manual magic-byte checks.
3. Add unit tests and push incremental commits to `feature/artifact-store-adr`.

