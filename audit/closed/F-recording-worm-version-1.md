# F-recording-worm-version-1: replay/export served the object-store "latest" version, not the WORM-locked finalized version (shadow-PUT tamper)
- Severity: high
- Status: Verified-Fixed
- Area: recording

## Context (S23 red-team panel A4 — crown jewels)

S3 Object Lock protects an object **version**, not the key from a **new** PUT: a
later PUT to the same key becomes the "current" version, and an unversioned GET
returns it. The CP holds the customer **public** key and sealing needs only the
public key (`seal.rs::seal_to_customer`), so a compromised CP could seal a forged
asciicast and PUT it to the finalized recording's key → a plain replay/export GET
(`WormObjectStore.presignDownloadBlocking` built `GetObjectRequest` with **no
versionId**) would serve the forgery. A compromised/buggy Gateway could do the PUT
alone: `requestUpload` re-issued a fresh presigned PUT **post-finalize** (no
terminal-state guard). Nothing on the access path re-verified the served bytes
against the write-once `hash_chain_head`/`content_digest`. Defeats §15 (“a
compromised CP/admin can't alter a recording”), FR-AUD-3 (WORM immutability),
NFR-6.

## Root-cause fix (version pinning + terminal guard)

- **Gateway captures the PUT-response `x-amz-version-id`** (`recorder/upload.rs`
  `send_put` → threaded through `put`/`put_inner`/`upload_with_retry`) and sends it
  in `FinalizeRecording` (`recorder/mod.rs`; proto `FinalizeRecordingRequest.
  object_version_id = 7`, additive/N-1).
- **CP stores it WRITE-ONCE** — new `recording_ref.object_version_id` column
  (migration `V24`), added to the `enforce_recording_ref_write_once` trigger, so
  even the restricted app credential (`cp_runtime`) cannot repoint it. Wired through
  `RecordingRef.finalized(...)` + `RecordingRegistrationService.finalizeRecording`.
- **Replay/export PIN the version** — `RecordingStore.presignDownload(objectKey,
  objectVersionId, ttl)`; `WormObjectStore` sets `GetObjectRequest.versionId(...)`;
  `RecordingAccessService` passes `ref.objectVersionId()`. Null (N-1 recording) falls
  back to the current version.
- **F4 terminal-state guard** — `RecordingRegistrationService.requestUpload` refuses
  a fresh presigned PUT once `status != "recording"` (no post-finalize shadow PUT).

Residual: a DB **superuser** rewriting `object_version_id` is the same residual the
deferred external Merkle anchor (FR-AUD-10) addresses — stated, not masked.

## Regression tests

- `RecordingStoreSeamTest.replayPinsTheFinalizedObjectVersion` — replay's presigned
  GET carries the pinned `?versionId=<finalized>` (unit).
- `RecordingIT.finalizePersistsTheObjectVersionIdAndCannotRepointIt` — the wire
  version id is stored, and a same-status re-finalize can't move the pin (Docker).
- `RecordingIT.requestUploadAfterFinalizeIsRefused` — post-finalize `RequestUpload`
  → PERMISSION_DENIED (Docker).
