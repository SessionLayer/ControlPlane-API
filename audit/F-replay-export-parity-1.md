# F-replay-export-parity-1: recording:replay and recording:export both confer a full-object download

- Severity: low
- Status: Accepted-Risk
- Area: security

Both `replay` and `export` issue an identical short-lived presigned GET of the whole encrypted object (`RecordingStore.presignDownload`); they differ only by the permission checked and the audit action label. So `recording:replay` already grants everything `recording:export` does, and the FR-PADM-2 replay/export split is a permission/audit-label distinction, not a capability difference.

**Justification (by design):** replay in this architecture IS client-side fetch-and-decrypt (the SESSION's own Dashboard note: "fetch the encrypted object + decrypt client-side"), because the CP never proxies bytes and cannot decrypt. Making replay a genuinely narrower capability (viewer-mediated / range-limited streaming) would require the CP to proxy/transcode bytes — contradicting the never-proxy-bytes crown-jewels design. The two verbs still let an org grant playback-audit-labeled access separately from export-audit-labeled access.

**Follow-up:** document to operators that both verbs = download-and-decrypt; if capability differentiation is ever required it needs a viewer service outside the CP.
