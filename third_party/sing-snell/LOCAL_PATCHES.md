# Local URLTest session handoff

Upstream: v0.0.0-20260904135315-bc5a12ac736f. All files are copied from the upstream Go module archive; changes are limited to snellv6/reuse.go and the new snellv6/urltest.go.

URLTestDialer owns one physical Snell v6 session for exactly two logical requests. The first is the existing HTTP warmup; the second waits for its server EOF before reusing the same transport. The reserved session is never inserted into the shared pool, so background traffic cannot consume it between requests. It is closed when the probe finishes or fails.

Ordinary clients retain the original pool behavior. TCP Fast Open and the configured underlying dialer remain active for the warmup. The measured request still establishes its own destination TCP/TLS connection and performs the original HEAD request; only the proxy-session handoff is made deterministic.

Tests in the parent repository's protocol/snell package exercise the complete URLTest entry point with a Snell server and controlled EOF/connect delays. The existing common/dialer tests verify real Android-path TFO socket controls.
