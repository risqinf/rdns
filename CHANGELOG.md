# Changelog

All notable changes to the **rdns** (Residential & Stealth SmartDNS Platform) project are documented in this file.
This project adheres to [Semantic Versioning](https://semver.org/).

## [v0.2.1] - 2026-11-08

### Fixed
- **Empty Ruleset & Zero-Domain Profiling (`internal/rules/rules.go`)**:
  - Allowed empty ruleset `{}` and zero-domain profile arrays (`{ "profile": [] }`) on startup without fatal panic.
  - mTLS Yamux tunnels to exit nodes remain active and warm even when no domains are assigned yet, routing unmatched traffic directly or via default upstream DNS.
- **Port Conflict Hardening (`internal/nftsetup/nftsetup.go`)**:
  - Migrated default DNS redirect port target from `5353` to `14053` (`DNSTarget: 14053`) to avoid port collisions with `dnsmasq` and system mDNS/Avahi resolvers on client decision nodes.
- **Graceful File Logging Fallback (`internal/logging/logging.go`)**:
  - Implemented non-fatal fallback to stderr if the configured log file path cannot be opened due to strict systemd mount boundaries or read-only filesystem restrictions.
- **Service Hardening (`deploy/rdns-client.service`)**:
  - Added `ExecStartPre` to pre-create `/var/log/rdns-client.log` with mode `0644`.
  - Added `/var/log` and `/etc/rdns` to `ReadWritePaths` under `ProtectSystem=strict`.

## [v0.2.0] - 2026-11-06

### Added
- **SmartDNS / Reverse DNS Split Routing Engine**:
  - Multi-profile mTLS Yamux stealth tunnels between decision node and exit nodes.
  - Interceptors for UDP DNS (:5353), TCP SNI (:14300), and UDP QUIC (:14400).
  - High-performance Longest-Suffix Domain Rule matcher.
- **Media CDN Direct Streaming Bypass (`cdn_direct: true`)**:
  - Direct video chunk streaming for Netflix, Disney+, Prime, YouTube, reducing exit node bandwidth consumption by >99%.
- **PKI & 1-Click Pairing Token (`tools/rdns-certs`)**:
  - Built-in CA and certificate minting with base64 `rdns://` token encoding for 1-click client pairing.
