module github.com/sandy-t-shelvan/govcode

// Standard library only. Adding a third-party module requires an SBOM
// update and security review (see docs/SUPPLY_CHAIN.md).
//
// The patch-level go directive makes any older (vulnerable) toolchain
// refuse to build: Go 1.24.7 had 36 reachable standard-library
// vulnerabilities; 1.27.4 has none known (govulncheck, Nov 2026).
go 1.27.4
