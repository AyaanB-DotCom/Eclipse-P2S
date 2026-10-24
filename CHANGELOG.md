# Changelog

## 1.0.0 - unreleased

Initial version.

- Curses interface with opening screen, URL inspection, manual offline version check, advisory database archive and JSON export.
- Compact result dashboard (THE BRAND) that fits 80x24 with a fixed key footer, and a scrollable detailed report (THE ARCHIVE) opened with `D`.
- HTTP header fingerprinting of explicit `PHP/x.y.z` disclosures (`X-Powered-By`, `Server`) with conflict detection.
- Numeric version comparison with pre-release and vendor-suffix handling.
- Version-based triage score for CVE-2026-109618 and CVE-2026-109619; legacy, unknown-branch and inconclusive handling; CVE-2026-115560 shown separately.
- Bounded HEAD/GET inspection with address policy, redirect validation, TLS verification, no proxies.
- Bundled advisory snapshot (reviewed 2026-10-23) with startup validation.
- External ASCII artwork loading from `assets/berserk.txt`.
- `unittest` suite and GitHub Actions workflow definition.
