# Security policy

## Supported versions

Only the latest 1.x release receives fixes.

## Reporting a vulnerability in ECLIPSE

Please do not open a public issue for a security problem. Once the repository is published, enable GitHub private vulnerability reporting (Settings -> Code security -> Private vulnerability reporting) and report through the "Security" tab. No e-mail address is published here; add one in this file if you prefer e-mail. Expect an acknowledgement and coordinated disclosure; please allow reasonable time before publishing details.

## Scope

In scope: bypasses of the target address policy or redirect validation, terminal escape injection through server-controlled or user-controlled text, unintended requests (anything beyond HEAD and one GET, any request body), credential or token leakage into reports, crashes caused by hostile responses, and wrong classification of a version against the bundled database.

Out of scope: vulnerabilities in PHP itself, results that are wrong because a server lies about its version, and the inherent limits below.

## Known limitations

- Header-based version detection is unauthenticated and incomplete. A positive score does not prove exploitability; it only means a reported version predates a fix.
- An unknown or inconclusive result must never be read as safe.
- Vendor backports can make a reported old version patched.
- Address blocking is a best-effort default, not a complete SSRF defence (see docs/DETECTION.md).
- The advisory data is a manual snapshot and may be stale.

## Responsible use

Only assess systems you own or have written permission to test. Handle target URLs as potentially sensitive: reports drop credentials, query strings and fragments, but exported files are stored locally in plain text.
