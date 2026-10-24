# Detection and scoring

## Header collection (`core/scanner.py`)

1. The input is normalised (`https://` assumed; only http/https; no credentials; valid host and port).
2. The host is resolved once per hop. Every address must be public (loopback, private, link-local, CGNAT, multicast and metadata addresses are refused) unless `--allow-local` is given. The socket then connects to the validated address, with the original hostname used for `Host` and TLS SNI.
3. One `HEAD` request is sent. Redirects (max 3) are re-validated with the same rules, and only http/https destinations are followed.
4. If the final response shows no PHP version, a single `GET` is sent to the same URL; its body is never read. If it fails, the HEAD result is kept.
5. Non-2xx responses are still inspected: error pages often carry the same headers.

Environment proxies are never used. TLS verification uses the platform default context. Timeouts apply per socket operation, plus a watchdog that closes the connection after twice the timeout.

Residual limits: a server can still answer differently on different hops; resolution of a name between our check and a redirect hop is not atomic; IPv6 transition mechanisms and hostile intermediaries are not modelled. This is a safety default, not a full SSRF defence.

## Fingerprint (`core/fingerprint.py`)

Only `X-Powered-By` and `Server` are read, case-insensitively, including repeated headers. A token `PHP/<major>.<minor>.<patch>[suffix]` counts. `PHP/8.3` (no patch) and `mod_php/8.3.35` do not. Cookies, CMS names, `.php` URLs, framework headers and web server names never count. Identical values from several headers agree; different values give `CONFLICTING VERSION EVIDENCE` and no choice is made. Values are sanitised against terminal control characters.

Evidence quality is `EXPLICIT HEADER DISCLOSURE` (self-reported, unverified) for URL mode and `USER-SUPPLIED VERSION` for manual mode.

## Version parsing (`core/versions.py`)

`MAJOR.MINOR.PATCH` compared as integers, never as strings. A suffix is classified: `final` (none), `vendor_build` (`-1ubuntu1`, `+dfsg`), `prerelease` (`RC1`, `-dev`, `alpha`, `beta`, ...), or `unrecognized`. Pre-release and unrecognised suffixes on a known branch are *inconclusive*; `8.3.36RC1` is not treated as 8.3.36. A vendor-build suffix is compared by its numeric part and carries an explicit caveat.

## Classification (`core/assessment.py`)

Order of decisions: unparseable -> INCONCLUSIVE; branch not in the database and newer than the legacy limit -> ADVISORY COVERAGE UNKNOWN; pre-release/unrecognised suffix -> INCONCLUSIVE; legacy branch (<= 8.1) -> LEGACY PATCH REVIEW (90); below the branch's first fixed release -> POTENTIAL EXPOSURE (95); otherwise ORIGINAL FIX THRESHOLD MET (0). Scores come from `data/advisories.json`. CVE-2026-115560 never influences the score.

## Why unknown means unknown

No header does not mean no PHP, and it does not mean patched. Hidden, stripped or spoofed headers produce false negatives and false positives. A positive score is a prompt to check the real runtime, not a finding of exploitability: nothing is sent that could confirm or refute the vulnerabilities.
