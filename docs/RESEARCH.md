# Research basis

**Research cutoff: 2026-10-23.** The advisory facts below were supplied to this project as an already-verified brief and encoded in `data/advisories.json`. They were **not** independently re-fetched while the tool was built, and the application itself performs no research or updates at runtime. The database is a historical, manually maintained snapshot.

## CVE-2026-109618 (GHSA-w8hw-w9fx-j79w)

Remote code execution through out-of-memory state corruption. PHP historically used `longjmp()` in some out-of-memory paths; if an allocation failed while request data was only partly initialised, the request ended with invalid internal state and shutdown processing could act on it. Apache `mod_php` was the most significant confirmed concern because it can run request shutdown after early startup failures. CVSS v4.0 9.2.

## CVE-2026-109619 (GHSA-6wmf-4rv5-p3rp)

Remote code execution through stale global state (use-after-free). Some worker-level state can reference per-request memory that is later freed; a subsequent request may use it. Exploitation depends on conditions, PHP configuration and worker behaviour. CVSS v4.0 9.2.

Do not equate an affected version with proven exploitability.

## Fixed releases (2026-10-21)

| Branch | Last pre-fix | First fixed upstream |
|---|---|---|
| 8.2 | 8.2.34 | 8.2.35 |
| 8.3 | 8.3.35 | 8.3.36 |
| 8.4 | 8.4.26 | 8.4.27 |
| 8.5 | 8.5.11 | 8.5.12 |

## Unsupported branches and vendor backports

PHP 8.1 and older are end-of-life upstream and received no ordinary release in this security release. The PHP security team supplied minimal source backports for 7.4, 8.0 and 8.1, and some OS or extended-support vendors patch older branches. Plesk guidance (2026-10-22) describes patched 7.4.33, 8.0.30 and 8.1.34 builds that keep the upstream number and differ by build date. A version number therefore cannot show patch state; ECLIPSE classifies such versions as *legacy, patch review*, never as confirmed vulnerable.

The same caveat applies to supported branches: a distribution may ship a fix under an older number, so *potential exposure* can be a false positive.

## PHP 8.6 prerelease

PHP 8.6.0 RC4 (2026-10-21) contained both fixes but is a testing release not meant for production. ECLIPSE reports unknown future branches and prereleases as *advisory coverage unknown* / *inconclusive* and does not infer production safety.

## CVE-2026-115560 (informational advisory, 2026-10-23)

A separate session upload progress issue, not resolved by the 2026-10-21 releases. Per PHP's guidance it needs: `session.serialize_handler` set to `php_binary` or `php_serialize`; application code switching it to `php` with `ini_set()`; a later `session_start()`; and session upload progress still enabled. PHP recommends `session.upload_progress.enabled=0` until the next regular bugfix release for potentially affected configurations; applications that never change the handler at runtime can leave it enabled. As of the cutoff, the full advisory and fixed-version list were unpublished. It is **excluded** from the numeric score and shown separately.

## Affected environments

Apache `mod_php`, PHP-FPM, php-cgi, FrankenPHP and LiteSpeed/LSAPI. Exposure differs per environment and configuration. The SAPI cannot be inferred from a generic `Server` header and ECLIPSE does not guess it.

## Mitigations (partial)

Updating to a fixed release or an appropriately patched vendor package is the complete remediation. Partial reductions: `memory_limit=-1` and request/multipart size limits (CVE-2026-109618); disabling session upload progress and restarting workers, plus `fatal_error_backtraces=0` on PHP 8.5 (CVE-2026-109619). These do not replace patching.

## Version disclosure

`expose_php` makes PHP add `X-Powered-By: PHP/x.y.z`. It can be disabled and proxies can strip it, so remote detection is incomplete and unauthenticated.

## Sources (plain text)

- https://www.php.net/archive/2026.php
- https://www.php.net/archive/2026.php#2026-10-21-1
- https://www.php.net/archive/2026.php#2026-10-23-1
- https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w
- https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp
- https://www.php.net/manual/en/ini.core.php
- https://www.php.net/manual/en/security.hiding.php
- https://support.plesk.com/hc/en-us/articles/44397729587351-Vulnerability-CVE-2026-109618-and-CVE-2026-109619-PHP2Shell-Remote-code-execution-in-PHP-shipped-with-Plesk

Maintainers should re-verify every claim against these primary sources before changing the database.
