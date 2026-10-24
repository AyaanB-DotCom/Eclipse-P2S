# ECLIPSE // P2S

*Beneath the Eclipse, nothing remains hidden.*
<img width="3456" height="2218" alt="Screenshot 2026-10-23 at 10 06 57 PM-clean" src="https://github.com/user-attachments/assets/75dd12fc-83b1-423b-9548-630cd8601641" />


ECLIPSE // P2S is a local, zero-dependency terminal auditor for PHP2Shell version exposure. It reads the PHP version a website reports in ordinary HTTP response headers, compares it with a bundled snapshot of the October 2026 PHP security fixes, and prints a version-based triage assessment with its evidence. It never sends exploit payloads and never claims a vulnerability is confirmed.

The interface is a keyboard-driven `curses` application styled after a cursed Unix diagnostic tool from the 1990s.

## Terminal preview

A scan ends on **THE BRAND**, a compact screen built to be read in seconds and to fit 80x24. *The layout below is illustrative; the values are an example, not an observation of any real server.*

<img width="3456" height="2218" alt="Screenshot 2026-10-23 at 10 06 50 PM-clean" src="https://github.com/user-attachments/assets/e857ea80-6eeb-4e99-9f03-253bc65d2e15" />


The score is the centerpiece: crimson for *potential exposure*, desaturated green for *original fix threshold met*, amber for *inconclusive* / *legacy* / *unknown coverage*. Inconclusive results show `N/A`, never a made-up number, and no fixed version. On terminals of about 30 rows or more the score is drawn in large block digits; on short terminals optional lines are dropped, but the score, classification and the key footer always stay.

`[D]` opens **THE ARCHIVE**, a scrollable technical report with sections: target inspection, version evidence, PHP2Shell assessment, related advisories (CVE-2026-115560), recommendations, limitations and database. The same assessment feeds the dashboard, the report and the JSON export. Run `python3 p2s.py --manual 8.3.35` to print both views for any version without opening the TUI.

## What is PHP2Shell?

PHP2Shell is the name used for two critical PHP vulnerabilities disclosed by the PHP project on 2026-10-21, both rated CVSS v4.0 9.2:

- **CVE-2026-109618** ([GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)): remote code execution through out-of-memory state corruption. An out-of-memory path that used `longjmp()` could leave request data partially initialised, and request shutdown could then act on invalid memory.
- **CVE-2026-109619** ([GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)): remote code execution through stale global state (use-after-free). Worker-level state could keep references to request memory after it was freed.

Exploitability depends on the SAPI, PHP configuration and worker behaviour. Apache `mod_php` was the highest confirmed concern. PHP-FPM, php-cgi, FrankenPHP and LiteSpeed/LSAPI deployments can also be affected.

| Branch | Last pre-fix release | First fixed upstream release |
|---|---|---|
| 8.2 | 8.2.34 | **8.2.35** |
| 8.3 | 8.3.35 | **8.3.36** |
| 8.4 | 8.4.26 | **8.4.27** |
| 8.5 | 8.5.11 | **8.5.12** |

PHP 8.1 and older are end-of-life upstream and got no ordinary release; backports exist for source builds and some vendors ship patched packages under the old version number.

A **separate** issue, CVE-2026-115560 (session upload progress, announced 2026-10-23), is *not* fixed by those releases and is *not* part of the score. ECLIPSE shows it as an additional advisory on every result. See [docs/RESEARCH.md](docs/RESEARCH.md).

## Features

- Local `curses` interface, arrow keys and shortcuts, scrolling, resize handling, colour fallback to 8 colours and monochrome.
- **Inspect target**: bounded HEAD request (at most one follow-up GET, body never read), redirect validation, TLS verification.
- **Manual version**: fully offline assessment of a version you type in. Same engine as URL mode.
- Exact numeric version comparison per branch; conservative handling of pre-releases, vendor suffixes, legacy and unknown branches.
- Opt-in JSON report export to `./exports/`.
- Bundled, manually maintained advisory database: `data/advisories.json`.
- Your own ASCII artwork loaded from `assets/berserk.txt`.
- Python standard library only. No telemetry, no network access except the target you enter.

## Requirements and installation

Python 3.9 or newer and a terminal with `curses` (macOS, Linux).

```bash
python3 --version
```

```bash
git clone https://github.com/USERNAME/eclipse-p2s.git
cd eclipse-p2s
python3 p2s.py
```

(`USERNAME` is a placeholder; this repository has not been published.)

## Usage

```bash
python3 p2s.py                      # interactive interface
python3 p2s.py --manual 8.3.35      # offline, plain output
python3 p2s.py --manual 8.3.36 --json
python3 p2s.py --url example.com    # inspect without the TUI (only for systems you may test)
python3 p2s.py --url localhost:8080 --allow-local   # local testing of your own server
```

Keys:

| Screen | Keys |
|---|---|
| Menu | `Up/Down`, `Enter`, `1`-`4` (or `I`, `M`, `A`, `Q`) |
| Text input | typing, Backspace, Delete, arrows, `Home/End` (`Ctrl-A`/`Ctrl-E`), `Ctrl-U`, `Enter` begin, `Esc` back |
| THE BRAND (result) | `N` new, `D` details, `E` export JSON, `Q` quit, `Esc` home |
| THE ARCHIVE (details) | `Esc` / `B` back, `Up/Down` (or `j/k`) scroll, `PgUp/PgDn` page, `Home/End`, `Q` quit |
| Menu "THE ARCHIVE" | advisory database records (scroll as above, `Esc` back) |

Accepted targets: `example.com`, `https://example.com`, `http://example.com`, `https://example.com/path`. A missing scheme means HTTPS. URLs with embedded credentials are rejected.

## How detection works

ECLIPSE collects response headers and looks only at `X-Powered-By` and `Server` for a literal `PHP/MAJOR.MINOR.PATCH` token, which PHP emits when `expose_php` is on. Cookies (`PHPSESSID`), CMS names, `.php` URLs, frameworks and web server names are **not** evidence of a version. Two different reported versions yield *CONFLICTING VERSION EVIDENCE* instead of a pick. The version is then compared numerically with the first fixed release of its own branch. Details: [docs/DETECTION.md](docs/DETECTION.md).

## Risk scoring

The 0-100 score is a custom triage heuristic. It is not CVSS and not a probability of compromise.

| Condition | Score | Classification |
|---|---|---|
| Known branch, below first fixed release | 95 | POTENTIAL EXPOSURE |
| Known branch, at or above first fixed release | 0 | ORIGINAL FIX THRESHOLD MET |
| PHP 8.1 or older (upstream EOL) | 90 | LEGACY PATCH REVIEW |
| No version, conflicting versions, unparseable or pre-release/unrecognised suffix | N/A | INCONCLUSIVE |
| Branch newer than 8.5 | N/A | ADVISORY COVERAGE UNKNOWN |

`0` never means a site is secure and `95` never means exploitation is confirmed. Score values live in the database.

## Limitations

- Many servers hide the version (`expose_php=Off`) or sit behind proxies that strip it: the result is then *inconclusive*, which is **not** safe.
- Headers can be spoofed or stale. A reported version is unverified.
- Vendors backport fixes without changing the version number, so *POTENTIAL EXPOSURE* may be a false positive.
- The PHP SAPI and configuration are not detected and are not guessed from `Server: nginx/Apache`.
- No exploitation or vulnerability test is ever performed.
- The database is a snapshot reviewed on 2026-10-23; later advisories are not known to the tool.
- CVE-2026-115560 depends on configuration and application code and cannot be judged from a version.
- Private-address blocking resolves a name before connecting and pins the connection to that address; exotic cases (IPv6 transition addresses, a resolver answering differently between hops, intermediaries) are not fully covered. This is not a complete SSRF defence.

## Updating advisories

Edit `data/advisories.json` by hand from official PHP announcements, bump `database_version` and `last_reviewed`, and run the tests. The file is validated at startup; a malformed or unsupported file stops the tool with a clear error. See [CONTRIBUTING.md](CONTRIBUTING.md).

## Custom ASCII artwork

Put UTF-8 text in `assets/berserk.txt`. It is loaded at runtime, never modified, never scaled, centred if it fits the width, bottom-cropped if the terminal is short (at least 8 rows), and hidden if it is too wide or too short. Without it the wordmark is shown. Pass `--art PATH` to use another file.

## Tests

```bash
python3 -m unittest discover -s tests -t . -v
```

Tests are offline; network behaviour is checked against a throwaway local HTTP server and mocks. Interactive curses behaviour is not covered by unit tests; see the manual checklist in [CONTRIBUTING.md](CONTRIBUTING.md).

## References

- https://www.php.net/archive/2026.php
- https://www.php.net/archive/2026.php#2026-10-21-1
- https://www.php.net/archive/2026.php#2026-10-23-1
- https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w
- https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp
- https://www.php.net/manual/en/ini.core.php
- https://www.php.net/manual/en/security.hiding.php
- https://support.plesk.com/hc/en-us/articles/44397729587351-Vulnerability-CVE-2026-109618-and-CVE-2026-109619-PHP2Shell-Remote-code-execution-in-PHP-shipped-with-Plesk

## Responsible use

ECLIPSE sends ordinary, non-destructive requests, but only inspect systems you own or are authorised to assess.

## License

The code is MIT licensed, see [LICENSE](LICENSE). Artwork you place in `assets/` is **not** covered by that license; it belongs to its owner, and you should not redistribute third-party artwork without permission.

## Attribution

The visual theme is independently inspired by dark fantasy. This project is not affiliated with, endorsed by, or an official product of Berserk, its creators or publishers.
