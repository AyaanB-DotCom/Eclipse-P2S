# Contributing

## Setup

Python 3.9+ and nothing else. There are no runtime or test dependencies and none may be added.

```bash
python3 p2s.py                         # run the interface
python3 -m unittest discover -s tests -t . -v
```

## Layout

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). Keep rendering (`tui/`) separate from networking and assessment (`core/`). New screen text goes into the pure builders in `tui/screens.py` so it can be unit tested.

## Style

Type hints, small functions, standard-library only, ASCII in source except where the artwork requires otherwise. All server-supplied or user-supplied text must pass through `core.textsafe.sanitize_text` before display or storage.

## Updating advisory data

1. Read the official PHP announcement or GitHub advisory. Do not rely on secondary summaries or unaudited proofs of concept.
2. Edit `data/advisories.json`: fixed versions per branch, `related_advisories`, `sources`, then bump `database_version` and `last_reviewed`.
3. A new CVE with a published fixed threshold changes scoring; one without a threshold stays in `related_advisories` with `included_in_primary_score: false`.
4. Add or adjust tests in `tests/test_assessment.py` (threshold, one below, one above) and update `docs/RESEARCH.md` and `CHANGELOG.md`.
5. Run the tests; the file is validated by `core.assessment.validate_advisories`.

Every security claim needs a primary-source reference. Do not weaken caveats (vendor backports, self-reported versions, unknown means unknown).

## Scanning behaviour

Contributions must stay non-destructive: HEAD plus at most one GET, no bodies, no payloads, no path guessing, no fuzzing, no mass scanning. Changes to `core/scanner.py` need tests for the address policy and redirects.

## Manual TUI checklist

Automated tests do not drive curses. Before a release verify in a real terminal: opening screen with and without `assets/berserk.txt`; resize from large to tiny and back; manual flow `8.3.35` and `8.3.36`; the result dashboard at 80x24, 100x30 and 120x40 with the footer always visible; `D` opens the details, scroll to the end, `B` returns; `E` creates a file under `exports/`; `Esc` cancels an in-flight inspection; `Ctrl+C` restores the terminal; 8-colour (`TERM=xterm`) and `NO_COLOR`-like mono terminals remain readable; idle CPU stays near zero.

## Pull requests

Small, focused, with tests. Describe what you verified and how.
