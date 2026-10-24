# Architecture

```text
p2s.py            launcher, argparse, plain-output modes
core/
  scanner.py      URL normalisation, address policy, pinned HEAD/GET, redirects
  fingerprint.py  header -> explicit PHP version evidence
  versions.py     version parsing and comparison
  assessment.py   advisory DB loading/validation, classification, assess_manual / assess_url
  reports.py      JSON report building and opt-in export
  textsafe.py     sanitising, display width, URL redaction
tui/
  app.py          curses loop, key handling, drawing, worker thread
  screens.py      pure builders for result/archive/error/home content (no curses)
  theme.py        palette with 256/8/mono fallbacks
  art.py          artwork loader and fitting
data/advisories.json   the only place advisory facts and score values live
assets/berserk.txt     user artwork
```

Data flow, URL mode: `app.py` starts one daemon worker -> `assess_url` -> `scanner.inspect_url` (progress callbacks) -> `fingerprint.extract_php_version` -> `assessment.assess_fingerprint` -> `Assessment`. The worker posts events to a `queue.Queue`; only the main thread touches curses. Manual mode calls `assess_manual` directly and never imports networking code paths. Both end in `_assess_version`.

The UI polls at 100 ms only while a job runs; otherwise `getch` blocks, so idle CPU is near zero. Cancelling a job discards its result; the worker is bounded by the network timeouts.

`screens.py` turns an `Assessment` into a `ResultView` (headline, style, score text, short omen) and `dashboard_rows` fits it to the available rows by dropping low-priority rows first; `build_details_lines` produces the scrollable report. It returns lists of `(text, style)` segments; `app.py` draws them with a scroll offset. This keeps layout testable without a terminal.
