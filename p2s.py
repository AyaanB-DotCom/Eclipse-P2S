#!/usr/bin/env python3
"""ECLIPSE // P2S - launcher. Run with: python3 p2s.py"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from core import TOOL_NAME, TOOL_VERSION
from core.assessment import AdvisoryError, assess_manual, assess_url, load_advisories
from core.reports import build_report
from core.scanner import ScanError
from core.textsafe import sanitize_text

BASE = Path(__file__).resolve().parent
DATA_PATH = BASE / "data" / "advisories.json"
ART_PATH = BASE / "assets" / "berserk.txt"


def _print_assessment(a, db, as_json: bool) -> None:
    import json
    from tui.screens import (build_details_lines, dashboard_rows, dashboard_text, lines_to_text,
                             view_from_assessment)
    if as_json:
        print(json.dumps(build_report(a), indent=2, ensure_ascii=False))
    else:
        print(dashboard_text(dashboard_rows(view_from_assessment(a), 18, 76), 76))
        print("\n" + "-" * 76)
        print(lines_to_text(build_details_lines(a, db, 76)))


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="p2s.py", description="%s - PHP2Shell version exposure auditor" % TOOL_NAME)
    parser.add_argument("--version", action="version", version="%s %s" % (TOOL_NAME, TOOL_VERSION))
    parser.add_argument("--manual", metavar="VERSION", help="assess a PHP version offline and print the result")
    parser.add_argument("--url", metavar="URL", help="inspect a URL and print the result (no TUI)")
    parser.add_argument("--json", action="store_true", help="with --manual/--url: print the JSON report")
    parser.add_argument("--allow-local", action="store_true",
                        help="permit loopback/private targets (local testing only)")
    parser.add_argument("--advisories", metavar="PATH", default=str(DATA_PATH), help="advisory database path")
    parser.add_argument("--art", metavar="PATH", default=str(ART_PATH), help="ASCII artwork path")
    parser.add_argument("--export-dir", metavar="DIR", default="exports", help="directory for exported reports")
    args = parser.parse_args(argv)

    try:
        db = load_advisories(Path(args.advisories))
    except AdvisoryError as exc:
        print("ECLIPSE: advisory database error: %s" % sanitize_text(exc), file=sys.stderr)
        print("No assessment can be made. Restore data/advisories.json (see CONTRIBUTING.md).", file=sys.stderr)
        return 2

    if args.manual is not None:
        _print_assessment(assess_manual(db, args.manual), db, args.json)
        return 0
    if args.url is not None:
        try:
            _print_assessment(assess_url(args.url, db, allow_local=args.allow_local), db, args.json)
        except ScanError as exc:
            print("ECLIPSE: inspection failed (%s): %s" % (exc.kind, exc.message), file=sys.stderr)
            print("A failed inspection is not evidence of safety.", file=sys.stderr)
            return 1
        return 0

    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        print("ECLIPSE: an interactive terminal is required. Use --manual or --url for plain output.",
              file=sys.stderr)
        return 2
    from tui.app import run
    try:
        run(db, Path(args.art), args.allow_local, Path(args.export_dir))
    except KeyboardInterrupt:
        print("ECLIPSE: interrupted.", file=sys.stderr)
        return 130
    return 0


if __name__ == "__main__":
    sys.exit(main())
