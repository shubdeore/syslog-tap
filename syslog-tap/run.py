#!/usr/bin/env python3
"""
run.py

The thing you actually run. Parses logs, generates the report, and prints
a short summary to the terminal so you don't have to open the HTML file
just to know if anything's wrong.

    python run.py                      full pipeline, default log paths
    python run.py --logs a.log b.log   specific files
    python run.py --parse-only         just ingest, skip the report
    python run.py --report-only        rebuild report from what's already in the db
    python run.py --quiet              skip the terminal summary
"""

import logging
import argparse

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")
log = logging.getLogger("run")


def print_terminal_summary():
    """Small text summary printed after a run — no need to open the HTML
    just to check whether the hour was normal or not."""
    from analyze import run_all

    data = run_all()
    s, noise = data["summary"], data["noise"]

    print()
    print(f"  events in db     : {s['total']:,}")
    print(f"  errors / warnings: {s['errors']} / {s['warnings']}")
    print(f"  security events  : {s['security']}")

    if noise.get("available"):
        print(f"  noise score      : {noise['verdict']} (z={noise['z_score']})")
    else:
        print(f"  noise score      : {noise['reason']}")
    print()


def main():
    ap = argparse.ArgumentParser(
        description="syslog-tap — parse syslogs into DuckDB, build a report",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    ap.add_argument("--logs", nargs="+", help="specific log files (default: auto-detect)")
    ap.add_argument("--parse-only", action="store_true")
    ap.add_argument("--report-only", action="store_true")
    ap.add_argument("--quiet", action="store_true", help="skip the terminal summary")
    args = ap.parse_args()

    if not args.report_only:
        from tap import run as run_tap
        inserted = run_tap(log_paths=args.logs)
        log.info("ingested %d new rows", inserted)

    if not args.parse_only:
        from report import run as run_report
        path = run_report()
        log.info("report written to %s", path)

        if not args.quiet:
            print_terminal_summary()


if __name__ == "__main__":
    main()
