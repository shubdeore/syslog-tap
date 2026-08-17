#!/usr/bin/env python3
"""
tap.py

Reads syslog-format log files and loads them into a local DuckDB file
as structured rows instead of raw text. That's the whole job of this
file — parsing and getting data into the database. Nothing here writes
reports or runs analysis; see analyze.py and report.py for that.

Written against RFC 3164 syslog format, which is what rsyslog / syslog-ng
still write by default on most distros:

    Jan  5 03:14:07 myhost sshd[1122]: Failed password for root from 1.2.3.4

If your logs are already JSON (journald --output=json, some cloud setups),
this won't be much use to you as-is — the regex below assumes the classic
plain-text format.
"""

import re
import os
import sys
import logging
import argparse
from datetime import datetime

import duckdb

DB_PATH = os.environ.get("TAP_DB", "db/tap.duckdb")

# Default places to look for logs, checked in order. First few that
# actually exist on disk get used — you don't have to pick a distro.
DEFAULT_LOG_PATHS = [
    "/var/log/syslog",
    "/var/log/messages",
    "/var/log/auth.log",
    "/var/log/secure",
]

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")
log = logging.getLogger("tap")

# group names double as the dict keys we build records from further down
LINE_RE = re.compile(
    r'^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+'
    r'(?P<host>\S+)\s+'
    r'(?P<process>[^\[:]+?)(?:\[(?P<pid>\d+)\])?:\s+'
    r'(?P<message>.+)$'
)

MONTHS = {m: i + 1 for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
)}

# Keyword buckets used for the quick-and-dirty severity/event tagging below.
# This is intentionally simple string matching, not a real log-format parser
# per source — syslog doesn't give you a severity field in the plain-text
# format most of the time, so this is a reasonable stand-in.
ERROR_WORDS = ("error", "failed", "failure", "critical", "fatal", "panic")
WARN_WORDS = ("warn", "warning", "deprecated")
SECURITY_WORDS = ("invalid", "refused", "denied", "unauthorized", "reject")

AUTH_PROCS = ("sshd", "su", "sudo", "pam", "login")
SYSTEM_PROCS = ("systemd", "kernel", "init")
MEMORY_WORDS = ("oom", "out of memory", "killed process")


def guess_severity(message: str) -> str:
    m = message.lower()
    if any(w in m for w in ERROR_WORDS):
        return "ERROR"
    if any(w in m for w in WARN_WORDS):
        return "WARN"
    if any(w in m for w in SECURITY_WORDS):
        return "SECURITY"
    return "INFO"


def guess_event_type(process: str, message: str) -> str:
    p, m = process.lower(), message.lower()
    if any(k in p for k in AUTH_PROCS):
        return "auth"
    if any(k in m for k in MEMORY_WORDS):
        return "memory"
    if any(k in p for k in SYSTEM_PROCS) or any(k in m for k in ("started", "stopped", "restart", "failed to start")):
        return "service"
    return "general"


def parse_line(line: str, source_file: str):
    """One raw log line in, one dict out (or None if it doesn't match)."""
    line = line.rstrip("\n")
    if not line.strip():
        return None

    match = LINE_RE.match(line)
    if not match:
        # Not every line in a syslog file is a well-formed log line — kernel
        # ring buffer dumps, multi-line stack traces, etc. all show up here
        # and just get skipped. That's expected, not a bug.
        return None

    try:
        year = datetime.now().year  # syslog doesn't include a year, annoyingly
        month = MONTHS.get(match.group("month"), 1)
        day = int(match.group("day"))
        ts = datetime.strptime(f"{year}-{month:02d}-{day:02d} {match.group('time')}", "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None

    process = match.group("process").strip()
    message = match.group("message").strip()
    pid = match.group("pid")

    return {
        "ts": ts,
        "host": match.group("host"),
        "process": process,
        "pid": int(pid) if pid else None,
        "message": message[:2000],
        "severity": guess_severity(message),
        "event_type": guess_event_type(process, message),
        "source_file": os.path.basename(source_file),
        "raw_line": line[:2000],
    }


def ensure_schema(conn):
    conn.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id           INTEGER PRIMARY KEY,
            ts           TIMESTAMP NOT NULL,
            host         VARCHAR,
            process      VARCHAR,
            pid          INTEGER,
            message      TEXT,
            severity     VARCHAR,
            event_type   VARCHAR,
            source_file  VARCHAR,
            raw_line     TEXT,
            ingested_at  TIMESTAMP DEFAULT current_timestamp
        )
    """)
    conn.execute("CREATE SEQUENCE IF NOT EXISTS events_id_seq START 1")
    for col in ("ts", "severity", "event_type", "process"):
        conn.execute(f"CREATE INDEX IF NOT EXISTS idx_events_{col} ON events({col})")


def already_seen(conn) -> set:
    """
    (source_file, raw_line) pairs for everything already in the table.
    This is how re-running tap.py against the same log file doesn't
    double-insert every line every time — cron will call this hourly
    and most of the file will already be known.

    Note: this used to compare hashes instead of the raw tuples directly,
    but DuckDB's hash() and Python's built-in hash() are different
    algorithms — hashing on one side and comparing against the other
    meant nothing ever matched, silently, no error, just quietly wrong.
    A set of tuples is a few extra bytes per row but it's actually correct.
    """
    try:
        rows = conn.execute("SELECT source_file, raw_line FROM events").fetchall()
        return {(r[0], r[1]) for r in rows}
    except duckdb.Error:
        return set()


def ingest_file(conn, path: str, seen: set) -> tuple[int, int]:
    if not os.path.exists(path):
        log.warning("skipping %s — file doesn't exist", path)
        return 0, 0

    batch = []
    dupes = 0
    unparsed = 0

    with open(path, "r", errors="replace") as f:
        for line in f:
            record = parse_line(line, path)
            if record is None:
                unparsed += 1
                continue
            key = (record["source_file"], record["raw_line"])
            if key in seen:
                dupes += 1
                continue
            seen.add(key)
            batch.append(record)

    if not batch:
        log.info("%s: nothing new (%d already seen, %d unparsed)", path, dupes, unparsed)
        return 0, dupes

    conn.executemany(
        """
        INSERT INTO events (id, ts, host, process, pid, message, severity, event_type, source_file, raw_line)
        VALUES (nextval('events_id_seq'), ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        [
            (r["ts"], r["host"], r["process"], r["pid"], r["message"],
             r["severity"], r["event_type"], r["source_file"], r["raw_line"])
            for r in batch
        ],
    )

    log.info("%s: +%d rows (%d dupes skipped, %d unparsed)", path, len(batch), dupes, unparsed)
    return len(batch), dupes


def run(log_paths=None) -> int:
    paths = log_paths or [p for p in DEFAULT_LOG_PATHS if os.path.exists(p)]
    if not paths:
        log.error("couldn't find any log files. pass --logs explicitly.")
        sys.exit(1)

    os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)
    conn = duckdb.connect(DB_PATH)
    ensure_schema(conn)

    seen = already_seen(conn)
    log.info("%d rows already in the db", len(seen))

    inserted = skipped = 0
    for path in paths:
        i, s = ingest_file(conn, path, seen)
        inserted += i
        skipped += s

    total = conn.execute("SELECT count(*) FROM events").fetchone()[0]
    log.info("done — %d new, %d skipped, %d total in db", inserted, skipped, total)
    conn.close()
    return inserted


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Parse syslog files into DuckDB")
    ap.add_argument("--logs", nargs="+", help="specific log files, otherwise auto-detected")
    run(log_paths=ap.parse_args().logs)
