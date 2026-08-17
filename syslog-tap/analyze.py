#!/usr/bin/env python3
"""
analyze.py

All the SQL lives here. Each function is one question about the log data
("who's failing to log in", "which hour was the worst", etc.) and returns
plain lists/dicts so report.py doesn't need to know anything about SQL.

The one thing in here that isn't just a GROUP BY is `noise_score()` near
the bottom — everything else is straightforward aggregation.
"""

import os
import logging
import statistics
import duckdb

DB_PATH = os.environ.get("TAP_DB", "db/tap.duckdb")

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")
log = logging.getLogger("analyze")


def connect():
    if not os.path.exists(DB_PATH):
        raise FileNotFoundError(f"no db at {DB_PATH} — run tap.py first")
    return duckdb.connect(DB_PATH, read_only=True)


def summary(conn) -> dict:
    row = conn.execute("""
        SELECT
            count(*),
            count(*) FILTER (WHERE severity = 'ERROR'),
            count(*) FILTER (WHERE severity = 'WARN'),
            count(*) FILTER (WHERE severity = 'SECURITY'),
            min(ts), max(ts),
            count(DISTINCT host),
            count(DISTINCT process)
        FROM events
    """).fetchone()
    return {
        "total": row[0], "errors": row[1], "warnings": row[2], "security": row[3],
        "earliest": str(row[4]) if row[4] else "n/a",
        "latest": str(row[5]) if row[5] else "n/a",
        "hosts": row[6], "processes": row[7],
    }


def failed_logins(conn, limit=20) -> list:
    rows = conn.execute("""
        SELECT ts, host, process, message
        FROM events
        WHERE event_type = 'auth'
          AND (message ILIKE '%failed password%'
               OR message ILIKE '%invalid user%'
               OR message ILIKE '%authentication failure%')
        ORDER BY ts DESC
        LIMIT ?
    """, [limit]).fetchall()
    return [{"ts": str(r[0]), "host": r[1], "process": r[2], "message": r[3]} for r in rows]


def failed_login_sources(conn) -> list:
    """Which process is on the receiving end of the most failed auth attempts."""
    rows = conn.execute("""
        SELECT process, count(*), min(ts), max(ts)
        FROM events
        WHERE event_type = 'auth'
          AND (message ILIKE '%failed password%' OR message ILIKE '%invalid user%')
        GROUP BY process
        ORDER BY 2 DESC
    """).fetchall()
    return [{"process": r[0], "attempts": r[1], "first": str(r[2]), "last": str(r[3])} for r in rows]


def service_flaps(conn, limit=20) -> list:
    """Things starting, stopping, restarting, or failing to start."""
    rows = conn.execute("""
        SELECT ts, host, process, message
        FROM events
        WHERE event_type = 'service'
          AND (message ILIKE '%started%' OR message ILIKE '%stopped%'
               OR message ILIKE '%restart%' OR message ILIKE '%failed to start%')
        ORDER BY ts DESC
        LIMIT ?
    """, [limit]).fetchall()
    return [{"ts": str(r[0]), "host": r[1], "process": r[2], "message": r[3]} for r in rows]


def errors_by_hour(conn) -> list:
    rows = conn.execute("""
        SELECT date_trunc('hour', ts) AS h, count(*)
        FROM events
        WHERE severity = 'ERROR'
        GROUP BY 1
        ORDER BY 2 DESC
        LIMIT 24
    """).fetchall()
    return [{"hour": str(r[0]), "count": r[1]} for r in rows]


def noisiest_processes(conn, limit=10) -> list:
    rows = conn.execute("""
        SELECT process, count(*) FROM events
        WHERE severity = 'ERROR'
        GROUP BY process ORDER BY 2 DESC LIMIT ?
    """, [limit]).fetchall()
    return [{"process": r[0], "errors": r[1]} for r in rows]


def severity_split(conn) -> list:
    rows = conn.execute("""
        SELECT severity, count(*), round(count(*) * 100.0 / sum(count(*)) OVER (), 1)
        FROM events GROUP BY severity ORDER BY 2 DESC
    """).fetchall()
    return [{"severity": r[0], "count": r[1], "pct": float(r[2])} for r in rows]


def event_type_split(conn) -> list:
    rows = conn.execute("SELECT event_type, count(*) FROM events GROUP BY 1 ORDER BY 2 DESC").fetchall()
    return [{"event_type": r[0], "count": r[1]} for r in rows]


def recent_security_events(conn, limit=15) -> list:
    rows = conn.execute("""
        SELECT ts, host, process, message FROM events
        WHERE severity = 'SECURITY' ORDER BY ts DESC LIMIT ?
    """, [limit]).fetchall()
    return [{"ts": str(r[0]), "host": r[1], "process": r[2], "message": r[3]} for r in rows]


def memory_events(conn, limit=10) -> list:
    rows = conn.execute("""
        SELECT ts, host, process, message FROM events
        WHERE event_type = 'memory' ORDER BY ts DESC LIMIT ?
    """, [limit]).fetchall()
    return [{"ts": str(r[0]), "host": r[1], "process": r[2], "message": r[3]} for r in rows]


def hourly_volume(conn, hours=48) -> list:
    rows = conn.execute("""
        SELECT date_trunc('hour', ts) AS h, count(*),
               count(*) FILTER (WHERE severity = 'ERROR'),
               count(*) FILTER (WHERE severity = 'SECURITY')
        FROM events GROUP BY 1 ORDER BY 1 DESC LIMIT ?
    """, [hours]).fetchall()
    return [{"hour": str(r[0]), "total": r[1], "errors": r[2], "security": r[3]} for r in rows]


def noise_score(conn) -> dict:
    """
    This is the one bit of "analysis" in here that isn't a plain GROUP BY.

    The idea: instead of a hardcoded "more than N errors = bad" threshold,
    compare the most recent hour of log volume against a rolling baseline
    built from the hours before it. A quiet system that suddenly gets loud
    is more interesting than a system that's always a little noisy.

    It's a simple z-score, not anything statistically fancy — (latest hour's
    event count minus the mean of the last N hours) divided by their stdev.
    A score past ~2 means "this hour was meaningfully louder than usual for
    THIS machine," which matters more than an arbitrary fixed number, since
    "normal" volume varies a lot host to host.

    If there isn't enough history yet to build a baseline (fresh DB, first
    run) this just says so instead of guessing.
    """
    rows = conn.execute("""
        SELECT date_trunc('hour', ts) AS h, count(*)
        FROM events GROUP BY 1 ORDER BY 1 DESC LIMIT 25
    """).fetchall()

    if len(rows) < 6:
        return {"available": False, "reason": "not enough history yet (need ~6+ hourly buckets)"}

    latest_hour, latest_count = rows[0]
    baseline_counts = [r[1] for r in rows[1:25]]

    mean = statistics.mean(baseline_counts)
    stdev = statistics.pstdev(baseline_counts)

    if stdev == 0:
        # perfectly flat baseline — any deviation at all is notable
        z = 0.0 if latest_count == mean else float("inf")
    else:
        z = (latest_count - mean) / stdev

    if z == float("inf") or z > 3:
        verdict = "unusually loud"
    elif z > 1.5:
        verdict = "a bit louder than usual"
    elif z < -1.5:
        verdict = "unusually quiet"
    else:
        verdict = "normal range"

    return {
        "available": True,
        "hour": str(latest_hour),
        "latest_count": latest_count,
        "baseline_mean": round(mean, 1),
        "baseline_stdev": round(stdev, 1),
        "z_score": round(z, 2) if z != float("inf") else None,
        "verdict": verdict,
    }


def run_all() -> dict:
    conn = connect()
    try:
        return {
            "summary": summary(conn),
            "noise": noise_score(conn),
            "failed_logins": failed_logins(conn),
            "failed_login_sources": failed_login_sources(conn),
            "service_flaps": service_flaps(conn),
            "errors_by_hour": errors_by_hour(conn),
            "noisiest_processes": noisiest_processes(conn),
            "severity_split": severity_split(conn),
            "event_type_split": event_type_split(conn),
            "recent_security": recent_security_events(conn),
            "memory_events": memory_events(conn),
            "hourly_volume": hourly_volume(conn),
        }
    finally:
        conn.close()


if __name__ == "__main__":
    import json
    data = run_all()
    print(json.dumps({"summary": data["summary"], "noise": data["noise"]}, indent=2))
