#!/usr/bin/env python3
"""
report.py

Turns whatever analyze.py hands back into one self-contained HTML file.
No templating library — at this size, f-strings are genuinely easier to
follow than a Jinja setup would be, so that's what this uses.
"""

import os
import logging
from datetime import datetime

from analyze import run_all

REPORTS_DIR = os.environ.get("TAP_REPORTS", "reports")

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")
log = logging.getLogger("report")

SEVERITY_COLORS = {"ERROR": "#e53e3e", "WARN": "#d69e2e", "SECURITY": "#805ad5", "INFO": "#38a169"}


def badge(text, color):
    return f'<span style="background:{color};color:#fff;padding:2px 8px;border-radius:4px;font-size:12px;font-weight:600">{text}</span>'


def rows_to_table(headers, rows, cap=None):
    if not rows:
        return '<p class="empty">nothing to show here</p>'
    if cap:
        rows = rows[:cap]
    head = "".join(f"<th>{h}</th>" for h in headers)
    body = ""
    for i, r in enumerate(rows):
        bg = "#f7fafc" if i % 2 == 0 else "#fff"
        cells = "".join(f"<td>{v}</td>" for v in r.values())
        body += f'<tr style="background:{bg}">{cells}</tr>'
    return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"


def stat(label, value, color="#2b6cb0"):
    return f'<div class="stat"><div class="stat-num" style="color:{color}">{value:,}</div><div class="stat-label">{label}</div></div>'


def noise_card(noise: dict) -> str:
    if not noise.get("available"):
        return f'<p class="empty">{noise.get("reason", "not enough data yet")}</p>'

    verdict_colors = {
        "unusually loud": "#e53e3e",
        "a bit louder than usual": "#d69e2e",
        "unusually quiet": "#3182ce",
        "normal range": "#38a169",
    }
    color = verdict_colors.get(noise["verdict"], "#4a5568")
    z_display = noise["z_score"] if noise["z_score"] is not None else "n/a"

    return f"""
    <div class="noise-card">
        <div class="noise-verdict" style="color:{color}">{noise['verdict'].upper()}</div>
        <p>
            The hour ending <strong>{noise['hour']}</strong> logged <strong>{noise['latest_count']}</strong> events,
            against a baseline of <strong>{noise['baseline_mean']}</strong> &plusmn; {noise['baseline_stdev']}
            over the preceding hours &mdash; that's a z-score of <strong>{z_display}</strong>.
        </p>
    </div>
    """


def section(title, html, icon=""):
    return f'<div class="section"><h2>{icon} {title}</h2>{html}</div>'


def build_html(data: dict, generated_at: datetime) -> str:
    s = data["summary"]
    when = generated_at.strftime("%Y-%m-%d %H:%M:%S")
    trouble = s["errors"] > 0 or s["security"] > 0
    status_color = "#e53e3e" if trouble else "#38a169"
    status_text = "ISSUES DETECTED" if trouble else "ALL CLEAR"

    stats_html = f"""
    <div class="stats-grid">
        {stat("Total events", s["total"], "#2b6cb0")}
        {stat("Errors", s["errors"], "#e53e3e" if s["errors"] else "#38a169")}
        {stat("Warnings", s["warnings"], "#d69e2e" if s["warnings"] else "#38a169")}
        {stat("Security", s["security"], "#805ad5" if s["security"] else "#38a169")}
        {stat("Processes seen", s["processes"], "#4a5568")}
        {stat("Hosts", s["hosts"], "#4a5568")}
    </div>
    <p class="window">window: <strong>{s['earliest']}</strong> &rarr; <strong>{s['latest']}</strong></p>
    """

    severity_html = rows_to_table(["Severity", "Count", "Share"], [
        {"Severity": badge(r["severity"], SEVERITY_COLORS.get(r["severity"], "#718096")),
         "Count": f"{r['count']:,}", "Share": f"{r['pct']}%"}
        for r in data["severity_split"]
    ])

    event_html = rows_to_table(["Event type", "Count"], [
        {"Event type": r["event_type"], "Count": f"{r['count']:,}"} for r in data["event_type_split"]
    ])

    logins_html = rows_to_table(["Time", "Host", "Process", "Message"], [
        {"Time": r["ts"], "Host": r["host"], "Process": r["process"], "Message": r["message"][:80]}
        for r in data["failed_logins"]
    ], cap=15)

    login_sources_html = rows_to_table(["Process", "Attempts", "First seen", "Last seen"], [
        {"Process": r["process"], "Attempts": r["attempts"], "First seen": r["first"], "Last seen": r["last"]}
        for r in data["failed_login_sources"]
    ])

    flaps_html = rows_to_table(["Time", "Host", "Process", "Message"], [
        {"Time": r["ts"], "Host": r["host"], "Process": r["process"], "Message": r["message"][:80]}
        for r in data["service_flaps"]
    ], cap=15)

    hour_html = rows_to_table(["Hour", "Errors"], [
        {"Hour": r["hour"], "Errors": r["count"]} for r in data["errors_by_hour"]
    ])

    noisy_html = rows_to_table(["Process", "Errors"], [
        {"Process": r["process"], "Errors": r["errors"]} for r in data["noisiest_processes"]
    ])

    security_html = rows_to_table(["Time", "Host", "Process", "Message"], [
        {"Time": r["ts"], "Host": r["host"], "Process": r["process"], "Message": r["message"][:80]}
        for r in data["recent_security"]
    ])

    memory_html = rows_to_table(["Time", "Host", "Process", "Message"], [
        {"Time": r["ts"], "Host": r["host"], "Process": r["process"], "Message": r["message"][:80]}
        for r in data["memory_events"]
    ])

    volume_html = rows_to_table(["Hour", "Total", "Errors", "Security"], [
        {"Hour": r["hour"], "Total": r["total"], "Errors": r["errors"], "Security": r["security"]}
        for r in data["hourly_volume"]
    ])

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>syslog-tap report — {when}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f0f4f8; color: #2d3748; line-height: 1.6; }}
  header {{ background: #1a202c; color: #fff; padding: 22px 36px; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 12px; }}
  header h1 {{ font-size: 20px; font-weight: 700; font-family: 'SF Mono', Monaco, monospace; }}
  header .meta {{ font-size: 13px; color: #a0aec0; margin-top: 2px; }}
  .status {{ background: {status_color}; color: #fff; padding: 6px 16px; border-radius: 20px; font-size: 12px; font-weight: 700; letter-spacing: 1px; }}
  .container {{ max-width: 1150px; margin: 0 auto; padding: 28px 20px; }}
  .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 14px; }}
  .stat {{ background: #fff; border-radius: 10px; padding: 18px; text-align: center; border: 1px solid #e2e8f0; }}
  .stat-num {{ font-size: 28px; font-weight: 800; }}
  .stat-label {{ font-size: 11px; color: #718096; margin-top: 4px; text-transform: uppercase; letter-spacing: 0.5px; }}
  .window {{ color: #718096; font-size: 13px; margin-top: 10px; }}
  .noise-card {{ background: #fff; border-radius: 10px; padding: 20px; border: 1px solid #e2e8f0; }}
  .noise-verdict {{ font-size: 18px; font-weight: 800; letter-spacing: 0.5px; margin-bottom: 8px; }}
  .noise-card p {{ font-size: 13px; color: #4a5568; }}
  .section {{ background: #fff; border-radius: 10px; padding: 22px; margin-top: 22px; border: 1px solid #e2e8f0; }}
  .section h2 {{ font-size: 15px; font-weight: 700; margin-bottom: 14px; padding-bottom: 8px; border-bottom: 2px solid #e2e8f0; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  th {{ background: #2d3748; color: #e2e8f0; padding: 9px 11px; text-align: left; font-size: 11px; text-transform: uppercase; letter-spacing: 0.4px; }}
  td {{ padding: 8px 11px; border-bottom: 1px solid #edf2f7; word-break: break-word; }}
  .empty {{ color: #a0aec0; font-style: italic; font-size: 13px; }}
  .two-col {{ display: grid; grid-template-columns: 1fr 1fr; gap: 22px; margin-top: 22px; }}
  footer {{ text-align: center; padding: 24px; color: #a0aec0; font-size: 12px; }}
  @media (max-width: 760px) {{ .two-col {{ grid-template-columns: 1fr; }} }}
</style>
</head>
<body>
<header>
  <div><h1>syslog-tap</h1><div class="meta">generated {when}</div></div>
  <div class="status">{status_text}</div>
</header>

<div class="container">
  {section("overview", stats_html, "")}
  {section("noise score", noise_card(data["noise"]), "")}

  <div class="two-col">
    <div>{section("severity split", severity_html)}</div>
    <div>{section("event types", event_html)}</div>
  </div>

  {section("failed logins", logins_html)}
  {section("failed logins, grouped", login_sources_html)}
  {section("recent security events", security_html)}
  {section("service starts / stops / restarts", flaps_html)}

  <div class="two-col">
    <div>{section("worst hours (by error count)", hour_html)}</div>
    <div>{section("loudest processes", noisy_html)}</div>
  </div>

  {section("memory pressure / OOM", memory_html)}
  {section("hourly volume, last 48h", volume_html)}
</div>

<footer>syslog-tap &middot; {when}</footer>
</body>
</html>"""


def run() -> str:
    now = datetime.now()
    log.info("pulling analysis...")
    data = run_all()

    log.info("rendering report...")
    html = build_html(data, now)

    os.makedirs(REPORTS_DIR, exist_ok=True)
    stamped = os.path.join(REPORTS_DIR, f"report_{now.strftime('%Y%m%d_%H%M%S')}.html")
    latest = os.path.join(REPORTS_DIR, "latest.html")

    for path in (stamped, latest):
        with open(path, "w") as f:
            f.write(html)

    log.info("wrote %s", stamped)
    return stamped


if __name__ == "__main__":
    run()
