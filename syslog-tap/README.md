# syslog-tap

A small tool that parses Linux syslog files into DuckDB and gives you back
an hourly HTML report instead of a wall of text. Built it because I kept
manually `grep`-ing `/var/log/auth.log` after noticing SSH login attempts,
and wanted that check running on its own instead of relying on remembering
to do it.

It's not trying to be a SIEM. It's `tail -f` with a memory and some SQL.

```
/var/log/syslog, auth.log, messages, secure
                 │
                 ▼
    tap.py       parses each line, tags it (severity + event type),
                 loads it into a local DuckDB file
                 │
                 ▼
    analyze.py   runs the SQL — failed logins, service flaps, error
                 spikes by hour, a noise score for the latest hour
                 │
                 ▼
    report.py    renders one HTML file, no external assets
                 │
                 ▼
    cron         does the above on its own, hourly
```

Run `python run.py` and you'll have a report in `reports/latest.html`
plus a short summary printed straight to your terminal.

---

## The noise score thing

Most of this project is what you'd expect — parse a line, `GROUP BY`,
put it in a table. One part isn't: instead of a fixed "more than N errors
in an hour = alert," `analyze.py` compares the latest hour's event volume
against a rolling baseline built from the hours before it (mean + stdev,
basic z-score).

The reason is that "normal" log volume is different on every machine.
A box that quietly logs 40 events an hour going to 200 is a much bigger
signal than a box that already logs 5,000 an hour going to 5,200 — a fixed
threshold treats those the same, a baseline comparison doesn't. It's not
fancy statistics, just enough to stop me from hardcoding a number that
would've been wrong for half the machines I'd run this on.

If there isn't enough history yet (fresh database, first run) it says so
instead of pretending to have an answer.

---

## Why DuckDB instead of SQLite

The queries this runs are almost all `GROUP BY ... date_trunc(...)` —
aggregating across potentially hundreds of thousands of rows. SQLite is
row-oriented and does fine with lots of small point lookups, but it's not
built for that kind of scan-and-aggregate workload. DuckDB is columnar
and vectorized specifically for this pattern, and on a log file with
500K+ lines the aggregation queries here run in milliseconds instead of
seconds.

It's also just a file on disk — no server process, no setup beyond
`pip install duckdb`. For a project this size that's exactly the right
amount of infrastructure and not a line more.

---

## Running it

Needs Python 3.10+.

```bash
git clone https://github.com/yourusername/syslog-tap.git
cd syslog-tap

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

```bash
python run.py
```

It auto-detects log paths based on what actually exists on your system.
If none of the defaults apply, point it somewhere yourself:

```bash
python run.py --logs /var/log/syslog /var/log/auth.log
```

Open `reports/latest.html` when it's done, or just read the terminal
summary it prints — for a quick check that's usually enough.

To have it run on its own every hour:

```bash
chmod +x install-cron.sh
./install-cron.sh
```

That adds one line to your crontab. Nothing else changes on your system.

---

## What actually ends up in the report

- **Overview** — total events, error/warning/security counts, time window covered
- **Noise score** — is the latest hour normal, quiet, or louder than usual
- **Severity split** — how much of the volume is real signal vs. INFO noise
- **Failed logins** — who's trying to get in and failing, and which process is catching it
- **Service flaps** — anything that started, stopped, restarted, or failed to start
- **Worst hours** — sorted by error count, so you know where to look first
- **Loudest processes** — the usual suspects, ranked
- **Memory events** — OOM kills, if you've had any
- **48-hour volume trend** — total activity over time

---

## A few things worth knowing before you dig in

**Re-running it is safe.** Every line gets hashed on `(source_file, raw_line)`
before insert, so running `run.py` five times against the same log file
inserts the data once, not five times. Matters a lot once cron is calling
this unattended every hour.

**One real dependency.** `duckdb` is the only thing in `requirements.txt`.
The HTML is built with plain f-strings — no Jinja2, no Flask. Fewer moving
parts, and it runs anywhere Python 3.10+ does.

**Plain regex, on purpose.** RFC 3164 syslog lines are simple and stable
enough that one regex handles them reliably. Didn't reach for a heavier
parsing library because there wasn't an actual problem it would've solved.

**It only knows what you feed it.** No log shipping, no remote collection,
no multi-host anything — it reads local files on the machine it runs on.
If you need centralized log aggregation across a fleet, this isn't that;
it's meant for exactly one box.

---

## Layout

```
syslog-tap/
├── run.py            entry point — parse + report + terminal summary
├── tap.py            syslog lines → structured rows → DuckDB
├── analyze.py        every query the report uses, incl. noise_score()
├── report.py         builds the HTML
├── install-cron.sh   sets up the hourly cron job
├── requirements.txt
├── db/                (gitignored) the DuckDB file lives here
├── reports/           (gitignored) generated HTML reports
└── logs/              (gitignored) cron's own output
```

---

## Log paths by distro, for reference

| Distro | Checked automatically |
|---|---|
| Ubuntu / Debian | `/var/log/syslog`, `/var/log/auth.log` |
| RHEL / CentOS / Fedora | `/var/log/messages`, `/var/log/secure` |
| Arch | `/var/log/syslog` (needs rsyslog or syslog-ng running) |

Whichever of these exist on disk get used automatically. `--logs`
overrides all of it if you want to point somewhere else.
