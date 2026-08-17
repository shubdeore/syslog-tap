#!/usr/bin/env bash
#
# install-cron.sh
#
# Adds an hourly cron entry that runs run.py on its own. Safe to run more
# than once — it checks for an existing entry first instead of duplicating it.
#
#   chmod +x install-cron.sh
#   ./install-cron.sh
#
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PY="$(command -v python3)"
ENTRYPOINT="$DIR/run.py"
CRONLOG="$DIR/logs/cron.log"

mkdir -p "$DIR/logs"

JOB="0 * * * * cd $DIR && $PY $ENTRYPOINT --quiet >> $CRONLOG 2>&1"

if crontab -l 2>/dev/null | grep -qF "$ENTRYPOINT"; then
    echo "already installed:"
    crontab -l | grep -F "$ENTRYPOINT"
    exit 0
fi

(crontab -l 2>/dev/null; echo "$JOB") | crontab -

echo "installed. syslog-tap will now run every hour."
echo "output goes to: $CRONLOG"
echo ""
echo "check it:  crontab -l"
echo "remove it: crontab -e   (then delete the line)"
