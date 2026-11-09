#!/usr/bin/env python3
"""Export Cowrie honeypot logs to a public CSV that Mothlight reads.

Runs on the honeypot VM every 5 minutes (cron, as the unprivileged `mothexport` user):
  1. Reads Cowrie's JSON logs (today's file plus rotated ones).
  2. Keeps only attacker activity: login attempts, commands, and file downloads.
  3. Drops anything about our own setup (the VM's IPs, ports, sensor name) and any
     non-public source IP, so Tailscale/admin traffic never shows up.
  4. Force-pushes a single snapshot commit to the data repo with a deploy key that can
     only write to that one repo. The repo keeps one commit, so it never grows.

Standard library only (Python 3.10+). No third-party packages on the honeypot.
"""

import csv
import fcntl
import glob
import hashlib
import io
import ipaddress
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timedelta, timezone

LOG_DIR = "/home/cowrie/cowrie/var/log/cowrie"
HOME = "/var/lib/mothexport"
WORK = os.path.join(HOME, "repo")
DEPLOY_KEY = os.path.join(HOME, "deploy_key")
KNOWN_HOSTS = os.path.join(HOME, "known_hosts")
EXCLUDE_FILE = os.path.join(HOME, "exclude_ips.txt")  # optional: one IP per line (e.g. your home IP)
LAST_HASH = os.path.join(HOME, "last_hash")
REMOTE = "git@github.com:realzephaniahjohnson/mothlight-honeypot-data.git"
AUTHOR = ("Zephaniah Johnson", "311254405+realzephaniahjohnson@users.noreply.github.com")

DAYS = 7               # how far back to export
MAX_ROWS = 50_000      # newest rows kept if there are more
MAX_FIELD = 200        # longest username/password/command kept
COLUMNS = ["timestamp", "src_ip", "event", "username", "password", "command", "session"]
EVENTS = {
    "cowrie.login.failed": "login_failed",
    "cowrie.login.success": "login_success",
    "cowrie.command.input": "command",
    "cowrie.command.failed": "command",
    "cowrie.session.file_download": "download",
}


def clean(value):
    """Plain single-line text, no control characters, length-capped."""
    if value is None:
        return ""
    text = "".join(ch if ch.isprintable() else " " for ch in str(value))
    return " ".join(text.split())[:MAX_FIELD]


def is_public(ip):
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def load_excludes():
    try:
        with open(EXCLUDE_FILE) as f:
            return {line.strip() for line in f if line.strip() and not line.startswith("#")}
    except FileNotFoundError:
        return set()


def read_events():
    cutoff = datetime.now(timezone.utc) - timedelta(days=DAYS)
    excludes = load_excludes()
    rows = []
    files = sorted(glob.glob(os.path.join(LOG_DIR, "cowrie.json*")))
    for path in files:
        try:
            handle = open(path, encoding="utf-8", errors="replace")
        except OSError:
            continue
        with handle:
            for line in handle:
                try:
                    event = json.loads(line)
                except ValueError:
                    continue
                kind = EVENTS.get(event.get("eventid"))
                ip = event.get("src_ip", "")
                if not kind or not is_public(ip) or ip in excludes:
                    continue
                try:
                    when = datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00"))
                except (KeyError, ValueError):
                    continue
                if when < cutoff:
                    continue
                command = event.get("input", "") if kind == "command" else event.get("url", "") if kind == "download" else ""
                rows.append({
                    "timestamp": when.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "src_ip": ip,
                    "event": kind,
                    "username": clean(event.get("username")) if kind.startswith("login") else "",
                    "password": clean(event.get("password")) if kind.startswith("login") else "",
                    "command": clean(command),
                    "session": clean(event.get("session"))[:12],
                })
    rows.sort(key=lambda r: r["timestamp"])
    return rows[-MAX_ROWS:]


def to_csv(rows):
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=COLUMNS, lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    return buffer.getvalue()


def readme(rows, generated):
    ips = len({r["src_ip"] for r in rows})
    logins = sum(r["event"].startswith("login") for r in rows)
    return f"""# Mothlight honeypot data

Live SSH attack data from the [Mothlight](https://github.com/realzephaniahjohnson/mothlight) Cowrie honeypot
(Oracle Cloud, Montreal). Updated every 5 minutes. Shown live at https://mothlight.streamlit.app.

**Last update:** {generated} · **{len(rows):,} events** from **{ips:,} attacker IPs** · {logins:,} login attempts
(last {DAYS} days, newest {MAX_ROWS:,} events at most)

`honeypot.csv` columns: {", ".join(f"`{c}`" for c in COLUMNS)}

`event` is one of `login_failed`, `login_success`, `command`, or `download` (`command` holds the URL).
Every row is an attack against a fake SSH server. The usernames and passwords are ones that attackers
tried, not real credentials. Our own IPs, ports, and private traffic are removed before publishing.
"""


def git(*args, cwd=WORK):
    env = dict(os.environ,
               GIT_AUTHOR_NAME=AUTHOR[0], GIT_AUTHOR_EMAIL=AUTHOR[1],
               GIT_COMMITTER_NAME=AUTHOR[0], GIT_COMMITTER_EMAIL=AUTHOR[1],
               GIT_SSH_COMMAND=(f"ssh -i {DEPLOY_KEY} -o IdentitiesOnly=yes -o BatchMode=yes "
                                f"-o UserKnownHostsFile={KNOWN_HOSTS} -o StrictHostKeyChecking=yes"))
    subprocess.run(["git", *args], cwd=cwd, env=env, check=True, capture_output=True, timeout=120)


def main():
    with open(os.path.join(HOME, "export.lock"), "w") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return  # previous run still going
        rows = read_events()
        data = to_csv(rows)
        digest = hashlib.sha256(data.encode()).hexdigest()
        try:
            with open(LAST_HASH) as f:
                if f.read().strip() == digest:
                    return  # nothing new
        except FileNotFoundError:
            pass
        generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        shutil.rmtree(WORK, ignore_errors=True)
        os.makedirs(WORK)
        with open(os.path.join(WORK, "honeypot.csv"), "w") as f:
            f.write(data)
        with open(os.path.join(WORK, "README.md"), "w") as f:
            f.write(readme(rows, generated))
        git("init", "-q", "-b", "main")
        git("add", "honeypot.csv", "README.md")
        git("commit", "-q", "-m", f"Honeypot snapshot {generated}")
        git("push", "-q", "--force", REMOTE, "main")
        with open(LAST_HASH, "w") as f:
            f.write(digest)
        print(f"{generated}: pushed {len(rows):,} events")


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as error:
        print(f"git failed: {error.stderr.decode(errors='replace')[-500:]}", file=sys.stderr)
        sys.exit(1)
