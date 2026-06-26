import json
import os
from pathlib import Path
from datetime import datetime, timezone, timedelta

ARCHIVE_FILE = Path(os.getenv("WAZUH_ARCHIVES_JSON", "/var/ossec/logs/archives/archives.json"))


def parse_time(value):
    if not value or value == "now":
        return datetime.now(timezone.utc)

    value = str(value).strip()

    if value.startswith("now-"):
        num = int(value[4:-1])
        unit = value[-1]
        now = datetime.now(timezone.utc)

        if unit == "h":
            return now - timedelta(hours=num)
        if unit == "d":
            return now - timedelta(days=num)
        if unit == "m":
            return now - timedelta(minutes=num)

    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except Exception:
        return None


def event_time(src):
    ts = src.get("@timestamp") or src.get("timestamp")
    return parse_time(ts)


def read_local_archives(time_from="now-120d", time_to="now", limit=10000, agent_names=None):
    if not ARCHIVE_FILE.exists():
        return {"hits": {"hits": []}, "truncated": False, "source": str(ARCHIVE_FILE)}

    start = parse_time(time_from)
    end = parse_time(time_to)

    agent_set = set(agent_names or [])

    hits = []
    truncated = False

    with ARCHIVE_FILE.open("r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()[-limit:]

    for line in lines:
        try:
            src = json.loads(line)
        except Exception:
            continue

        ts = event_time(src)
        if start and ts and ts < start:
            continue
        if end and ts and ts > end:
            continue

        agent = src.get("agent", {}).get("name", "-")
        if agent_set and agent not in agent_set:
            continue

        hits.append({"_source": src})

    if len(hits) >= limit:
        truncated = True

    return {
        "hits": {"hits": hits},
        "truncated": truncated,
        "source": str(ARCHIVE_FILE),
    }
