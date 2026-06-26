from datetime import datetime, timedelta

def get_window(ts, minutes=30):

    ts = ts.replace("Z", "+00:00")

    dt = datetime.fromisoformat(ts)

    start = dt - timedelta(minutes=minutes)
    end = dt + timedelta(minutes=minutes)

    return start.isoformat(), end.isoformat()
