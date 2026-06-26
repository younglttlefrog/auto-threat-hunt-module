def select_seeds(events, min_level=12):
    return [e for e in events if int(e.get("level", 0)) >= min_level]
