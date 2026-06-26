def classify(seed):

    rule = str(seed["rule_id"])
    desc = seed["description"].lower()

    if "shellshock" in desc:
        return "Web Exploitation"

    if "sqlmap" in desc:
        return "SQL Injection"

    if "lsass" in desc:
        return "Credential Dumping"

    if "registry" in desc:
        return "Persistence"

    if "scheduled task" in desc:
        return "Persistence"

    return "Other"
