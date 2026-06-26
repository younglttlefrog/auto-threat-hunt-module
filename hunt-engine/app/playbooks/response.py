import json
from pathlib import Path

RESPONSE_PATH = Path("playbooks/generated/response_actions.json")

FALLBACK_ACTIONS = {
    "T1059.001": {
        "technique_id": "T1059.001",
        "name": "PowerShell",
        "priority": "high",
        "log_sources": [
            "PowerShell Operational Log",
            "Sysmon Process Creation",
            "Windows Security Events"
        ],
        "key_indicators": [
            "Encoded PowerShell command",
            "PowerShell downloading content from the internet",
            "PowerShell spawned by unusual parent process"
        ],
        "questions": [
            "Was this PowerShell activity expected for the user or host?",
            "Was the command executed by a privileged account?",
            "Did the command download or execute remote content?"
        ],
        "escalate_if": [
            "Encoded command observed",
            "External download observed",
            "Suspicious parent process observed"
        ],
        "recommended_actions": [
            {
                "priority": "high",
                "stage": "triage",
                "action": "Review PowerShell command line and parent process",
                "reason": "PowerShell execution was observed and may indicate script-based execution",
                "safe_mode": "manual_review",
                "commands": [
                    "Get-WinEvent -LogName Microsoft-Windows-PowerShell/Operational",
                    "Get-Process powershell"
                ]
            }
        ]
    },
    "T1547.001": {
        "technique_id": "T1547.001",
        "name": "Registry Run Keys / Startup Folder",
        "priority": "high",
        "log_sources": [
            "Sysmon Registry Events",
            "Windows Security Events"
        ],
        "key_indicators": [
            "New Run key value",
            "Suspicious executable path in startup registry"
        ],
        "questions": [
            "Is the registry value expected?",
            "Does the referenced binary exist in a suspicious path?"
        ],
        "escalate_if": [
            "Unknown binary configured for startup",
            "Persistence survives reboot"
        ],
        "recommended_actions": [
            {
                "priority": "high",
                "stage": "triage",
                "action": "Verify registry Run key modification on the affected host",
                "reason": "T1547.001 indicates possible persistence via Registry Run Keys",
                "safe_mode": "manual_review",
                "commands": [
                    "reg query HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                    "reg query HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
                ]
            }
        ]
    },
    "T1053.005": {
        "technique_id": "T1053.005",
        "name": "Scheduled Task",
        "priority": "medium",
        "log_sources": [
            "Windows Task Scheduler Operational Log",
            "Sysmon Process Creation"
        ],
        "key_indicators": [
            "Unexpected scheduled task creation",
            "Scheduled task launching script interpreter"
        ],
        "questions": [
            "Who created the scheduled task?",
            "What binary or script does the task execute?"
        ],
        "escalate_if": [
            "Task runs from user-writable directory",
            "Task launches PowerShell/cmd with suspicious arguments"
        ],
        "recommended_actions": [
            {
                "priority": "medium",
                "stage": "triage",
                "action": "Review recently created scheduled tasks",
                "reason": "Scheduled task activity may indicate execution or persistence",
                "safe_mode": "manual_review",
                "commands": [
                    "schtasks /query /fo LIST /v"
                ]
            }
        ]
    },
    "T1036": {
        "technique_id": "T1036",
        "name": "Masquerading",
        "priority": "medium",
        "log_sources": [
            "Sysmon Process Creation",
            "File Integrity Monitoring"
        ],
        "key_indicators": [
            "Process name resembles legitimate binary",
            "Executable path is unusual for the claimed process"
        ],
        "questions": [
            "Is the executable path expected?",
            "Does the file signature match the claimed vendor?"
        ],
        "escalate_if": [
            "Unsigned binary masquerading as system process",
            "Binary located in user-writable directory"
        ],
        "recommended_actions": [
            {
                "priority": "medium",
                "stage": "investigation",
                "action": "Verify process path, signature, and hash reputation",
                "reason": "Masquerading may hide malicious execution under a legitimate-looking name",
                "safe_mode": "manual_review",
                "commands": [
                    "Get-AuthenticodeSignature <path>",
                    "Get-FileHash <path>"
                ]
            }
        ]
    },
    "T1110": {
        "technique_id": "T1110",
        "name": "Brute Force",
        "priority": "medium",
        "log_sources": [
            "Authentication Logs",
            "Windows Security Events",
            "SSH logs"
        ],
        "key_indicators": [
            "Multiple failed logins",
            "Failed logins followed by success"
        ],
        "questions": [
            "Was the successful login expected?",
            "Did failures originate from a single source?"
        ],
        "escalate_if": [
            "Successful login after repeated failures",
            "Privileged account targeted"
        ],
        "recommended_actions": [
            {
                "priority": "medium",
                "stage": "triage",
                "action": "Review failed and successful authentication events for the user and source",
                "reason": "Brute force activity may indicate account compromise attempts",
                "safe_mode": "manual_review",
                "commands": [
                    "Get-WinEvent -LogName Security"
                ]
            }
        ]
    },
    "T1078": {
        "technique_id": "T1078",
        "name": "Valid Accounts",
        "priority": "high",
        "log_sources": [
            "Authentication Logs",
            "EDR",
            "VPN logs"
        ],
        "key_indicators": [
            "Unusual login time",
            "Login from unusual source",
            "Privilege use after login"
        ],
        "questions": [
            "Is the login consistent with the user's baseline?",
            "Was MFA used?",
            "Was the account recently modified?"
        ],
        "escalate_if": [
            "Privileged account used from unusual source",
            "Successful login after suspicious failures"
        ],
        "recommended_actions": [
            {
                "priority": "high",
                "stage": "triage",
                "action": "Validate account legitimacy and recent authentication activity",
                "reason": "Valid account use can indicate compromised credentials",
                "safe_mode": "manual_review",
                "commands": [
                    "net user <username> /domain"
                ]
            }
        ]
    }
}

def load_response_playbooks():
    data = {}
    if RESPONSE_PATH.exists():
        try:
            data = json.loads(RESPONSE_PATH.read_text(encoding="utf-8"))
        except Exception:
            data = {}

    merged = dict(FALLBACK_ACTIONS)
    merged.update(data)
    return merged

def get_recommended_actions_for_techniques(techniques, max_actions=10):
    playbooks = load_response_playbooks()
    actions = []

    for tid in techniques:
        pb = playbooks.get(tid)
        if not pb:
            continue

        actions.append({
            "technique_id": tid,
            "technique_name": pb.get("name", tid),
            "priority": pb.get("priority", "medium"),
            "log_sources": pb.get("log_sources", []),
            "key_indicators": pb.get("key_indicators", []),
            "questions": pb.get("questions", []),
            "escalate_if": pb.get("escalate_if", []),
            "recommended_actions": pb.get("recommended_actions", []),
            "source": pb.get("source", "local_fallback"),
        })

    priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    actions = sorted(actions, key=lambda x: priority_order.get(x.get("priority", "medium"), 2))

    return actions[:max_actions]
