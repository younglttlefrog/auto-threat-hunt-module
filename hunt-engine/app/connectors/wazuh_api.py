import requests

WAZUH_API = "https://127.0.0.1:55000"
WAZUH_USER = "wazuh-wui"
WAZUH_PASS = "*otu4MkS51DborwlRJi.o9tgJA7fRusR"

def get_token():
    r = requests.get(
        f"{WAZUH_API}/security/user/authenticate?raw=true",
        auth=(WAZUH_USER, WAZUH_PASS),
        verify=False,
        timeout=10,
    )
    r.raise_for_status()
    return r.text.strip()

def list_agents(status=None):
    token = get_token()
    params = {
        "select": "id,name,ip,status,os.name",
        "limit": 10000,
    }
    if status:
        params["status"] = status

    r = requests.get(
        f"{WAZUH_API}/agents",
        headers={"Authorization": f"Bearer {token}"},
        params=params,
        verify=False,
        timeout=10,
    )
    r.raise_for_status()
    data = r.json()

    # Wazuh thường trả về data.affected_items
    items = data.get("data", {}).get("affected_items", [])
    return items

def valid_agent_names(include_manager=True, only_active=False):
    agents = list_agents(status="active" if only_active else None)

    names = set()
    for a in agents:
        name = a.get("name")
        if not name:
            continue
        if not include_manager and a.get("id") == "000":
            continue
        names.add(name)

    return sorted(names)
