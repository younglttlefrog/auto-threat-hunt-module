import requests

WAZUH_URL = "https://127.0.0.1:55000"
USERNAME = "wazuh-wui"
PASSWORD = "PASSWORD"

def get_token():
    r = requests.get(
        f"{WAZUH_URL}/security/user/authenticate?raw=true",
        auth=(USERNAME, PASSWORD),
        verify=False,
    )
    return r.text

def headers():
    token = get_token()
    return {"Authorization": f"Bearer {token}"}
