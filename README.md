# Auto Threat Hunt Platform

## Components

### hunt-engine

Python backend.

Responsibilities:

* OpenSearch query
* Wazuh API integration
* Threat hunting
* MITRE correlation
* Campaign clustering
* IOC extraction
* Report generation

API default:

http://localhost:8089

---

### auto_threat_hunt_plugin

OpenSearch Dashboards plugin source.

Responsibilities:

* UI
* ATT&CK visualization
* Campaign browser
* IOC browser
* Timeline viewer
* Report history

---

### dist

Built plugin package.

Install:

sudo /usr/share/wazuh-dashboard/bin/opensearch-dashboards-plugin install file:///path/to/autoThreatHunt-2.19.4.zip --allow-root

---

## Backend startup

python3 -m venv venv

source venv/bin/activate

pip install -r requirements.txt

uvicorn api:app --host 0.0.0.0 --port 8089

---

## Frontend source

OpenSearch-Dashboards/plugins/auto_threat_hunt

Build:

node ../../scripts/plugin_helpers.js build
