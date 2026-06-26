import json
import os
import subprocess
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, PlainTextResponse
from pydantic import BaseModel

app = FastAPI(title="Auto Threat Hunt API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

HUNT_ENGINE_DIR = Path("/home/frog/hunt-engine")
OUTPUT_FILE = HUNT_ENGINE_DIR / "output/latest_hunt.json"
REPORT_DIR = HUNT_ENGINE_DIR / "reports"
PYTHON_BIN = HUNT_ENGINE_DIR / "venv/bin/python"


class HuntRequest(BaseModel):
    hunt_name: str = "Threat Hunt"
    format: str = "md"
    time_from: str = "now-24h"
    time_to: str = "now"
    min_level: int = 12
    seed_size: int = 30
    pivot_minutes: int = 30


def safe_report_path(filename: str) -> Path:
    if not filename or filename == "undefined":
        raise HTTPException(status_code=400, detail="Missing filename")
    if "/" in filename or "\\" in filename or ".." in filename:
        raise HTTPException(status_code=400, detail="Invalid filename")

    file_path = REPORT_DIR / filename
    if not file_path.exists():
        raise HTTPException(status_code=404, detail=f"Report not found: {filename}")

    return file_path


def load_latest_data():
    if not OUTPUT_FILE.exists():
        return {}

    return json.loads(OUTPUT_FILE.read_text(encoding="utf-8"))



def load_report_data(filename: str):
    stem = Path(filename).stem
    candidate = HUNT_ENGINE_DIR / "output" / f"{stem}.json"

    if candidate.exists():
        return json.loads(candidate.read_text(encoding="utf-8"))

    return load_latest_data()

def make_report_view(filename: str):
    data = load_report_data(filename)
    overview = data.get("overview", {})
    campaigns = data.get("campaigns", [])
    iocs = data.get("iocs", {})
    attack_chain = data.get("attack_chain", [])
    recommendations = data.get("recommendations", [])

    high_campaigns = [c for c in campaigns if int(c.get("risk_score", 0) or 0) >= 80]

    return {
        "filename": filename,
        "generated_at": data.get("generated_at", "-"),
        "hunt_name": data.get("hunt_name", filename),
        "report_file": data.get("report_file", filename),
        "executive_summary": {
            "total_events": overview.get("total_events", 0),
            "seed_alerts": overview.get("seeds", 0),
            "timeline_events": overview.get("timeline_events", 0),
            "campaigns": overview.get("campaigns", 0),
            "high_risk_campaigns": overview.get("high_risk", len(high_campaigns)),
            "mitre_techniques": overview.get("mitre_techniques", 0),
            "chain_confidence": overview.get("chain_confidence", 0),
            "valid_agents": data.get("valid_agents", []),
        },
        "key_findings": [
            f"Detected {overview.get('campaigns', 0)} campaign clusters from Wazuh alerts.",
            f"Identified {overview.get('high_risk', len(high_campaigns))} high-risk campaigns.",
            f"Observed {overview.get('mitre_techniques', 0)} MITRE ATT&CK techniques.",
            "Results were filtered using the real Wazuh agent inventory.",
        ],
        "top_campaigns": campaigns[:10],
        "attack_chain": attack_chain[:30],
        "ioc_summary": {
            "ips": [x for x in iocs.get("ips", []) if x and x != "-"][:30],
            "urls": [x for x in iocs.get("urls", []) if x and x != "-"][:30],
            "files": [x for x in iocs.get("files", []) if x and x != "-"][:30],
            "users": [x for x in iocs.get("users", []) if x and x != "-"][:30],
            "hosts": [x for x in iocs.get("hosts", []) if x and x != "-"][:30],
        },
        "recommendations": recommendations[:10],
    }


@app.get("/api/health")
def health():
    return {"status": "ok"}


@app.get("/api/hunt/latest")
def latest_hunt():
    if not OUTPUT_FILE.exists():
        raise HTTPException(status_code=404, detail="latest_hunt.json not found")
    return load_latest_data()


@app.post("/api/hunt/run")
def run_hunt_now(req: HuntRequest):
    env = os.environ.copy()
    env["HUNT_NAME"] = req.hunt_name
    env["REPORT_FORMAT"] = req.format
    env["TIME_FROM"] = req.time_from
    env["TIME_TO"] = req.time_to
    env["MIN_LEVEL"] = str(req.min_level)
    env["SEED_SIZE"] = str(req.seed_size)
    env["PIVOT_MINUTES"] = str(req.pivot_minutes)

    result = subprocess.run(
        [str(PYTHON_BIN), "run_hunt.py"],
        cwd=str(HUNT_ENGINE_DIR),
        capture_output=True,
        text=True,
        timeout=300,
        env=env,
    )

    if result.returncode != 0:
        raise HTTPException(status_code=500, detail=result.stderr)

    return {
        "status": "ok",
        "message": "Hunt completed",
        "hunt_name": req.hunt_name,
        "format": req.format,
        "time_from": req.time_from,
        "time_to": req.time_to,
        "min_level": req.min_level,
        "seed_size": req.seed_size,
        "pivot_minutes": req.pivot_minutes,
        "stdout": result.stdout,
    }


@app.post("/api/hunt/report/executive")
def generate_executive_report(req: HuntRequest):
    env = os.environ.copy()
    env["HUNT_NAME"] = req.hunt_name
    env["REPORT_FORMAT"] = req.format
    env["TIME_FROM"] = req.time_from
    env["TIME_TO"] = req.time_to
    env["MIN_LEVEL"] = str(req.min_level)
    env["SEED_SIZE"] = str(req.seed_size)
    env["PIVOT_MINUTES"] = str(req.pivot_minutes)

    # Generate fresh hunt first so executive report matches selected range
    hunt_result = subprocess.run(
        [str(PYTHON_BIN), "run_hunt.py"],
        cwd=str(HUNT_ENGINE_DIR),
        capture_output=True,
        text=True,
        timeout=300,
        env=env,
    )

    if hunt_result.returncode != 0:
        raise HTTPException(status_code=500, detail=hunt_result.stderr)

    result = subprocess.run(
        [str(PYTHON_BIN), "summarize_hunt.py"],
        cwd=str(HUNT_ENGINE_DIR),
        capture_output=True,
        text=True,
        timeout=120,
        env=env,
    )

    if result.returncode != 0:
        raise HTTPException(status_code=500, detail=result.stderr)

    return {
        "status": "ok",
        "message": "Executive report generated",
        "stdout": result.stdout,
    }


@app.get("/api/hunt/reports")
def list_hunt_reports():
    REPORT_DIR.mkdir(exist_ok=True)

    files = sorted(
        list(REPORT_DIR.glob("*.md")) + list(REPORT_DIR.glob("*.pdf")),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )

    return [
        {
            "filename": f.name,
            "type": "executive" if f.name.startswith("executive_") else "technical",
            "extension": f.suffix.replace(".", ""),
            "size": f.stat().st_size,
            "modified": f.stat().st_mtime,
        }
        for f in files[:100]
    ]


@app.get("/api/hunt/report")
def read_report(filename: str = Query(...)):
    file_path = safe_report_path(filename)

    return {
        "filename": filename,
        "type": "pdf" if file_path.suffix == ".pdf" else "md",
        "view": make_report_view(filename),
        "download_url": f"/api/hunt/report/download?filename={filename}",
    }


@app.get("/api/hunt/report/raw", response_class=PlainTextResponse)
def read_report_raw(filename: str = Query(...)):
    file_path = safe_report_path(filename)
    if file_path.suffix == ".pdf":
        raise HTTPException(status_code=400, detail="PDF cannot be returned as text")
    return file_path.read_text(encoding="utf-8", errors="ignore")


@app.get("/api/hunt/report/download")
def download_report(filename: str = Query(...)):
    file_path = safe_report_path(filename)
    media_type = "application/pdf" if file_path.suffix == ".pdf" else "text/markdown"

    return FileResponse(
        path=str(file_path),
        filename=file_path.name,
        media_type=media_type,
    )
