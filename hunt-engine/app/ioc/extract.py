import re
from urllib.parse import urlparse

PLACEHOLDERS = {"", "-", "unknown", "none", "null", "n/a"}

IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.I)
DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")
LINUX_PATH_RE = re.compile(r"(?<!\w)/(?:[\w.\-]+/)*[\w.\-]+")
WIN_PATH_RE = re.compile(r"\b[A-Za-z]:\\(?:[^\\/:*?\"<>|\r\n]+\\)*[^\\/:*?\"<>|\r\n]*")


def valid(v):
    return v is not None and str(v).strip().lower() not in PLACEHOLDERS


def add(s, v):
    if valid(v):
        s.add(str(v).strip())


def extract_iocs(events):
    ips = set()
    urls = set()
    domains = set()
    files = set()
    users = set()
    hosts = set()

    for e in events:
        raw = e.get("raw", {}) or {}
        data = raw.get("data", {}) or {}
        full_log = e.get("full_log", "") or ""

        add(hosts, e.get("agent"))

        for key in ["srcip", "dstip", "src_ip", "dst_ip"]:
            add(ips, data.get(key))
        add(ips, e.get("srcip"))

        for key in ["srcuser", "dstuser", "user", "username"]:
            add(users, data.get(key))

        win = data.get("win", {}).get("eventdata", {}) if isinstance(data.get("win"), dict) else {}
        for key in ["targetUserName", "subjectUserName", "user"]:
            add(users, win.get(key))

        for key in ["url", "uri", "request", "http_url"]:
            add(urls, data.get(key))
        add(urls, e.get("url"))

        for key in ["file", "file_path", "path", "targetFilename", "image", "processPath"]:
            add(files, data.get(key))
            add(files, win.get(key))

        for ip in IP_RE.findall(full_log):
            add(ips, ip)

        for url in URL_RE.findall(full_log):
            add(urls, url)
            try:
                netloc = urlparse(url).netloc
                add(domains, netloc.split(":")[0])
            except Exception:
                pass

        for dom in DOMAIN_RE.findall(full_log):
            if not IP_RE.fullmatch(dom):
                add(domains, dom)

        for path in LINUX_PATH_RE.findall(full_log):
            if len(path) > 3:
                add(files, path)

        for path in WIN_PATH_RE.findall(full_log):
            add(files, path)

    return {
        "ips": sorted(ips),
        "urls": sorted(urls),
        "domains": sorted(domains),
        "files": sorted(files),
        "users": sorted(users),
        "hosts": sorted(hosts),
    }
