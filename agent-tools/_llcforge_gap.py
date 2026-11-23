import json
import pathlib
import re
import urllib.request

ROOT = pathlib.Path(r"c:\Users\plume\Desktop\Kittysploit-framework")
CACHE = pathlib.Path(r"C:\Users\plume\.cursor\projects\c-Users-plume-Desktop-Kittysploit-framework\agent-tools\582f7d5d-8413-4acd-9951-f271f60e2b7c.txt")

existing = set()
for p in ROOT.rglob("*.py"):
    for c in re.findall(r"CVE-\d{4}-\d+", p.read_text(encoding="utf-8", errors="ignore"), re.I):
        existing.add(c.upper())

data = json.loads(CACHE.read_text(encoding="utf-8"))
rows = []
for r in data:
    m = re.search(r"CVE-\d{4}-\d+", r["name"], re.I)
    if not m:
        continue
    cve = m.group().upper()
    if cve in existing:
        continue
    rows.append((cve, r["name"], (r.get("description") or "")[:100]))


def score(item):
    d = (item[2] + " " + item[1]).lower()
    s = 0
    if "nginx" in d and ("uaf" in d or "heap" in d or "work in progress" in d):
        s -= 10
    if "chrome" in d or "hotspot" in d or "ber " in d:
        s -= 10
    if "outlook" in d:
        s -= 5
    for i, w in enumerate(
        [
            "wordpress",
            "unauth",
            "file read",
            "traversal",
            "bypass",
            "rce",
            "rest",
            "api",
            "jwt",
            "tomcat",
            "plugin",
            "admin",
            "sql",
            "upload",
            "etherpad",
            "powerstore",
            "vmware",
        ]
    ):
        if w in d:
            s += 10 - i
    return s


rows.sort(key=score, reverse=True)
for t in rows[:30]:
    print(score(t), t[0], "|", t[2])