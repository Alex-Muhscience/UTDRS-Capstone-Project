#!/usr/bin/env python3
"""
Fill a running UTDRS stack with demo data, through the API gateway only.

Creates an analyst account, assets, detection rules, a simulation, and a day of
security events. The events go through the core engine like any other, so the
alerts you see are the engine's real verdicts, not inserted rows. Some alerts are
then moved through triage so every status is represented.

    python3 scripts/seed-demo.py [--gateway http://localhost:8000] [--username demo]

The password is taken from DEMO_PASSWORD, or generated and printed. Standard
library only, so it runs with any Python 3.9+.
"""
import argparse
import json
import os
import random
import secrets
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone


class Gateway:
    def __init__(self, base_url):
        self.base = base_url.rstrip("/") + "/api/v1"
        self.token = None

    def request(self, method, path, body=None, form=None, params=None):
        url = self.base + path
        if params:
            url += "?" + urllib.parse.urlencode(params)
        headers = {}
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        if form is not None:
            data = urllib.parse.urlencode(form).encode()
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        request = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=15) as response:
                return json.loads(response.read() or b"null")
        except urllib.error.HTTPError as error:
            raise SystemExit(f"{method} {path} failed: {error.code} {error.read().decode()[:300]}")

    def sign_in(self, username, password):
        try:
            self.request("POST", "/auth/register", body={
                "username": username, "email": f"{username}@example.com", "password": password,
                "firstName": "Demo", "lastName": "Analyst",
            })
        except SystemExit:
            pass  # Already registered: sign in with the given password.
        self.token = self.request("POST", "/auth/login", form={"username": username, "password": password})["access_token"]


ASSETS = [
    {"name": "web-01", "asset_type": "server", "ip_address": "10.0.10.11", "os": "Ubuntu 24.04", "criticality": "high", "department": "Engineering", "owner": "Platform team"},
    {"name": "db-01", "asset_type": "server", "ip_address": "10.0.10.21", "os": "Debian 12", "criticality": "critical", "department": "Engineering", "owner": "Platform team"},
    {"name": "fin-laptop-07", "asset_type": "laptop", "ip_address": "10.0.40.57", "os": "Windows 11", "criticality": "high", "department": "Finance", "owner": "J. Smith"},
    {"name": "hr-ws-12", "asset_type": "workstation", "ip_address": "10.0.40.112", "os": "Windows 11", "criticality": "medium", "department": "People"},
    {"name": "core-sw-01", "asset_type": "network_device", "ip_address": "10.0.0.2", "os": "IOS-XE 17", "criticality": "critical", "department": "IT"},
    {"name": "vpn-gw", "asset_type": "network_device", "ip_address": "203.0.113.10", "os": "OpenVPN AS", "criticality": "high", "department": "IT"},
]
VULNERABILITIES = {"web-01": ["CVE-2024-6387"], "vpn-gw": ["CVE-2024-3400", "CVE-2023-46805"], "fin-laptop-07": ["CVE-2024-21412"]}

RULES = [
    {"name": "vpn-brute-force", "description": "Many failed VPN logins from one address", "rule_type": "signature", "detection_source": "identity", "severity": "high", "status": "enabled", "tags": ["T1110", "brute-force"], "logic": "event_type == 'authentication' and status == 'failed' | count by source_ip > 10 in 5m"},
    {"name": "encoded-powershell", "description": "PowerShell started with an encoded command", "rule_type": "signature", "detection_source": "endpoint", "severity": "high", "status": "enabled", "tags": ["T1059.001"], "logic": "process_name == 'powershell.exe' and command_line matches '(?i)-enc(odedcommand)?'"},
    {"name": "shadow-copy-deletion", "description": "Shadow copies or backups deleted", "rule_type": "behavior", "detection_source": "endpoint", "severity": "critical", "status": "enabled", "tags": ["T1490", "ransomware"], "logic": "command_line matches '(?i)vssadmin(.exe)? delete shadows|wmic shadowcopy delete'"},
    {"name": "dns-to-known-bad", "description": "DNS lookup of a domain on the block list", "rule_type": "signature", "detection_source": "network", "severity": "high", "status": "enabled", "tags": ["T1071.004"], "logic": "event_type == 'dns' and domain in threat_intel.domains"},
    {"name": "off-hours-admin", "description": "Administrator sign-in outside business hours", "rule_type": "anomaly", "detection_source": "identity", "severity": "medium", "status": "testing", "tags": ["T1078"], "logic": "user_type == 'admin' and hour(timestamp) not in 07..19"},
    {"name": "lateral-smb", "description": "One host opening SMB sessions to many others", "rule_type": "correlation", "detection_source": "network", "severity": "high", "status": "disabled", "tags": ["T1021.002"], "logic": "protocol == 'smb' | distinct destination_ip by source_ip > 20 in 10m"},
]


def events(now):
    """A day of events: mostly routine, with a few the engine should flag."""
    def at(minutes_ago):
        return (now - timedelta(minutes=minutes_ago)).isoformat()

    routine = []
    for index in range(36):
        minutes_ago = random.randint(5, 23 * 60)
        kind = random.choice(["login", "process", "network", "dns"])
        if kind == "login":
            routine.append({"timestamp": at(minutes_ago), "event_type": "authentication", "source": "vpn-gw", "user_id": random.choice(["jsmith", "akamau", "mwanjiru", "dkoech"]), "source_ip": f"198.51.100.{random.randint(2, 250)}", "description": "VPN sign-in", "raw_data": {"status": "success"}})
        elif kind == "process":
            name = random.choice(["chrome.exe", "outlook.exe", "excel.exe", "teams.exe", "code.exe"])
            routine.append({"timestamp": at(minutes_ago), "event_type": "process", "source": "endpoint_agent", "user_id": random.choice(["jsmith", "akamau"]), "description": f"{name} started", "raw_data": {"process_name": name, "command_line": name}})
        elif kind == "network":
            routine.append({"timestamp": at(minutes_ago), "event_type": "network", "source": "firewall", "source_ip": f"10.0.40.{random.randint(2, 250)}", "destination_ip": random.choice(["142.250.185.78", "140.82.121.4", "151.101.1.69"]), "protocol": "tcp", "action": "allow", "description": "Outbound HTTPS", "raw_data": {"dst_port": 443, "direction": "outbound", "bytes_sent": random.randint(800, 90_000)}})
        else:
            routine.append({"timestamp": at(minutes_ago), "event_type": "dns", "source": "dns-resolver", "source_ip": f"10.0.40.{random.randint(2, 250)}", "description": "DNS query", "raw_data": {"domain": random.choice(["github.com", "office.com", "slack.com", "pypi.org"])}})

    suspicious = [
        {"timestamp": at(18), "event_type": "process", "source": "endpoint_agent", "user_id": "jsmith", "asset": "fin-laptop-07", "description": "Shadow copies deleted", "raw_data": {"process_name": "vssadmin.exe", "command_line": "vssadmin delete shadows /all /quiet"}},
        {"timestamp": at(21), "event_type": "process", "source": "endpoint_agent", "user_id": "jsmith", "asset": "fin-laptop-07", "description": "Encoded PowerShell command", "raw_data": {"process_name": "powershell.exe", "command_line": "powershell.exe -NoProfile -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQ=="}},
        {"timestamp": at(95), "event_type": "dns", "source": "dns-resolver", "source_ip": "10.0.40.112", "asset": "hr-ws-12", "description": "DNS query for evil.net", "raw_data": {"domain": "evil.net"}},
        {"timestamp": at(200), "event_type": "authentication", "source": "vpn-gw", "user_id": "admin", "source_ip": "185.220.101.4", "asset": "vpn-gw", "description": "VPN sign-in failed", "raw_data": {"status": "failed"}},
        {"timestamp": at(320), "event_type": "file", "source": "endpoint_agent", "user_id": "mwanjiru", "asset": "hr-ws-12", "description": "File renamed with .locked extension", "raw_data": {"operation": "rename", "filepath": "C:\\Users\\mwanjiru\\Documents\\payroll.xlsx.locked", "file_extension": "locked"}},
        {"timestamp": at(610), "event_type": "system", "source": "endpoint_agent", "user_id": "dkoech", "asset": "web-01", "description": "Security service stopped", "raw_data": {"action": "disable", "service_name": "windows-defender"}},
    ]
    return routine, suspicious


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--gateway", default=os.environ.get("GATEWAY_URL", "http://localhost:8000"))
    parser.add_argument("--username", default="demo")
    args = parser.parse_args()

    password = os.environ.get("DEMO_PASSWORD") or secrets.token_urlsafe(12)
    api = Gateway(args.gateway)
    api.sign_in(args.username, password)

    asset_ids = {}
    for asset in ASSETS:
        created = api.request("POST", "/assets/", body=asset)
        asset_ids[asset["name"]] = created["id"]
        for vulnerability in VULNERABILITIES.get(asset["name"], []):
            api.request("PATCH", f"/assets/{created['id']}/vulnerabilities/add", params={"vulnerability": vulnerability})
    for rule in RULES:
        api.request("POST", "/detection/rules", body=rule)
    api.request("POST", "/simulation/", body={
        "name": "Quarterly ransomware drill", "description": "Shadow-copy deletion and file encryption on a finance laptop.",
        "scenario_type": "ransomware", "scope": "endpoint", "intensity": "medium", "status": "idle", "target_assets": [asset_ids["fin-laptop-07"]],
    })

    random.seed(7)
    routine, suspicious = events(datetime.now(timezone.utc))
    for event in routine:
        api.request("POST", "/events/", body=event)
    flagged = []
    for event in suspicious:
        asset = event.pop("asset", None)
        if asset:
            event["asset_id"] = asset_ids[asset]
        flagged.append(api.request("POST", "/events/", body=event)["id"])

    # Wait for the engine's verdicts, then triage some of the alerts.
    alert_ids = []
    deadline = time.monotonic() + 30
    pending = list(flagged)
    while pending and time.monotonic() < deadline:
        for event_id in list(pending):
            analysis = api.request("GET", f"/events/{event_id}").get("metadata", {}).get("analysis")
            if analysis:
                pending.remove(event_id)
                if analysis.get("alert_id"):
                    alert_ids.append(analysis["alert_id"])
        time.sleep(0.5)
    for alert_id, status in zip(alert_ids[2:], ["in_progress", "resolved", "false_positive"]):
        api.request("PATCH", f"/alerts/{alert_id}/status", params={"status": status, "notes": "Triaged during the demo seed."})

    print(f"Seeded {len(ASSETS)} assets, {len(RULES)} rules, {len(routine) + len(suspicious)} events "
          f"and {len(alert_ids)} alerts raised by the core engine.")
    if pending:
        print(f"{len(pending)} events were still awaiting analysis; is the core engine connected?", file=sys.stderr)
    print(f"Sign in as {args.username!r} with password {password!r}")


if __name__ == "__main__":
    main()
