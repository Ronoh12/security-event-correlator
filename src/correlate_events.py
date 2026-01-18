#!/usr/bin/env python3
import argparse
import json
import os
import re
from collections import Counter, defaultdict
from datetime import datetime
from typing import Dict, Any, List, Optional


# --- Regex patterns ---
AUTH_FAILED = re.compile(r"Failed password for (invalid user )?(?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)")
AUTH_SUCCESS = re.compile(r"Accepted (password|publickey) for (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)")

UFW_BLOCK = re.compile(r"\[UFW BLOCK\].*SRC=(?P<src>\d+\.\d+\.\d+\.\d+).*DPT=(?P<dpt>\d+)")


def risk_label(level: str) -> str:
    level = level.upper()
    if level == "HIGH":
        return "[HIGH RISK]"
    if level == "MEDIUM":
        return "[MEDIUM RISK]"
    return "[LOW RISK]"


def score_incident(failed_attempts: int, blocked_count: int, sensitive_ports: int) -> str:
    """
    Simple SOC-style scoring:
    - HIGH: many failures OR targeting sensitive ports like RDP/SMB
    - MEDIUM: moderate failures/blocks
    - LOW: small noise
    """
    if sensitive_ports > 0:
        return "HIGH"
    if failed_attempts >= 8 or blocked_count >= 8:
        return "HIGH"
    if failed_attempts >= 3 or blocked_count >= 3:
        return "MEDIUM"
    return "LOW"


def parse_auth_log(path: str) -> Dict[str, Any]:
    failed_by_ip = Counter()
    failed_by_user = Counter()
    success_by_ip = Counter()
    success_by_user = Counter()

    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()

            m = AUTH_FAILED.search(line)
            if m:
                failed_by_ip[m.group("ip")] += 1
                failed_by_user[m.group("user")] += 1
                continue

            m = AUTH_SUCCESS.search(line)
            if m:
                success_by_ip[m.group("ip")] += 1
                success_by_user[m.group("user")] += 1

    return {
        "failed_by_ip": dict(failed_by_ip),
        "failed_by_user": dict(failed_by_user),
        "success_by_ip": dict(success_by_ip),
        "success_by_user": dict(success_by_user),
    }


def parse_firewall_log(path: str) -> Dict[str, Any]:
    blocks_by_ip = Counter()
    dpt_by_ip = defaultdict(Counter)

    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            m = UFW_BLOCK.search(line)
            if not m:
                continue

            src = m.group("src")
            dpt = int(m.group("dpt"))
            blocks_by_ip[src] += 1
            dpt_by_ip[src][dpt] += 1

    return {
        "blocks_by_ip": dict(blocks_by_ip),
        "dpt_by_ip": {ip: dict(cnt) for ip, cnt in dpt_by_ip.items()},
    }


def build_incidents(auth: Dict[str, Any], fw: Dict[str, Any]) -> List[Dict[str, Any]]:
    ips = set(auth["failed_by_ip"].keys()) | set(fw["blocks_by_ip"].keys())

    incidents = []
    for ip in sorted(ips):
        failed = int(auth["failed_by_ip"].get(ip, 0))
        blocked = int(fw["blocks_by_ip"].get(ip, 0))
        ports = fw["dpt_by_ip"].get(ip, {})

        # Sensitive ports (common exposure concern)
        sensitive = 0
        for p in ports:
            if p in (3389, 445, 23, 21):
                sensitive += 1

        risk = score_incident(failed, blocked, sensitive)

        incidents.append({
            "source_ip": ip,
            "failed_logins": failed,
            "firewall_blocks": blocked,
            "destination_ports": ports,
            "risk": risk,
            "label": risk_label(risk),
            "notes": "Correlated from auth + firewall logs (demo or real).",
        })

    # Sort: HIGH first, then counts
    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    incidents.sort(key=lambda x: (order[x["risk"]], -(x["failed_logins"] + x["firewall_blocks"])))
    return incidents


def write_markdown(incidents: List[Dict[str, Any]], out_path: str, meta: Dict[str, Any]) -> None:
    lines: List[str] = []
    lines.append("# 🧩 Security Event Correlation Report\n")
    lines.append(f"- Generated: `{meta['generated_at']}`")
    lines.append(f"- Auth log: `{meta['auth_log']}`")
    lines.append(f"- Firewall log: `{meta['firewall_log']}`\n")

    high = sum(1 for i in incidents if i["risk"] == "HIGH")
    med = sum(1 for i in incidents if i["risk"] == "MEDIUM")
    low = sum(1 for i in incidents if i["risk"] == "LOW")
    lines.append("## ✅ Summary\n")
    lines.append(f"- Total incidents: **{len(incidents)}**")
    lines.append(f"- High: **{high}**, Medium: **{med}**, Low: **{low}**\n")

    lines.append("## 🚨 Incidents\n")
    if not incidents:
        lines.append("_No incidents found._\n")
    else:
        lines.append("| Source IP | Failed Logins | Firewall Blocks | Ports Targeted | Risk |")
        lines.append("|---|---:|---:|---|---|")
        for i in incidents:
            ports = ", ".join(f"{p}({c})" for p, c in sorted(i["destination_ports"].items()))
            lines.append(f"| {i['source_ip']} | {i['failed_logins']} | {i['firewall_blocks']} | {ports or '-'} | {i['label']} |")
        lines.append("")

    lines.append("## 🧠 Notes\n")
    lines.append("- This tool correlates events across multiple sources to build an incident-style view.")
    lines.append("- Risk scoring is heuristic and intended for learning and baseline triage.\n")

    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


def main() -> None:
    ap = argparse.ArgumentParser(description="Correlate auth + firewall logs into incident-style findings.")
    ap.add_argument("--auth", required=True, help="Path to auth log file (or demo/demo_auth.log).")
    ap.add_argument("--fw", required=True, help="Path to firewall log file (or demo/demo_firewall.log).")
    ap.add_argument("--out-json", default="reports/incident_report.json", help="JSON output path.")
    ap.add_argument("--out-md", default="reports/incident_report.md", help="Markdown output path.")
    args = ap.parse_args()

    if not os.path.exists(args.auth):
        raise SystemExit(f"❌ Auth log not found: {args.auth}")
    if not os.path.exists(args.fw):
        raise SystemExit(f"❌ Firewall log not found: {args.fw}")

    auth = parse_auth_log(args.auth)
    fw = parse_firewall_log(args.fw)

    incidents = build_incidents(auth, fw)

    os.makedirs(os.path.dirname(args.out_json), exist_ok=True)
    os.makedirs(os.path.dirname(args.out_md), exist_ok=True)

    meta = {
        "generated_at": datetime.now().isoformat(),
        "auth_log": args.auth,
        "firewall_log": args.fw,
    }

    with open(args.out_json, "w", encoding="utf-8") as f:
        json.dump({"meta": meta, "incidents": incidents}, f, indent=2)

    write_markdown(incidents, args.out_md, meta)

    print("✅ Incident reports generated")
    print(f"- Markdown: {args.out_md}")
    print(f"- JSON:     {args.out_json}")


if __name__ == "__main__":
    main()

