# 🧩 Security Event Correlator (Python)

A Blue Team / SOC-style project that **correlates authentication events and firewall blocks** into an **incident-focused report** with **risk scoring** (LOW / MEDIUM / HIGH).  
Outputs both **Markdown** (human-friendly) and **JSON** (machine-friendly) reports.

---

## ✅ What It Detects
- Failed SSH login attempts by source IP
- Firewall blocks by source IP and destination port
- Correlated “incident” view per IP (auth + firewall evidence combined)
- Heuristic risk scoring:
  - **HIGH**: sensitive ports targeted (e.g., 3389/445/21/23) or high volume activity
  - **MEDIUM**: moderate repeated failures/blocks
  - **LOW**: low volume noise

---

## 📂 Project Structure
```text
security-event-correlator/
├── README.md
├── demo/
│   ├── demo_auth.log
│   └── demo_firewall.log
├── reports/
│   ├── sample_incident_report.md
│   └── sample_incident_report.json
└── src/
    └── correlate_events.py

