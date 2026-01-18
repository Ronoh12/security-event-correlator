# 🧩 Security Event Correlator (Python)

Correlates Linux authentication logs and firewall logs into an **incident-style report** with **risk scoring** (LOW / MEDIUM / HIGH).  
Outputs both **Markdown** (human-friendly) and **JSON** (machine-friendly) reports.

## ▶️ Run Demo
```bash
python3 src/correlate_events.py --auth demo/demo_auth.log --fw demo/demo_firewall.log

