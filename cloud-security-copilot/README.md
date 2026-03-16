# 🛡️ Cloud Security Copilot
## GenAI-Powered Security & Cost Optimization

### Project Structure (exact match to spec)
```
cloud-security-copilot/
├── data/
│   └── cloud_resources.json          ← Step 1: Cloud data (VMs, Storage, DBs, IAM, SGs)
├── ai_engine/
│   └── misconfiguration_detector.py  ← Step 2+3: Python+Pandas loader + 25 AI detection rules
├── risk_scoring/
│   └── risk_score.py                 ← Step 4: URS 0-100 scoring formula
├── cost_optimizer/
│   └── idle_resource_detector.py     ← Step 5: Idle resource detection + savings
├── dashboard/
│   └── app.py                        ← Step 6: Streamlit interactive dashboard
└── reports/
    └── report_generator.py           ← Step 6: HTML + CSV export
```

### Quick Start
```bash
pip install -r requirements.txt
streamlit run dashboard/app.py
```
Open: http://localhost:8501

### Optional: Gemini AI
Get free key at: https://aistudio.google.com/app/apikey
Paste it in the dashboard sidebar.

### Risk Score Formula
```
URS = (Severity × 0.5) + (Exposure × 0.3) + (Exploitability × 0.2)
80-100 = Critical | 60-79 = High | 40-59 = Medium | 0-39 = Low
```

### Results from your dataset
- 19 resources scanned (5 VMs, 4 Buckets, 4 DBs, 3 SGs, 3 IAM)
- 52 findings (9 Critical, 20 High, 2 Medium, 21 Low)
- 8 idle resources → $445/month savings → $5,340/year savings
