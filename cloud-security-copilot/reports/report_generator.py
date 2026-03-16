"""
reports/report_generator.py  —  Step 6: Report Generation
===========================================================
Generates downloadable PDF-ready HTML report and CSV files.
"""
import csv, io
from datetime import datetime
from typing import List, Dict

SEV_COLOR = {"Critical":"#FF3D5A","High":"#FFB800","Medium":"#00C8FF","Low":"#06D6A0"}
SEV_ORIG  = {"CRITICAL":"Critical","HIGH":"High","MEDIUM":"Medium","LOW":"Low"}


def export_findings_csv(enriched: List[Dict]) -> str:
    out = io.StringIO()
    if not enriched: return ""
    fields = ["urs_score","urs_label","severity","resource_id","resource_type",
              "resource_name","region","owner","environment",
              "check_id","title","category","description","fix","monthly_cost"]
    w = csv.DictWriter(out, fieldnames=fields, extrasaction="ignore")
    w.writeheader()
    w.writerows(enriched)
    return out.getvalue()


def export_cost_csv(opps: List[Dict]) -> str:
    out = io.StringIO()
    if not opps: return ""
    fields = ["resource_id","resource_name","resource_type","region","owner",
              "environment","status","idle_days","monthly_cost_usd",
              "estimated_monthly_saving","estimated_annual_saving","action","suggestion"]
    w = csv.DictWriter(out, fieldnames=fields, extrasaction="ignore")
    w.writeheader()
    rows = [o.to_dict() if hasattr(o,'to_dict') else o for o in opps]
    w.writerows(rows)
    return out.getvalue()


def export_html_report(enriched: List[Dict], cost_opps: List[Dict],
                       cost_sum: Dict, resource_count: int) -> str:
    now = datetime.now().strftime("%d %B %Y, %H:%M UTC")
    critical = sum(1 for f in enriched if f["urs_label"]=="Critical")
    high     = sum(1 for f in enriched if f["urs_label"]=="High")
    medium   = sum(1 for f in enriched if f["urs_label"]=="Medium")
    low      = sum(1 for f in enriched if f["urs_label"]=="Low")

    # Security rows
    sec_rows = ""
    for f in enriched[:50]:
        c = SEV_COLOR.get(f["urs_label"],"#888")
        sec_rows += f"""<tr>
<td><b style="color:{f['urs_color']}">{f['urs_score']}</b></td>
<td><span class="b" style="background:{c}">{f['urs_label']}</span></td>
<td>{f['resource_type']}</td><td>{f['resource_name']}</td>
<td>{f.get('region','—')}</td><td>{f['check_id']}</td>
<td>{f['title']}</td><td>{f['category']}</td>
</tr>"""

    # Cost rows
    cost_rows = ""
    for o in cost_opps:
        ac = "#FF3D5A" if o["action"]=="TERMINATE" else "#FFB800" if o["action"]=="REVIEW" else "#A78BFA"
        cost_rows += f"""<tr>
<td>{o['resource_name']}</td><td>{o['resource_type']}</td>
<td>{o['region']}</td><td>{o['idle_days']}d</td>
<td>${o['monthly_cost_usd']:.2f}</td>
<td style="color:#06D6A0"><b>${o['estimated_monthly_saving']:.2f}</b></td>
<td style="color:#06D6A0"><b>${o['estimated_annual_saving']:.2f}</b></td>
<td><span class="b" style="background:{ac}">{o['action']}</span></td>
</tr>"""

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<title>Cloud Security Copilot — Security Report</title>
<style>
body{{font-family:'Segoe UI',Arial,sans-serif;background:#07101F;color:#C8DCF5;margin:0;padding:24px}}
.hdr{{background:#0C1A30;padding:24px;border-radius:12px;margin-bottom:24px;border-top:4px solid #00C8FF}}
h1{{color:#00C8FF;margin:0 0 6px;font-size:28px}} .meta{{color:#6A8CB0;font-size:12px}}
.kpis{{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:24px}}
.kpi{{background:#0C1A30;border-radius:10px;padding:18px;text-align:center;border-top:3px solid}}
.kn{{font-size:36px;font-weight:800;margin-bottom:4px}} .kl{{font-size:10px;color:#6A8CB0;text-transform:uppercase;letter-spacing:1px}}
.sec{{background:#0C1A30;border-radius:12px;padding:20px;margin-bottom:20px}}
.st{{font-size:10px;font-weight:700;letter-spacing:3px;text-transform:uppercase;color:#00C8FF;margin-bottom:14px}}
table{{width:100%;border-collapse:collapse;font-size:12px}}
th{{background:#142244;color:#6A8CB0;padding:10px 8px;text-align:left;font-size:10px;letter-spacing:1px;text-transform:uppercase}}
td{{padding:9px 8px;border-bottom:1px solid #1A2E55}}
tr:hover td{{background:#142244}}
.b{{display:inline-block;padding:2px 8px;border-radius:3px;font-size:10px;font-weight:700;color:#07101F}}
.cost-kpis{{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-bottom:14px}}
.ck{{background:#142244;border-radius:8px;padding:14px;text-align:center}}
.cn{{font-size:22px;font-weight:800;color:#06D6A0}} .cl{{font-size:10px;color:#6A8CB0;text-transform:uppercase;letter-spacing:1px;margin-top:3px}}
.footer{{text-align:center;color:#2E4668;font-size:11px;margin-top:24px}}
</style></head><body>

<div class="hdr">
  <h1>🛡️ GenAI Cloud Security Copilot</h1>
  <div class="meta">Security & Cost Optimization Report &nbsp;|&nbsp; Generated: {now} &nbsp;|&nbsp; {resource_count} Resources Scanned</div>
</div>

<div class="kpis">
  <div class="kpi" style="border-color:#FF3D5A"><div class="kn" style="color:#FF3D5A">{critical}</div><div class="kl">Critical</div></div>
  <div class="kpi" style="border-color:#FFB800"><div class="kn" style="color:#FFB800">{high}</div><div class="kl">High</div></div>
  <div class="kpi" style="border-color:#00C8FF"><div class="kn" style="color:#00C8FF">{medium}</div><div class="kl">Medium</div></div>
  <div class="kpi" style="border-color:#06D6A0"><div class="kn" style="color:#06D6A0">{low}</div><div class="kl">Low</div></div>
</div>

<div class="sec">
  <div class="st">Security Findings — Risk Scoring Results (Top 50)</div>
  <table><thead><tr>
    <th>URS</th><th>Risk Level</th><th>Type</th><th>Resource</th>
    <th>Region</th><th>Check ID</th><th>Finding</th><th>Category</th>
  </tr></thead><tbody>{sec_rows}</tbody></table>
</div>

<div class="sec">
  <div class="st">Cost Optimization Opportunities</div>
  <div class="cost-kpis">
    <div class="ck"><div class="cn">${cost_sum.get('estimated_monthly_saving',0):,.0f}</div><div class="cl">Monthly Savings</div></div>
    <div class="ck"><div class="cn">${cost_sum.get('estimated_annual_saving',0):,.0f}</div><div class="cl">Annual Savings</div></div>
    <div class="ck"><div class="cn">{cost_sum.get('waste_percentage',0)}%</div><div class="cl">Waste Reduction</div></div>
  </div>
  <table><thead><tr>
    <th>Resource</th><th>Type</th><th>Region</th><th>Idle</th>
    <th>Cost/Month</th><th>Save/Month</th><th>Save/Year</th><th>Action</th>
  </tr></thead><tbody>{cost_rows}</tbody></table>
</div>

<div class="footer">
  Cloud Security Copilot &nbsp;|&nbsp; Risk Score Formula: (Severity×0.5) + (Exposure×0.3) + (Exploitability×0.2)
</div>
</body></html>"""


if __name__ == "__main__":
    print("[✓] Report generator ready — call export_html_report() or export_findings_csv()")
