
from typing import List, Dict

SEVERITY_BASE = {"CRITICAL":100,"HIGH":75,"MEDIUM":50,"LOW":20}
EXPOSURE      = {"VM-001":95,"VM-002":95,"VM-003":50,"VM-004":20,"VM-005":5,"S3-001":100,"S3-002":90,"S3-003":55,"S3-004":20,"S3-005":25,"S3-006":5,"DB-001":95,"DB-002":55,"DB-003":70,"DB-004":20,"DB-005":40,"DB-006":5,"SG-001":100,"SG-002":90,"SG-003":90,"SG-004":5,"IAM-001":95,"IAM-002":80,"IAM-003":75,"IAM-004":35,"IAM-005":10}
EXPLOITABILITY= {"VM-001":95,"VM-002":90,"VM-003":45,"VM-004":20,"VM-005":5,"S3-001":95,"S3-002":85,"S3-003":50,"S3-004":20,"S3-005":25,"S3-006":5,"DB-001":90,"DB-002":55,"DB-003":70,"DB-004":20,"DB-005":40,"DB-006":5,"SG-001":100,"SG-002":90,"SG-003":85,"SG-004":5,"IAM-001":95,"IAM-002":80,"IAM-003":75,"IAM-004":30,"IAM-005":10}

def compute_urs(check_id,severity,monthly_cost=0):
    sev=SEVERITY_BASE.get(severity,20); exp=EXPOSURE.get(check_id,30); expl=EXPLOITABILITY.get(check_id,30)
    cf=min(100,(monthly_cost/500)*100); eb=expl*0.8+cf*0.2
    return round(min((sev*0.50)+(exp*0.30)+(eb*0.20),100),1)

def urs_label(s): return "Critical" if s>=80 else "High" if s>=60 else "Medium" if s>=40 else "Low"
def urs_color(s): return "#FF3D5A" if s>=80 else "#FFB800" if s>=60 else "#00C8FF" if s>=40 else "#06D6A0"
def urs_badge(s): return "red" if s>=80 else "orange" if s>=60 else "blue" if s>=40 else "green"

def enrich_with_scores(findings,resources):
    rmap={r["id"]:r for r in resources}; enriched=[]
    for f in findings:
        r=rmap.get(f.resource_id,{}); cost=r.get("monthly_cost_usd",0); urs=compute_urs(f.check_id,f.severity,cost)
        d=f.to_dict(); d.update({"urs_score":urs,"urs_label":urs_label(urs),"urs_color":urs_color(urs),"urs_badge":urs_badge(urs),"monthly_cost":cost,"region":r.get("region","—"),"owner":r.get("owner","—"),"environment":r.get("environment","—")}); enriched.append(d)
    enriched.sort(key=lambda x:x["urs_score"],reverse=True); return enriched

def score_summary(enriched):
    c={"Critical":0,"High":0,"Medium":0,"Low":0}
    for e in enriched:
        lbl=e.get("urs_label","Low")
        if lbl in c: c[lbl]+=1
    c["Total"]=len(enriched); return c
