"""
cost_optimizer/idle_resource_detector.py  —  Idle Resource & Cost Optimizer
IF cpu < 10% AND idle > 30d  → Idle VM
IF not_accessed > 60d AND size > 50GB → Idle Storage
IF status==idle AND no_queries > 20d  → Idle DB
"""
from dataclasses import dataclass
from typing import List, Dict
import pandas as pd

THR={"VirtualMachine":30,"StorageBucket":60,"Database":20,"IAMRole":90}
STRATEGIES={
    "VirtualMachine":"Terminate idle VM (save AMI first). Switch active VMs to Reserved Instances (save 30-72%).",
    "StorageBucket":"Move to S3-Infrequent Access or Glacier. Saves up to 75%.",
    "Database":"Take final snapshot, delete idle instance. Right-size active databases.",
    "IAMRole":"Delete unused role to reduce attack surface.",
    "SecurityGroup":"Delete orphaned security group.",
}

@dataclass
class CostOpportunity:
    resource_id:str; name:str; type:str; region:str; owner:str
    environment:str; status:str; idle_days:int; monthly_cost:float
    estimated_saving:float; annual_saving:float; action:str
    strategy:str; savings_percentage:float
    def to_dict(self): return self.__dict__

def _act(idle,thr): return "TERMINATE" if idle>thr*2 else "REVIEW"

def run_optimizer(data:dict)->List[CostOpportunity]:
    opps=[]
    for r in data.get("virtual_machines",[]):
        cpu,idle,cost=r.get("cpu_usage_percent",100),r.get("last_active_days",0),r.get("monthly_cost_usd",0)
        if cpu<10 and idle>THR["VirtualMachine"]:
            s=round(cost*0.60,2)
            opps.append(CostOpportunity(r["id"],r["name"],"VirtualMachine",r.get("region","—"),r.get("owner","—"),r.get("environment","—"),r.get("status","—"),idle,cost,s,round(s*12,2),_act(idle,THR["VirtualMachine"]),STRATEGIES["VirtualMachine"],60))
    for r in data.get("storage_buckets",[]):
        idle,cost,size=r.get("last_accessed_days",0),r.get("monthly_cost_usd",0),r.get("size_gb",0)
        if idle>THR["StorageBucket"] and size>50:
            s=round(cost*0.75,2)
            opps.append(CostOpportunity(r["id"],r["name"],"StorageBucket",r.get("region","—"),r.get("owner","—"),r.get("environment","—"),r.get("status","active"),idle,cost,s,round(s*12,2),_act(idle,THR["StorageBucket"]),STRATEGIES["StorageBucket"],75))
    for r in data.get("databases",[]):
        idle,cost=r.get("last_query_days",0),r.get("monthly_cost_usd",0)
        if r.get("status")=="idle" or idle>THR["Database"]:
            s=round(cost*0.65,2)
            opps.append(CostOpportunity(r["id"],r["name"],"Database",r.get("region","—"),r.get("owner","—"),r.get("environment","—"),r.get("status","—"),idle,cost,s,round(s*12,2),_act(idle,THR["Database"]),STRATEGIES["Database"],65))
    for r in data.get("iam_roles",[]):
        if r.get("unused_days",0)>THR["IAMRole"]:
            opps.append(CostOpportunity(r["id"],r["name"],"IAMRole","global",r.get("owner","—"),r.get("environment","—"),r.get("status","active"),r.get("unused_days",0),0,0,0,"REVIEW",STRATEGIES["IAMRole"],0))
    for r in data.get("network_security_groups",[]):
        if r.get("unused") and r.get("attached_resources",0)==0:
            opps.append(CostOpportunity(r["id"],r["name"],"SecurityGroup",r.get("region","—"),r.get("owner","—"),r.get("environment","—"),"unused",r.get("last_modified_days",0),0,0,0,"DELETE",STRATEGIES["SecurityGroup"],0))
    opps.sort(key=lambda x:x.monthly_cost,reverse=True)
    return opps

def cost_summary(opps:List[CostOpportunity])->Dict:
    tm=sum(o.monthly_cost for o in opps); ts=sum(o.estimated_saving for o in opps)
    return {"total_resources_flagged":len(opps),"total_monthly_waste":round(tm,2),
            "estimated_monthly_saving":round(ts,2),"estimated_annual_saving":round(ts*12,2),
            "saving_percentage":round((ts/tm*100) if tm else 0,1),
            "terminate_count":sum(1 for o in opps if o.action=="TERMINATE"),
            "review_count":sum(1 for o in opps if o.action=="REVIEW")}

def to_dataframe(opps:List[CostOpportunity])->"pd.DataFrame":
    return pd.DataFrame([o.to_dict() for o in opps])


# Compatibility alias used by dashboard/app.py
def detect_idle_resources(resources):
    """Wrapper that accepts flat resource list."""
    IDLE_THR  = {"VirtualMachine":30,"StorageBucket":60,"Database":20}
    SAVE_PCT  = {"VirtualMachine":0.55,"StorageBucket":0.75,"Database":0.60}
    SUGGEST   = {
        "VirtualMachine":"Shut down — save AMI. Use Reserved Instance (save 30-72%).",
        "StorageBucket": "Move to S3-IA (46% saving) or Glacier (83% saving).",
        "Database":      "Snapshot and delete. Restore when needed.",
        "SecurityGroup": "Delete orphaned group.",
        "IAMRole":       "Delete stale role.",
    }
    opps = []
    for r in resources:
        rtype = r.get("type","")
        cost  = r.get("monthly_cost_usd",0)
        idle  = r.get("last_used_days",0)
        cpu   = r.get("cpu_usage_percent",100)
        stat  = r.get("status","active")
        thr   = IDLE_THR.get(rtype,30)
        is_idle,reason = False,""
        if rtype=="VirtualMachine":
            if cpu<10 and idle>thr: is_idle=True; reason=f"CPU={cpu}%% idle {idle}d"
            elif stat in("stopped","idle") and idle>thr: is_idle=True; reason=f"Status={stat} unused {idle}d"
        elif rtype=="StorageBucket":
            if idle>thr and r.get("size_gb",0)>50: is_idle=True; reason=f"{r.get('size_gb')}GB unused {idle}d"
        elif rtype=="Database":
            if stat=="idle" or idle>thr: is_idle=True; reason=f"Idle {idle}d (status={stat})"
        elif rtype=="SecurityGroup":
            if r.get("unused") and r.get("attached_resources",0)==0: is_idle=True; reason="Orphaned"
        if is_idle:
            pct=SAVE_PCT.get(rtype,0.50); sm=round(cost*pct,2); sy=round(sm*12,2)
            action="TERMINATE" if idle>thr*2 else ("DELETE" if rtype=="SecurityGroup" else "REVIEW")
            opps.append({"resource_id":r["id"],"resource_name":r["name"],"resource_type":rtype,
                "region":r.get("region","—"),"owner":r.get("owner","—"),"environment":r.get("environment","—"),
                "status":stat,"idle_days":idle,"cpu_usage_percent":cpu,"monthly_cost_usd":cost,
                "estimated_monthly_saving":sm,"estimated_annual_saving":sy,"saving_percent":round(pct*100),
                "reason":reason,"action":action,"suggestion":SUGGEST.get(rtype,"Review.")})
    opps.sort(key=lambda x:x["estimated_monthly_saving"],reverse=True)
    return opps


def cost_summary(opps):
    """Works with both CostOpportunity objects and plain dicts."""
    tc,ts = 0,0
    for o in opps:
        if isinstance(o, dict):
            tc += o.get('monthly_cost_usd', 0)
            ts += o.get('estimated_monthly_saving', 0)
        else:
            tc += getattr(o,'monthly_cost',0)
            ts += getattr(o,'estimated_saving',0)
    return {
        'idle_resource_count': len(opps),
        'total_monthly_cost_at_risk': round(tc,2),
        'estimated_monthly_saving':  round(ts,2),
        'estimated_annual_saving':   round(ts*12,2),
        'waste_percentage':          round((ts/tc*100) if tc else 0,1),
    }
