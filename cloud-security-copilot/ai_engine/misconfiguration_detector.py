"""
ai_engine/misconfiguration_detector.py
Step 2: Load JSON with Python+Pandas | Step 3: AI rule-based detection + RAG
"""
import json, os
import pandas as pd
from dataclasses import dataclass
from typing import List, Dict

RAG_KB = {
    "VM-001":{"source":"CIS AWS 4.1","context":"SSH port 22 to 0.0.0.0/0. Bots scan entire IPv4 internet in 45 minutes."},
    "VM-002":{"source":"NIST SP 800-53 SC-7","context":"RDP is #1 ransomware vector. BlueKeep CVE allows unauthenticated RCE."},
    "VM-003":{"source":"GDPR Article 32","context":"Unencrypted EBS exposes data via snapshot. KMS needed for GDPR/HIPAA/SOC2."},
    "VM-004":{"source":"NIST 800-53 CP-9","context":"Without backups, ransomware causes permanent data loss."},
    "VM-005":{"source":"AWS Cost Optimization","context":"Idle VMs still incur EBS costs. Use Reserved Instances for 30-72% saving."},
    "S3-001":{"source":"CIS AWS 2.1.5","context":"Public write enables malware hosting and cost explosion attacks."},
    "S3-002":{"source":"CIS AWS 2.1.5/GDPR 25","context":"7% of S3 buckets were publicly readable (Google Project Zero 2021)."},
    "S3-003":{"source":"CIS AWS 2.1.1","context":"SSE-S3/SSE-KMS required for HIPAA Safe Harbor and PCI-DSS Level 1."},
    "S3-004":{"source":"CIS AWS 2.1.3","context":"Versioning prevents ransomware overwrite. Combine with MFA Delete."},
    "S3-005":{"source":"SOC2 CC6.1","context":"Access logs required for SOC2/ISO27001/FedRAMP. Retain 90 days minimum."},
    "S3-006":{"source":"AWS S3 Storage Classes","context":"S3 Standard=$0.023/GB. S3-IA=$0.0125/GB. Glacier=$0.004/GB."},
    "DB-001":{"source":"CIS AWS 2.3.2","context":"MongoDB wave 2017: 28,000 internet-exposed DBs compromised. Use private subnets."},
    "DB-002":{"source":"HIPAA 164.312","context":"RDS encryption requires snapshot restore. Plan during maintenance window."},
    "DB-003":{"source":"PCI-DSS 4.1","context":"Set rds.force_ssl=1. Update all connection strings."},
    "DB-004":{"source":"SOC2 A1.2","context":"7-day minimum. Production needs 35 days for financial regulations."},
    "DB-005":{"source":"AWS RDS HA","context":"Multi-AZ failover is automatic within 60-120 seconds."},
    "DB-006":{"source":"AWS Cost — DB","context":"Idle RDS still charges full instance-hours. Snapshot and delete."},
    "SG-001":{"source":"CIS AWS 4.1/4.2","context":"0.0.0.0/0 all-ports = no firewall whatsoever."},
    "SG-002":{"source":"CIS AWS 4.1","context":"1.5M SSH brute-force attempts per hour globally. Restrict or use SSM."},
    "SG-003":{"source":"CISA AA21-131A","context":"Nation-state actors use automated RDP scanning as initial access."},
    "SG-004":{"source":"AWS SG Best Practices","context":"Orphaned groups create audit noise and accidental reuse risk."},
    "IAM-001":{"source":"CIS AWS 1.16","context":"AdministratorAccess enables full privilege escalation chains."},
    "IAM-002":{"source":"AWS IAM Best Practices","context":"Action:* grants all current AND future AWS actions."},
    "IAM-003":{"source":"CIS AWS 1.14","context":"MFA reduces account takeover risk by 99.9% (Microsoft 2019)."},
    "IAM-004":{"source":"CIS AWS 1.12","context":"Stale credentials exploited in breaches. Review and delete unused roles."},
    "IAM-005":{"source":"AWS IAM Managed Policies","context":"Inline policies cannot be reused or centrally audited."},
}

@dataclass
class Finding:
    resource_id:   str
    resource_type: str
    resource_name: str
    check_id:      str
    title:         str
    description:   str
    severity:      str
    category:      str
    fix:           str
    rag_source:    str = ""
    rag_context:   str = ""
    def to_dict(self): return self.__dict__

def _rag(f):
    r = RAG_KB.get(f.check_id, {})
    f.rag_source  = r.get("source","Internal Security Policy")
    f.rag_context = r.get("context","Follow cloud security best practices.")
    return f

def _mk(rid,rtype,rname,cid,title,desc,sev,cat,fix):
    return _rag(Finding(rid,rtype,rname,cid,title,desc,sev,cat,fix))

def load_data(json_path):
    with open(json_path) as f:
        raw = json.load(f)
    dfs = {}
    for k,v in raw.items():
        if v:
            df = pd.DataFrame(v); df["type"]=k; dfs[k]=df
    return raw, dfs, []

def flatten_resources(raw):
    tmap = {"virtual_machines":"VirtualMachine","storage_buckets":"StorageBucket",
            "databases":"Database","security_groups":"SecurityGroup","iam_roles":"IAMRole"}
    flat = []
    for k,t in tmap.items():
        for r in raw.get(k,[]):
            r=dict(r); r["type"]=t; flat.append(r)
    return flat

def _vm(r):
    F,b=[],( "VirtualMachine",r["name"])
    if r.get("port_22_open") and r.get("public_ip"):
        F.append(_mk(r["id"],*b,"VM-001","SSH Port 22 Open to Internet","Port 22 exposed to 0.0.0.0/0. Automated bots brute-force SSH continuously.","CRITICAL","Security","Restrict SSH to office IP. Use AWS SSM Session Manager."))
    if r.get("port_3389_open") and r.get("public_ip"):
        F.append(_mk(r["id"],*b,"VM-002","RDP Port 3389 Open to Internet","RDP top ransomware vector. Known CVEs allow unauthenticated RCE.","CRITICAL","Security","Block 3389 from internet. Use VPN or AWS SSM for Windows access."))
    if not r.get("encryption_enabled"):
        F.append(_mk(r["id"],*b,"VM-003","Disk Encryption Disabled","Root EBS unencrypted. Snapshot or physical access exposes all data.","HIGH","Security","Enable EBS encryption. Replace volume via encrypted snapshot."))
    if not r.get("backup_enabled"):
        F.append(_mk(r["id"],*b,"VM-004","Automated Backups Not Configured","No backup policy. Ransomware causes permanent data loss.","MEDIUM","Compliance","Enable AWS Backup retaining snapshots 7+ days."))
    if r.get("cpu_usage_percent",100)<10 and r.get("last_used_days",0)>30:
        F.append(_mk(r["id"],*b,"VM-005",f"Idle VM — CPU {r.get('cpu_usage_percent')}% — {r.get('last_used_days')} Days",f"CPU {r.get('cpu_usage_percent')}%, idle {r.get('last_used_days')} days, costing ${r.get('monthly_cost_usd')}/mo.","LOW","Cost","Terminate VM (save AMI first). Use Reserved Instance for 30-72% saving."))
    return F

def _s3(r):
    F,b=[],("StorageBucket",r["name"])
    if r.get("public_write"):
        F.append(_mk(r["id"],*b,"S3-001","Bucket Allows Public WRITE","Anyone can upload/delete objects. Enables malware hosting and cost explosion.","CRITICAL","Security","Set BlockPublicAcls=true and BlockPublicPolicy=true immediately."))
    if r.get("public_read"):
        F.append(_mk(r["id"],*b,"S3-002","Bucket Allows Public READ","Anyone downloads all objects — exposes PII, API keys, source code.","HIGH","Security","Enable S3 Block Public Access. Use pre-signed URLs for controlled access."))
    if not r.get("encryption_enabled"):
        F.append(_mk(r["id"],*b,"S3-003","Encryption at Rest Disabled","Objects stored as plaintext. Breach exposes all contents.","HIGH","Security","Enable default SSE-S3 or SSE-KMS on bucket."))
    if not r.get("versioning"):
        F.append(_mk(r["id"],*b,"S3-004","Versioning Disabled","Accidental deletion or ransomware overwrite is permanent.","MEDIUM","Compliance","Enable versioning. Add lifecycle rule to expire old versions after 90 days."))
    if not r.get("logging_enabled"):
        F.append(_mk(r["id"],*b,"S3-005","Access Logging Disabled","No audit trail. Fails SOC2/ISO27001/GDPR monitoring requirements.","MEDIUM","Compliance","Enable S3 access logging to dedicated audit bucket."))
    if r.get("last_used_days",0)>60 and r.get("size_gb",0)>50:
        F.append(_mk(r["id"],*b,"S3-006",f"Idle Bucket {r.get('size_gb')}GB — {r.get('last_used_days')} Days",f"{r.get('size_gb')}GB unused {r.get('last_used_days')} days, costing ${r.get('monthly_cost_usd')}/mo.","LOW","Cost","Move to S3-IA (46% saving) or Glacier (83% saving). Add lifecycle policy."))
    return F

def _db(r):
    F,b=[],("Database",r["name"])
    if r.get("publicly_accessible"):
        F.append(_mk(r["id"],*b,"DB-001","Database Publicly Accessible",f"{r.get('engine','DB')} exposed to internet. Direct SQL attacks, brute-force, CVE exploits.","CRITICAL","Security","Set PubliclyAccessible=false. Place in private VPC subnet."))
    if not r.get("encryption_enabled"):
        F.append(_mk(r["id"],*b,"DB-002","Database Encryption Disabled","Storage unencrypted. Snapshot access reveals all data.","HIGH","Security","Enable RDS KMS encryption via encrypted snapshot restore."))
    if not r.get("ssl_enforced"):
        F.append(_mk(r["id"],*b,"DB-003","SSL/TLS Not Enforced","Unencrypted connections. Passwords and PII interceptable via network sniffing.","HIGH","Security","Set rds.force_ssl=1. Update all connection strings to SSL."))
    if r.get("backup_retention_days",0)<7:
        F.append(_mk(r["id"],*b,"DB-004",f"Backup Retention {r.get('backup_retention_days',0)} Days",f"Only {r.get('backup_retention_days',0)}-day retention. Compliance requires 7 days minimum.","MEDIUM","Compliance","Increase backup retention to 7+ days (35 for production)."))
    if not r.get("multi_az") and r.get("environment")=="production":
        F.append(_mk(r["id"],*b,"DB-005","Production DB Not Multi-AZ","Single AZ: outage = complete production DB downtime.","MEDIUM","Compliance","Enable Multi-AZ with automatic failover (60-120s)."))
    if r.get("status")=="idle" and r.get("last_used_days",0)>20:
        F.append(_mk(r["id"],*b,"DB-006",f"Idle DB — {r.get('last_used_days')} Days",f"DB idle {r.get('last_used_days')} days, costing ${r.get('monthly_cost_usd')}/mo.","LOW","Cost","Take final snapshot, delete. Restore when needed. Try Aurora Serverless."))
    return F

def _sg(r):
    F,b=[],("SecurityGroup",r["name"])
    if r.get("inbound_all_open"):
        F.append(_mk(r["id"],*b,"SG-001","All Inbound Open (0.0.0.0/0 All Ports)","All traffic permitted on all ports. Network security completely bypassed.","CRITICAL","Security","Remove 0.0.0.0/0 all-port rule. Add specific port+IP rules only."))
    if r.get("ssh_from_anywhere"):
        F.append(_mk(r["id"],*b,"SG-002","SSH Open to 0.0.0.0/0","Bots attack open SSH ports continuously across the entire internet.","HIGH","Security","Restrict SSH to office IP. Use AWS SSM Session Manager."))
    if r.get("rdp_from_anywhere"):
        F.append(_mk(r["id"],*b,"SG-003","RDP Open to 0.0.0.0/0","Ransomware groups use automated RDP scanning as initial access.","HIGH","Security","Restrict RDP to trusted IPs. Use VPN for Windows access."))
    if r.get("unused") and r.get("attached_resources",0)==0:
        F.append(_mk(r["id"],*b,"SG-004","Orphaned Security Group","Not attached to any resource. Creates audit noise and accidental reuse risk.","LOW","Cost","Delete orphaned security group."))
    return F

def _iam(r):
    F,b=[],("IAMRole",r["name"])
    if r.get("admin_access"):
        F.append(_mk(r["id"],*b,"IAM-001","IAM Role Has Full AdministratorAccess","Role can do anything on any resource. Stolen = full account takeover.","CRITICAL","Security","Replace AdministratorAccess with scoped service policies. Use IAM Access Analyzer."))
    if r.get("wildcard_actions"):
        F.append(_mk(r["id"],*b,"IAM-002","IAM Policy Wildcard Actions (Action:*)","Action:* grants all current and future AWS service actions.","HIGH","Security","Replace Action:* with specific action names."))
    if not r.get("mfa_required"):
        F.append(_mk(r["id"],*b,"IAM-003","MFA Not Required","Stolen credentials = immediate full access. No second factor blocks attacker.","HIGH","Security",'Add MFA condition: {"Condition":{"BoolIfExists":{"aws:MultiFactorAuthPresent":"true"}}}'))
    if r.get("unused_days",0)>90:
        F.append(_mk(r["id"],*b,"IAM-004",f"Stale Role — {r.get('unused_days')} Days Unused",f"Role not used in {r.get('unused_days')} days. Stale credentials expand attack surface.","MEDIUM","Security","Delete if not needed. Verify permissions if keeping."))
    if r.get("inline_policies",0)>2:
        F.append(_mk(r["id"],*b,"IAM-005",f"Excessive Inline Policies ({r.get('inline_policies')})",f"{r.get('inline_policies')} inline policies — hard to audit, cannot be reused.","LOW","Compliance","Convert to customer-managed policies for central governance."))
    return F

DETECTORS={"VirtualMachine":_vm,"StorageBucket":_s3,"Database":_db,"SecurityGroup":_sg,"IAMRole":_iam}

def run_detection(resources):
    findings=[]
    for r in resources:
        fn=DETECTORS.get(r.get("type"))
        if fn: findings.extend(fn(r))
    return findings

def get_summary(findings):
    c={"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0}
    for f in findings: c[f.severity]+=1
    c["TOTAL"]=len(findings); return c
