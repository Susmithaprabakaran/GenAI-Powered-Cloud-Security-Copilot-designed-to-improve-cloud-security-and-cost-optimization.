"""
dashboard/app.py  —  Step 6: Streamlit Dashboard
==================================================
Run from project root:  streamlit run dashboard/app.py

Features:
  - Risk charts (severity, type, URS histogram, environment)
  - Security alerts with RAG context
  - Cost saving suggestions table + charts
  - Download PDF-ready HTML report + CSV files
  - Optional: Google Gemini AI explanations
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import sys, os, json

# ── Path setup ────────────────────────────────────────────────────────────────
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from ai_engine.misconfiguration_detector  import load_data, flatten_resources, run_detection, get_summary
from risk_scoring.risk_score              import enrich_with_scores, score_summary
from cost_optimizer.idle_resource_detector import detect_idle_resources, cost_summary
from reports.report_generator             import export_findings_csv, export_cost_csv, export_html_report

# ── Page config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="Cloud Security Copilot",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ── Global CSS ─────────────────────────────────────────────────────────────────
st.markdown("""
<style>
  .stApp { background-color: #07101F; }
  .main .block-container { padding-top: 0.8rem; }
  section[data-testid="stSidebar"] > div { background: #0C1A30; }

  /* KPI cards */
  .kpi { background:#0C1A30; border-radius:10px; padding:16px 18px;
         border-left:4px solid; margin-bottom:6px; }
  .kn  { font-size:32px; font-weight:800; line-height:1.1; }
  .kl  { font-size:10px; color:#6A8CB0; letter-spacing:1.5px;
         text-transform:uppercase; margin-top:3px; }

  /* Finding cards */
  .fc  { background:#0C1A30; border-radius:10px; padding:16px;
         margin-bottom:12px; border-left:5px solid; }
  .ft  { font-weight:700; font-size:14px; margin-bottom:4px; }
  .fm  { font-size:11px; color:#6A8CB0; margin-bottom:8px; }
  .fd  { font-size:12.5px; color:#A8C0D8; margin-bottom:8px; line-height:1.7; }
  .ff  { font-size:12px; background:#111F3A; border-radius:6px;
         padding:8px 12px; color:#00E5B0; margin-bottom:6px; }
  .fr  { font-size:11px; background:#0a1628; border-radius:6px;
         padding:7px 12px; color:#6A8CB0; border-left:3px solid #00C8FF; }
  .sh  { font-size:10px; font-weight:700; letter-spacing:3px;
         text-transform:uppercase; color:#00C8FF; margin:14px 0 8px; }
  .badge { display:inline-block; padding:1px 8px; border-radius:3px;
           font-size:10px; font-weight:700; color:#07101F; }
</style>
""", unsafe_allow_html=True)

SEV_COLOR = {"Critical":"#FF3D5A","High":"#FFB800","Medium":"#00C8FF","Low":"#06D6A0"}
TYPE_ICON = {"VirtualMachine":"🖥️","StorageBucket":"🪣","Database":"🗄️",
             "SecurityGroup":"🔒","IAMRole":"👤"}

# ── Sidebar ────────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("## 🛡️ Cloud Security Copilot")
    st.markdown("*GenAI Risk & Cost Optimization*")
    st.divider()

    # Gemini API (optional)
    st.markdown("### 🤖 AI Settings (Optional)")
    api_key = st.text_input("URL", type="password",
                            value=os.environ.get("GEMINI_API_KEY",""),
                            placeholder="AIza... (optional)",
                            help="Get free key at aistudio.google.com/app/apikey")
    use_ai = st.toggle("URL AI", value=bool(api_key))
    if api_key and use_ai:

        st.success("● Gemini Active")
    else:
        st.info("● Using fallback explanations")

    st.divider()
    page = st.radio("📂 Navigate", [
        "📊 Dashboard Overview",
        "🔍 Security Findings",
        "💸 Cost Optimization",
        "📋 Reports & Export",
    ])

    st.divider()
    st.markdown("**Filters**")
    sev_f  = st.multiselect("Risk Level", ["Critical","High","Medium","Low"],
                             default=["Critical","High","Medium","Low"])
    type_f = st.multiselect("Resource Type",
                             ["VirtualMachine","StorageBucket","Database","SecurityGroup","IAMRole"],
                             default=["VirtualMachine","StorageBucket","Database","SecurityGroup","IAMRole"])
    env_f  = st.multiselect("Environment",
                             ["production","staging","development"],
                             default=["production","staging","development"])
    st.divider()
    if st.button("🔄 Re-run Scan", use_container_width=True):
        st.cache_data.clear()
        st.rerun()

# ── Data Pipeline ─────────────────────────────────────────────────────────────
@st.cache_data(show_spinner="🔍 Scanning cloud resources...")
def run_pipeline(api_key_prefix: str, use_ai_flag: bool):
    data_path = os.path.join(ROOT, "data", "cloud_resources.json")
    raw, dfs, _ = load_data(data_path)
    resources   = flatten_resources(raw)
    findings    = run_detection(resources)
    enriched    = enrich_with_scores(findings, resources)
    cost_opps   = detect_idle_resources(resources)
    c_sum       = cost_summary(cost_opps)
    f_sum       = score_summary(enriched)
    total_r     = len(resources)

    # Optional Gemini enrichment
    if api_key_prefix and use_ai_flag:
        try:
            import google.generativeai as genai
            genai.configure(api_key=os.environ.get("GEMINI_API_KEY", api_key_prefix))
            model = genai.GenerativeModel("gemini-1.5-flash")
            for e in enriched:
                if e["severity"] in ("CRITICAL","HIGH"):
                    prompt = (
                        f"Cloud security finding — Resource: {e['resource_name']} "
                        f"({e['resource_type']}), Check: {e['check_id']}, "
                        f"Title: {e['title']}, URS: {e['urs_score']}/100. "
                        f"Write 2 sentences: business risk and urgency. Plain English, no bullets."
                    )
                    try:
                        resp = model.generate_content(prompt)
                        e["gemini_explanation"] = resp.text.strip()
                    except Exception:
                        e["gemini_explanation"] = _fallback(e["severity"])
                else:
                    e["gemini_explanation"] = _fallback(e["severity"])
        except Exception:
            for e in enriched:
                e["gemini_explanation"] = _fallback(e["severity"])
    else:
        for e in enriched:
            e["gemini_explanation"] = _fallback(e["severity"])

    return resources, enriched, cost_opps, c_sum, f_sum, total_r


def _fallback(severity):
    fb = {
        "CRITICAL": "This is an immediately exploitable critical vulnerability — automated bots are already scanning for it. Remediate within 24 hours to prevent full infrastructure compromise.",
        "HIGH":     "This high-severity misconfiguration creates a clear attack path. A motivated attacker can exploit it with moderate effort. Prioritize in your next sprint.",
        "MEDIUM":   "Medium-severity finding that weakens your security posture and may trigger compliance failures. Schedule remediation within two weeks.",
        "LOW":      "Best-practice violation with no immediate threat. Address in your quarterly security review to reduce technical security debt.",
    }
    return fb.get(severity, fb["MEDIUM"])


resources, enriched, cost_opps, c_sum, f_sum, total_r = run_pipeline(
    api_key[:8] if api_key else "", use_ai
)

# Apply filters
df = pd.DataFrame(enriched)
if not df.empty:
    df = df[df["urs_label"].isin(sev_f) &
            df["resource_type"].isin(type_f) &
            df["environment"].isin(env_f)]

# ══════════════════════════════════════════════
# PAGE 1 — DASHBOARD OVERVIEW
# ══════════════════════════════════════════════
if page == "📊 Dashboard Overview":
    st.markdown("## 📊 Security & Cost Dashboard")
    st.caption(f"{total_r} resources scanned · {f_sum['Total']} findings detected · "
               f"{'🤖 Gemini Active' if (api_key and use_ai) else '📋 Fallback Mode'}")

    # KPI row
    c1,c2,c3,c4,c5 = st.columns(5)
    for col,(val,lbl,color) in zip([c1,c2,c3,c4,c5],[
        (f_sum["Critical"],"Critical","#FF3D5A"),
        (f_sum["High"],    "High",    "#FFB800"),
        (f_sum["Medium"],  "Medium",  "#00C8FF"),
        (f_sum["Low"],     "Low",     "#06D6A0"),
        (f_sum["Total"],   "Total",   "#A78BFA"),
    ]):
        with col:
            st.markdown(f'<div class="kpi" style="border-color:{color}"><div class="kn" style="color:{color}">{val}</div><div class="kl">{lbl} Findings</div></div>', unsafe_allow_html=True)

    st.divider()

    # Charts row 1
    r1c1, r1c2 = st.columns(2)
    with r1c1:
        st.markdown('<div class="sh">Findings by Risk Level</div>', unsafe_allow_html=True)
        sdf = pd.DataFrame([{"Level":k,"Count":v} for k,v in f_sum.items() if k!="Total"])
        fig = px.bar(sdf, x="Level", y="Count", color="Level",
                     color_discrete_map=SEV_COLOR, template="plotly_dark")
        fig.update_layout(paper_bgcolor="#0C1A30",plot_bgcolor="#0C1A30",
                          font_color="#C8DCF5",showlegend=False,height=270,
                          margin=dict(l=8,r=8,t=8,b=8))
        fig.update_traces(marker_line_width=0)
        st.plotly_chart(fig, use_container_width=True)

    with r1c2:
        st.markdown('<div class="sh">Findings by Resource Type</div>', unsafe_allow_html=True)
        if not df.empty:
            tc = df.groupby("resource_type").size().reset_index(name="count")
            fig2 = px.pie(tc, names="resource_type", values="count", hole=0.44,
                          color_discrete_sequence=["#FF3D5A","#FFB800","#00C8FF","#06D6A0","#FF6B35"],
                          template="plotly_dark")
            fig2.update_layout(paper_bgcolor="#0C1A30",font_color="#C8DCF5",
                                height=270,margin=dict(l=8,r=8,t=8,b=8))
            st.plotly_chart(fig2, use_container_width=True)

    # Charts row 2
    r2c1, r2c2 = st.columns(2)
    with r2c1:
        st.markdown('<div class="sh">URS Score Distribution</div>', unsafe_allow_html=True)
        if not df.empty:
            fig3 = px.histogram(df, x="urs_score", nbins=20,
                                color_discrete_sequence=["#00C8FF"], template="plotly_dark")
            fig3.update_layout(paper_bgcolor="#0C1A30",plot_bgcolor="#0C1A30",
                                font_color="#C8DCF5",height=250,showlegend=False,
                                xaxis_title="Risk Score (0–100)", yaxis_title="Count",
                                margin=dict(l=8,r=8,t=8,b=8))
            st.plotly_chart(fig3, use_container_width=True)

    with r2c2:
        st.markdown('<div class="sh">Risk by Environment</div>', unsafe_allow_html=True)
        if not df.empty:
            env_df = df.groupby(["environment","urs_label"]).size().reset_index(name="count")
            fig4 = px.bar(env_df, x="environment", y="count", color="urs_label",
                          color_discrete_map=SEV_COLOR, barmode="stack", template="plotly_dark")
            fig4.update_layout(paper_bgcolor="#0C1A30",plot_bgcolor="#0C1A30",
                                font_color="#C8DCF5",height=250,
                                legend=dict(orientation="h",y=1.08),
                                margin=dict(l=8,r=8,t=8,b=8))
            st.plotly_chart(fig4, use_container_width=True)

    # Top findings table
    st.markdown('<div class="sh">Top 10 Highest Risk Findings</div>', unsafe_allow_html=True)
    if not df.empty:
        top10 = df.head(10)[["urs_score","urs_label","resource_type","resource_name","title","environment","owner"]].copy()
        top10.columns = ["URS","Risk Level","Type","Resource","Finding","Env","Owner"]
        st.dataframe(top10.style.applymap(
            lambda v: f"color:{SEV_COLOR.get(v,'#C8DCF5')};font-weight:bold", subset=["Risk Level"]
        ), use_container_width=True, height=320)

    # Cost summary
    st.divider()
    st.markdown('<div class="sh">💸 Cost Optimization Summary</div>', unsafe_allow_html=True)
    cc1,cc2,cc3,cc4 = st.columns(4)
    for col,(val,lbl,color) in zip([cc1,cc2,cc3,cc4],[
        (f"{c_sum['idle_resource_count']}",            "Idle Resources",       "#FFB800"),
        (f"${c_sum['estimated_monthly_saving']:,.0f}", "Monthly Savings Est.", "#06D6A0"),
        (f"${c_sum['estimated_annual_saving']:,.0f}",  "Annual Savings Est.",  "#06D6A0"),
        (f"{c_sum['waste_percentage']}%",              "Waste Reduction",      "#00C8FF"),
    ]):
        with col:
            st.markdown(f'<div class="kpi" style="border-color:{color}"><div class="kn" style="color:{color}">{val}</div><div class="kl">{lbl}</div></div>', unsafe_allow_html=True)


# ══════════════════════════════════════════════
# PAGE 2 — SECURITY FINDINGS
# ══════════════════════════════════════════════
elif page == "🔍 Security Findings":
    st.markdown("## 🔍 Security Findings")
    if df.empty:
        st.info("No findings match the current filters.")
    else:
        st.caption(f"{len(df)} findings · sorted by URS Score (highest risk first)")

        # Gauge + mini charts
        g1, g2, g3 = st.columns([1.1,1.5,1.5])
        top = df.iloc[0]
        with g1:
            gauge = go.Figure(go.Indicator(
                mode="gauge+number", value=top["urs_score"],
                title={"text":"Highest Risk Score","font":{"color":"#C8DCF5","size":11}},
                gauge={"axis":{"range":[0,100],"tickcolor":"#6A8CB0"},
                       "bar":{"color":top["urs_color"]},
                       "bgcolor":"#142244",
                       "steps":[{"range":[0,40],"color":"#0C1A30"},
                                 {"range":[40,60],"color":"#111F3A"},
                                 {"range":[60,80],"color":"#162544"},
                                 {"range":[80,100],"color":"#1e0a0a"}]},
                number={"font":{"color":top["urs_color"],"size":34}},
            ))
            gauge.update_layout(paper_bgcolor="#0C1A30",font_color="#C8DCF5",
                                 height=200,margin=dict(l=10,r=10,t=30,b=10))
            st.plotly_chart(gauge, use_container_width=True)

        with g2:
            owner_df = df.groupby("owner").size().reset_index(name="count")
            fig_o = px.bar(owner_df, x="owner", y="count", template="plotly_dark",
                           color_discrete_sequence=["#FF6B35"])
            fig_o.update_layout(paper_bgcolor="#0C1A30",plot_bgcolor="#0C1A30",
                                  font_color="#C8DCF5",height=200,showlegend=False,
                                  xaxis_title="Team",yaxis_title="Findings",
                                  margin=dict(l=8,r=8,t=8,b=8),xaxis_tickangle=-20)
            st.plotly_chart(fig_o, use_container_width=True)

        with g3:
            cat_df = df.groupby("category").size().reset_index(name="count")
            fig_c = px.pie(cat_df, names="category", values="count", hole=0.4,
                           color_discrete_sequence=["#FF3D5A","#FFB800","#06D6A0"],
                           template="plotly_dark")
            fig_c.update_layout(paper_bgcolor="#0C1A30",font_color="#C8DCF5",
                                  height=200,margin=dict(l=8,r=8,t=8,b=8))
            st.plotly_chart(fig_c, use_container_width=True)

        st.divider()
        quick = st.selectbox("Filter by Risk Level", ["All","Critical","High","Medium","Low"])
        show = df if quick=="All" else df[df["urs_label"]==quick]

        for _, f in show.iterrows():
            color = SEV_COLOR.get(f["urs_label"],"#888")
            icon  = TYPE_ICON.get(f["resource_type"],"☁️")
            st.markdown(f"""
<div class="fc" style="border-color:{color}">
  <div class="ft" style="color:{color}">[{f['check_id']}] {f['title']}</div>
  <div class="fm">{icon} {f['resource_type']} &nbsp;·&nbsp; <b>{f['resource_name']}</b>
    &nbsp;·&nbsp; {f.get('region','—')} &nbsp;·&nbsp; {f.get('owner','—')}
    &nbsp;·&nbsp; {f.get('environment','—')}
    &nbsp;·&nbsp; <b>URS: <span style="color:{f['urs_color']}">{f['urs_score']}</span></b>
    &nbsp;·&nbsp; <span class="badge" style="background:{color}">{f['urs_label']}</span>
    &nbsp;·&nbsp; {f['category']} &nbsp;·&nbsp; ${f['monthly_cost']}/mo
  </div>
  <div class="fd">{f['description']}</div>
  <div class="ff">🔧 <b>Fix:</b> {f['fix']}</div>
  <div class="fr">📚 <b>RAG Source:</b> {f.get('rag_source','Internal Policy')}<br>
    💡 {f.get('rag_context','Follow cloud security best practices.')}<br><br>
    🤖 <b>AI Analysis:</b> {f.get('gemini_explanation','—')}
  </div>
</div>""", unsafe_allow_html=True)

        st.download_button("⬇️ Download Findings CSV",
                           export_findings_csv(show.to_dict("records")),
                           "security_findings.csv","text/csv",use_container_width=True)


# ══════════════════════════════════════════════
# PAGE 3 — COST OPTIMIZATION
# ══════════════════════════════════════════════
elif page == "💸 Cost Optimization":
    st.markdown("## 💸 Cost Optimization")

    c1,c2,c3 = st.columns(3)
    for col,(val,lbl,color) in zip([c1,c2,c3],[
        (f"${c_sum['estimated_monthly_saving']:,.0f}","Estimated Monthly Savings","#06D6A0"),
        (f"${c_sum['estimated_annual_saving']:,.0f}", "Estimated Annual Savings", "#06D6A0"),
        (f"{c_sum['waste_percentage']}%",             "Cloud Waste %",            "#00C8FF"),
    ]):
        with col:
            st.markdown(f'<div class="kpi" style="border-color:{color}"><div class="kn" style="color:{color}">{val}</div><div class="kl">{lbl}</div></div>', unsafe_allow_html=True)

    if cost_opps:
        cdf = pd.DataFrame(cost_opps)

        ch1, ch2 = st.columns(2)
        with ch1:
            st.markdown('<div class="sh">Current Cost vs Potential Saving (per resource)</div>', unsafe_allow_html=True)
            fig_b = px.bar(cdf, x="resource_name",
                           y=["monthly_cost_usd","estimated_monthly_saving"],
                           barmode="group", template="plotly_dark",
                           color_discrete_map={"monthly_cost_usd":"#FF3D5A",
                                               "estimated_monthly_saving":"#06D6A0"})
            fig_b.update_layout(paper_bgcolor="#0C1A30",plot_bgcolor="#0C1A30",
                                  font_color="#C8DCF5",height=310,showlegend=True,
                                  legend=dict(orientation="h",y=1.1),
                                  xaxis_tickangle=-30,
                                  margin=dict(l=8,r=8,t=8,b=60),
                                  xaxis_title="",yaxis_title="USD/month")
            st.plotly_chart(fig_b, use_container_width=True)

        with ch2:
            st.markdown('<div class="sh">Savings Breakdown by Resource Type</div>', unsafe_allow_html=True)
            type_s = cdf.groupby("resource_type")["estimated_annual_saving"].sum().reset_index()
            fig_p = px.pie(type_s, names="resource_type", values="estimated_annual_saving",
                           hole=0.42, template="plotly_dark",
                           color_discrete_sequence=["#06D6A0","#00C8FF","#FFB800","#FF6B35","#FF3D5A"])
            fig_p.update_layout(paper_bgcolor="#0C1A30",font_color="#C8DCF5",
                                  height=310,margin=dict(l=8,r=8,t=8,b=8))
            st.plotly_chart(fig_p, use_container_width=True)

        # Scatter: idle days vs cost
        st.markdown('<div class="sh">Idle Days vs Monthly Cost (bubble size = annual saving)</div>', unsafe_allow_html=True)
        fig_s = px.scatter(cdf, x="idle_days", y="monthly_cost_usd",
                           size="estimated_annual_saving", color="resource_type",
                           hover_name="resource_name", template="plotly_dark",
                           color_discrete_sequence=["#FF3D5A","#FFB800","#00C8FF","#06D6A0","#FF6B35"],
                           labels={"idle_days":"Days Idle","monthly_cost_usd":"Monthly Cost ($)"})
        fig_s.update_layout(paper_bgcolor="#0C1A30",plot_bgcolor="#0C1A30",
                             font_color="#C8DCF5",height=300,
                             margin=dict(l=8,r=8,t=8,b=8))
        st.plotly_chart(fig_s, use_container_width=True)

        # Resource table
        st.markdown('<div class="sh">Resource Action Table</div>', unsafe_allow_html=True)
        tbl = cdf[["resource_name","resource_type","region","owner","environment",
                   "status","idle_days","monthly_cost_usd",
                   "estimated_monthly_saving","estimated_annual_saving","action"]].copy()
        tbl.columns = ["Name","Type","Region","Owner","Env","Status","Idle Days",
                       "Cost $/mo","Save $/mo","Save $/yr","Action"]
        def color_action(v):
            if v=="TERMINATE": return "background:#2a0a10;color:#FF3D5A;font-weight:bold"
            if v=="DELETE":    return "background:#200a28;color:#A78BFA;font-weight:bold"
            return "background:#1a1800;color:#FFB800;font-weight:bold"
        st.dataframe(tbl.style.applymap(color_action,subset=["Action"]),
                     use_container_width=True, height=380)

        # Action cards
        st.markdown('<div class="sh">Recommendations</div>', unsafe_allow_html=True)
        for o in cost_opps:
            ac = "#FF3D5A" if o["action"]=="TERMINATE" else "#A78BFA" if o["action"]=="DELETE" else "#FFB800"
            icon = TYPE_ICON.get(o["resource_type"],"☁️")
            st.markdown(f"""
<div class="fc" style="border-color:{ac}">
  <div class="ft" style="color:{ac}">
    {icon} {o['resource_name']}
    <span class="badge" style="background:{ac};margin-left:8px">{o['action']}</span>
  </div>
  <div class="fm">{o['resource_type']} · {o['region']} · {o['owner']} · env: {o['environment']}
    · <b>Idle: {o['idle_days']} days</b> · <b>${o['monthly_cost_usd']}/mo</b>
  </div>
  <div class="fd">📋 Reason: {o['reason']}</div>
  <div class="ff">💚 Save: <b>${o['estimated_monthly_saving']}/month → ${o['estimated_annual_saving']}/year</b>
    &nbsp;({o['saving_percent']}% reduction)<br>
    {o['suggestion']}
  </div>
</div>""", unsafe_allow_html=True)

        st.download_button("⬇️ Download Cost Report CSV",
                           export_cost_csv(cost_opps),
                           "cost_optimization.csv","text/csv",use_container_width=True)


# ══════════════════════════════════════════════
# PAGE 4 — REPORTS & EXPORT
# ══════════════════════════════════════════════
elif page == "📋 Reports & Export":
    st.markdown("## 📋 Reports & Export")
    st.caption("Download complete security + cost reports in HTML and CSV formats.")

    html = export_html_report(enriched, cost_opps, c_sum, total_r)

    col1,col2,col3 = st.columns(3)
    with col1:
        st.download_button("⬇️ HTML Security Report", html,
                           "cloud_security_report.html","text/html",use_container_width=True)
    with col2:
        st.download_button("⬇️ Findings CSV",
                           export_findings_csv(enriched),
                           "security_findings.csv","text/csv",use_container_width=True)
    with col3:
        st.download_button("⬇️ Cost Report CSV",
                           export_cost_csv(cost_opps),
                           "cost_optimization.csv","text/csv",use_container_width=True)

    st.divider()
    st.markdown('<div class="sh">Report Preview</div>', unsafe_allow_html=True)
    st.components.v1.html(html, height=850, scrolling=True)
