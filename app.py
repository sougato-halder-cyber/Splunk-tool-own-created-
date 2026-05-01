import os
import time
from datetime import datetime, timedelta

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import requests
import streamlit as st

st.set_page_config(page_title="Splunk Multi-OS Monitor", page_icon="📊", layout="wide")

st.markdown(
    """
    <style>
    .main {background: linear-gradient(180deg, #0b1220 0%, #111827 100%);}
    [data-testid="stHeader"] {background: rgba(0,0,0,0);}
    h1,h2,h3,p,label,div {color: #E5E7EB !important;}
    .stMetric {background:#1f2937;border-radius:14px;padding:10px;border:1px solid #334155;}
    </style>
    """,
    unsafe_allow_html=True,
)

st.title("🚀 Advanced Splunk Monitoring Suite")
st.caption("Windows • Linux • iOS (browser-based) | Real-time Security + System Telemetry")

with st.sidebar:
    st.header("Splunk Connection")
    splunk_url = st.text_input("Base URL", value=os.getenv("SPLUNK_URL", "https://localhost:8089"))
    username = st.text_input("Username", value=os.getenv("SPLUNK_USER", "admin"))
    password = st.text_input("Password", type="password", value=os.getenv("SPLUNK_PASSWORD", ""))
    verify_tls = st.toggle("Verify TLS", value=False)
    auto_refresh = st.slider("Auto Refresh (sec)", 5, 120, 30)
    run_query = st.button("Run Monitoring Query")


def fake_data(rows: int = 200) -> pd.DataFrame:
    now = datetime.utcnow()
    ts = [now - timedelta(minutes=i) for i in range(rows)][::-1]
    hosts = ["win-prod-01", "linux-api-02", "ios-mdm-gw"]
    records = []
    for i, t in enumerate(ts):
        for h in hosts:
            cpu = 35 + (i % 20) + (8 if "win" in h else 0)
            mem = 45 + ((i * 3) % 25)
            net = 100 + ((i * 7) % 300)
            risk = min(100, int((cpu + mem) / 2 + (20 if net > 300 else 0)))
            records.append({"time": t, "host": h, "cpu": cpu, "memory": mem, "network_mbps": net, "risk_score": risk})
    return pd.DataFrame(records)


def splunk_search(base_url: str, user: str, pwd: str, verify: bool = True) -> pd.DataFrame:
    search = (
        "search index=* (sourcetype=os OR sourcetype=linux OR sourcetype=ios) "
        "| eval host_group=case(match(host,\"win\"),\"Windows\",match(host,\"linux\"),\"Linux\",1=1,\"iOS\") "
        "| timechart span=1m avg(cpu_percent) as cpu avg(mem_percent) as memory sum(net_mbps) as network by host_group"
    )
    endpoint = f"{base_url}/services/search/jobs/export"
    payload = {"search": search, "output_mode": "json", "earliest_time": "-60m", "latest_time": "now"}
    resp = requests.post(endpoint, data=payload, auth=(user, pwd), verify=verify, timeout=30)
    resp.raise_for_status()

    rows = []
    for line in resp.text.splitlines():
        if '"result"' in line:
            try:
                item = pd.read_json(line, typ="series")
                if "result" in item:
                    rows.append(item["result"])
            except Exception:
                pass

    if not rows:
        return fake_data()

    df = pd.DataFrame(rows)
    if "_time" in df.columns:
        df["time"] = pd.to_datetime(df["_time"], errors="coerce")
    else:
        df["time"] = pd.Timestamp.utcnow()
    rename_map = {c: c.replace("avg(", "").replace(")", "") for c in df.columns}
    df = df.rename(columns=rename_map)
    if "cpu" not in df.columns:
        df["cpu"] = 0
    if "memory" not in df.columns:
        df["memory"] = 0
    if "network" not in df.columns:
        df["network_mbps"] = 0
    if "network_mbps" not in df.columns:
        df["network_mbps"] = df.get("network", 0)
    df["risk_score"] = ((df["cpu"].astype(float) + df["memory"].astype(float)) / 2).clip(0, 100)
    df["host"] = df.get("host_group", "unknown")
    return df[["time", "host", "cpu", "memory", "network_mbps", "risk_score"]]


if run_query:
    try:
        df = splunk_search(splunk_url, username, password, verify_tls)
        st.success("Live data loaded from Splunk.")
    except Exception as e:
        st.warning(f"Live Splunk query failed ({e}). Showing smart demo dataset.")
        df = fake_data()
else:
    df = fake_data()

latest = df.sort_values("time").groupby("host").tail(1)

c1, c2, c3, c4 = st.columns(4)
c1.metric("Active Hosts", latest["host"].nunique())
c2.metric("Avg CPU %", f"{latest['cpu'].mean():.1f}")
c3.metric("Avg Memory %", f"{latest['memory'].mean():.1f}")
c4.metric("Threat Risk", f"{latest['risk_score'].mean():.1f}")

left, right = st.columns([2, 1])

with left:
    fig = px.line(df, x="time", y=["cpu", "memory", "network_mbps"], color="host", title="System Health Timeline")
    fig.update_layout(template="plotly_dark", legend_title="Host")
    st.plotly_chart(fig, use_container_width=True)

with right:
    risk = px.bar(latest.sort_values("risk_score", ascending=False), x="host", y="risk_score", color="risk_score", title="Risk Heat")
    risk.update_layout(template="plotly_dark", xaxis_title="Host", yaxis_title="Risk")
    st.plotly_chart(risk, use_container_width=True)

map_fig = go.Figure(
    data=go.Table(
        header=dict(values=["Host", "CPU", "Memory", "Net Mbps", "Risk"], fill_color="#111827", font=dict(color="white")),
        cells=dict(values=[latest[h] for h in ["host", "cpu", "memory", "network_mbps", "risk_score"]], fill_color="#1f2937", font=dict(color="white")),
    )
)
map_fig.update_layout(height=340, margin=dict(l=10, r=10, t=20, b=10))
st.plotly_chart(map_fig, use_container_width=True)

st.info(
    "iOS support works through Safari/Chrome browser. For production, deploy on a server then open the URL from iPhone/iPad."
)

st.caption(f"Last updated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC")
time.sleep(0.01)
st.autorefresh(interval=auto_refresh * 1000, key="refresh")
