# Splunk-tool-own-created-

Advanced cross-platform Splunk monitoring tool with beautiful graphical interface.

## Features
- Runs on **Windows, Linux, and iOS** (iOS via browser).
- Modern dashboard UI (dark theme + live charts).
- Splunk API integration for live monitoring.
- Fallback demo dataset when Splunk is unavailable.
- Security risk scoring and host-level analytics.

## Quick Start
```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\\Scripts\\activate
pip install -r requirements.txt
streamlit run app.py
```

Open the shown local URL on Windows/Linux, or open the hosted URL in Safari on iOS.

## Splunk Connection
Set env vars (optional):
- `SPLUNK_URL`
- `SPLUNK_USER`
- `SPLUNK_PASSWORD`

Then click **Run Monitoring Query** in the sidebar.
