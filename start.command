#!/bin/zsh
# Double-click this file to start the OSINT SIEM dashboard.
cd "$(dirname "$0")"
source venv/bin/activate
streamlit run app.py
