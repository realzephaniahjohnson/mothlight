# app.py - OSINT Threat Intel SIEM (the web app)
# Run it with:  streamlit run app.py
#
# Pages:
#   Overview      - KPIs, alert queue, threat map, live feeds
#   Alerts        - every detection, filterable by severity
#   Search        - query all data with KQL, SPL, or SQL
#   Investigate   - check an IP, CVE, email, phone number, or domain
#   Honeypot      - attacks against our honeypot
#   Connectors    - health of every data source

import html
import re
import threading
import time
from datetime import datetime, timezone

import pandas as pd
import plotly.express as px
import streamlit as st
from dotenv import load_dotenv

import checks
import feeds
import globe3d
import legal
import query_engine as qe

load_dotenv()
st.set_page_config(page_title="Mothlight", page_icon=":material/emoji_nature:", layout="wide")

# Neon moth logo (inline SVG)
MOTH_LOGO = (
    '<svg width="38" height="38" viewBox="0 0 64 64" xmlns="http://www.w3.org/2000/svg" aria-label="Mothlight logo">'
    '<defs><radialGradient id="mlw" cx="70%" cy="30%" r="90%">'
    '<stop offset="0%" stop-color="#D0ECFF"/><stop offset="50%" stop-color="#4DA8FF"/>'
    '<stop offset="100%" stop-color="#1F4FC9"/></radialGradient>'
    '<radialGradient id="mll"><stop offset="0%" stop-color="#FFF4E6"/><stop offset="100%" stop-color="#9ED8FF" stop-opacity="0"/></radialGradient></defs>'
    '<circle cx="32" cy="7" r="7" fill="url(#mll)"/><circle cx="32" cy="7" r="2.6" fill="#FFF4E6"/>'
    '<path d="M31 26 L5 17 C2 30, 12 38, 31 34 Z" fill="url(#mlw)"/>'
    '<path d="M33 26 L59 17 C62 30, 52 38, 33 34 Z" fill="url(#mlw)"/>'
    '<path d="M31 35 C22 38, 15 47, 21 51 C27 54, 30 44, 31.5 39 Z" fill="#3D7CF0"/>'
    '<path d="M33 35 C42 38, 49 47, 43 51 C37 54, 34 44, 32.5 39 Z" fill="#3D7CF0"/>'
    '<path d="M14 25 L24 28 M50 25 L40 28" stroke="#D0ECFF" stroke-width="1.4" stroke-linecap="round" opacity="0.7"/>'
    '<ellipse cx="32" cy="36" rx="2.8" ry="12" fill="#0B1633" stroke="#E6F0FF" stroke-width="1.2"/>'
    '<path d="M31 25 C29 20, 26 17, 23 16 M33 25 C35 20, 38 17, 41 16" stroke="#E6F0FF" stroke-width="1.3" fill="none" stroke-linecap="round"/>'
    '</svg>'
)

RED, ORANGE, YELLOW, GREEN = "#FF4D6D", "#FF9F43", "#FFD166", "#3FB950"
HONEYPOT_LOCATION = (45.50, -73.57)  # Our Cowrie honeypot: Oracle Cloud, Montreal (ca-montreal-1)
SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
# Neon colors: (glow, text) for each severity, and glow colors for signals and statuses
SEVERITY_STYLE = {"Critical": ("#FF2E63", "#FF9DB3"), "High": ("#FF7A2E", "#FFC1A0"),
                  "Medium": ("#FFB020", "#FFDD99"), "Low": ("#FFE66D", "#FFF3B0")}
SIGNAL_COLOR = {"danger": "#FF2E63", "warning": "#FF9F43", "ok": "#39FF88", "info": "#4DD7FF"}
NEON_GREEN, NEON_RED, NEON_GRAY = "#39FF88", "#FF2E63", "#66758C"


KEY_ENV = {"AbuseIPDB": "ABUSEIPDB_API_KEY", "IPQualityScore": "IPQS_API_KEY", "data.gov": "DATA_GOV_API_KEY",
           "Ransomware.live": "RANSOMWARE_LIVE_API_KEY"}
SECRET_NAMES = tuple(KEY_ENV.values())


def redact(text):
    """Strip API keys out of error messages before they're shown (request URLs can contain them)."""
    text = str(text)
    for name in SECRET_NAMES:
        for secret in (feeds.get_secret(name), feeds.get_key(name)):
            if secret:
                text = text.replace(secret, "[redacted]")
    return re.sub(r"(api_?key|key|token)=[^&\s'\"]+", r"\1=[redacted]", text, flags=re.IGNORECASE)


def csv_safe(df):
    """Exported CSVs: stop feed text that starts with = + - @ from running as a formula in Excel/Sheets."""
    out = df.copy()
    for col in out.columns:
        if pd.api.types.is_object_dtype(out[col]) or pd.api.types.is_string_dtype(out[col]):
            out[col] = out[col].map(lambda v: "'" + v if isinstance(v, str) and v[:1] in ("=", "+", "-", "@", "\t", "\r") else v)
    return out.to_csv(index=False)


@st.cache_resource
def rate_counters():
    """Shared across every visitor, so opening new tabs can't get around the site-wide limits."""
    return {"lock": threading.Lock(), "hits": {}}


def allow(action, per_visitor, site_wide, window):
    """Rate limit: at most `per_visitor` per session and `site_wide` across everyone, per `window` seconds.
    Only timestamps are kept, never what was searched."""
    now = time.time()
    mine = [t for t in st.session_state.setdefault("rate_hits", {}).get(action, []) if now - t < window]
    if len(mine) >= per_visitor:
        return False
    counters = rate_counters()
    with counters["lock"]:
        everyone = [t for t in counters["hits"].get(action, []) if now - t < window]
        if len(everyone) >= site_wide:
            counters["hits"][action] = everyone
            return False
        counters["hits"][action] = everyone + [now]
    st.session_state.rate_hits[action] = mine + [now]
    return True


def esc(value):
    return html.escape("" if value is None or (isinstance(value, float) and pd.isna(value)) else str(value))


def neon_dot(color, pulse=False, size=9):
    return (f'<span class="neon{" pulse" if pulse else ""}" '
            f'style="--c:{color};width:{size}px;height:{size}px"></span>')


def sev_badge(severity):
    glow, text = SEVERITY_STYLE[severity]
    return (f'<span class="sev" style="--c:{glow};--t:{text}">'
            f'{neon_dot(glow, pulse=severity in ("Critical", "High"))}{severity}</span>')


def status_badge(text, color, pulse=False):
    return f'<span class="stat" style="--c:{color}">{neon_dot(color, pulse)}{esc(text)}</span>'


def html_table(headers, rows, height=None):
    """A styled, scrollable table. Cells must already be HTML-escaped."""
    head = "".join(f"<th>{h}</th>" for h in headers)
    body = "".join("<tr>" + "".join(row) + "</tr>" for row in rows)
    style = f' style="max-height:{height}px"' if height else ""
    st.markdown(f'<div class="siem-table-wrap"{style}><table class="siem-table"><thead><tr>{head}</tr></thead>'
                f'<tbody>{body}</tbody></table></div>', unsafe_allow_html=True)

# Night-sky theme to match the globe: deep space background, stars, blue glow
STARS = "https://cdn.jsdelivr.net/npm/three-globe/example/img/night-sky.png"
st.markdown(f"""
<style>
/* Whole app: stars with soft blue nebula glows */
.stApp, [data-testid="stAppViewContainer"] {{
  background:
    radial-gradient(ellipse 60% 45% at 15% 0%, rgba(56,132,255,0.20), transparent 70%),
    radial-gradient(ellipse 50% 40% at 95% 100%, rgba(0,200,255,0.13), transparent 70%),
    linear-gradient(rgba(3,6,14,0.78), rgba(3,6,14,0.78)),
    url("{STARS}") center / cover fixed,
    #03060E;
}}
[data-testid="stHeader"] {{background: transparent;}}
[data-testid="stSidebar"] {{
  background: rgba(8,14,30,0.82); backdrop-filter: blur(8px);
  border-right: 1px solid rgba(77,159,255,0.20);
}}
.block-container {{padding-top: 1.5rem; padding-bottom: 2rem;}}
h1, h2, h3 {{letter-spacing: 0.01em;}}
h1 {{background: linear-gradient(90deg, #FFFFFF, #A9D1FF); -webkit-background-clip: text; color: transparent !important;}}
textarea, code, pre {{font-family: "SF Mono", Menlo, Consolas, monospace !important;}}

/* Cards, tables, inputs: dark glass with blue edges */
[data-testid="stMetric"] {{
  background: rgba(12,22,42,0.65); border: 1px solid rgba(77,159,255,0.22) !important;
  border-radius: 10px; box-shadow: 0 0 18px rgba(56,132,255,0.08);
}}
[data-testid="stMetricValue"] {{color: #E6F0FF;}}
[data-testid="stDataFrame"], [data-testid="stExpander"], [data-testid="stFileUploaderDropzone"],
[data-testid="stTextArea"] textarea, [data-testid="stTextInput"] input {{
  border-color: rgba(77,159,255,0.22) !important; border-radius: 8px;
}}
[data-testid="stExpander"] details {{background: rgba(12,22,42,0.55); border-color: rgba(77,159,255,0.22);}}
iframe {{border-radius: 10px; box-shadow: 0 0 30px rgba(56,132,255,0.18);}}

/* Status bar */
.statusbar {{display: flex; flex-wrap: wrap; gap: 1.4rem; align-items: center; font-family: "SF Mono", Menlo, monospace;
  font-size: 0.78rem; padding: 0.5rem 0.9rem; border: 1px solid rgba(77,159,255,0.25); border-radius: 8px;
  margin-bottom: 1rem; background: rgba(12,22,42,0.6);}}
.statusbar .ok {{color: #3FB950;}} .statusbar .bad {{color: #FF4D6D;}} .statusbar .warn {{color: #FFB347;}}
.statusbar .dim {{color: #8FA6C8;}}

/* Neon indicators */
.neon {{display: inline-block; border-radius: 50%; background: var(--c); flex: none;
  box-shadow: 0 0 3px var(--c), 0 0 8px var(--c), 0 0 16px var(--c);}}
.pulse {{animation: neonpulse 1.6s ease-in-out infinite;}}
@keyframes neonpulse {{0%, 100% {{opacity: 1; transform: scale(1);}} 50% {{opacity: 0.55; transform: scale(0.8);}}}}
.sev {{display: inline-flex; align-items: center; gap: 8px; font: 600 0.72rem/1 "SF Mono", Menlo, monospace;
  letter-spacing: 0.08em; text-transform: uppercase; color: var(--t); text-shadow: 0 0 8px var(--c);}}
.stat {{display: inline-flex; align-items: center; gap: 8px;}}
.signal {{display: flex; align-items: baseline; gap: 10px; margin: 7px 0;}}
.signal .neon {{position: relative; top: -1px;}}
.brand {{display: flex; align-items: center; gap: 12px; margin: 0.2rem 0 0.6rem;}}
.brand svg {{filter: drop-shadow(0 0 6px rgba(77,168,255,0.85)) drop-shadow(0 0 14px rgba(77,159,255,0.5));
  animation: mothglow 3s ease-in-out infinite;}}
@keyframes mothglow {{0%, 100% {{opacity: 1;}} 50% {{opacity: 0.72;}}}}
.brand-name {{font-weight: 800; font-size: 1.2rem; letter-spacing: 0.18em; color: #E6F0FF;
  text-shadow: 0 0 12px rgba(77,159,255,0.7);}}
.brand-tag {{font-size: 0.68rem; letter-spacing: 0.06em; color: #8FB0DB; margin-top: 2px;}}

/* Severity count cards */
.sevcards {{display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 12px; margin-bottom: 1rem;}}
.sevcard {{display: flex; align-items: center; gap: 14px; padding: 14px 16px; border-radius: 10px;
  background: rgba(12,22,42,0.65); border: 1px solid color-mix(in srgb, var(--c) 45%, transparent);
  box-shadow: 0 0 18px color-mix(in srgb, var(--c) 16%, transparent), inset 0 0 14px color-mix(in srgb, var(--c) 8%, transparent);}}
.sevcard-label {{font: 600 0.72rem "SF Mono", Menlo, monospace; letter-spacing: 0.08em; text-transform: uppercase;
  color: var(--c); text-shadow: 0 0 8px var(--c);}}
.sevcard-num {{font-size: 1.8rem; font-weight: 600; color: #EEF5FF; line-height: 1.15;}}

/* SIEM tables */
.siem-table-wrap {{overflow: auto; border: 1px solid rgba(77,159,255,0.22); border-radius: 10px;
  background: rgba(12,22,42,0.55); margin-bottom: 0.8rem;}}
.siem-table {{width: 100%; border-collapse: collapse; font-size: 0.84rem;}}
.siem-table th {{position: sticky; top: 0; z-index: 1; background: rgba(14,26,50,0.98); color: #A3BEE3; text-align: left;
  font: 600 0.7rem "SF Mono", Menlo, monospace; letter-spacing: 0.07em; text-transform: uppercase; padding: 10px 12px;
  border-bottom: 1px solid rgba(77,159,255,0.25);}}
.siem-table td {{padding: 8px 12px; border-bottom: 1px solid rgba(77,159,255,0.08); color: #DDE8FB; vertical-align: middle;}}
.siem-table tr:hover td {{background: rgba(77,159,255,0.07);}}
.siem-table td.mono {{font-family: "SF Mono", Menlo, monospace; font-size: 0.8rem; color: #C2DCFF; white-space: nowrap;}}
.siem-table td.dim {{color: #8FA6C8; white-space: nowrap;}}
.siem-table td.nowrap {{white-space: nowrap;}}
.siem-table td.clip {{max-width: 460px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;}}
.siem-table a {{color: #7CC0FF;}}
.statusbar .ok, .statusbar .bad, .statusbar .warn {{text-shadow: 0 0 8px currentColor;}}

/* Investigate verdict banner */
.verdict {{padding: 0.9rem 1.1rem; border-radius: 8px; font-size: 1.05rem; margin-bottom: 0.8rem; border: 1px solid;}}
.verdict.malicious {{background: rgba(255,46,99,0.12); border-color: #FF2E63; box-shadow: 0 0 22px rgba(255,46,99,0.28);}}
.verdict.suspicious {{background: rgba(255,159,67,0.12); border-color: #FF9F43; box-shadow: 0 0 22px rgba(255,159,67,0.25);}}
.verdict.clean {{background: rgba(57,255,136,0.08); border-color: #39FF88; box-shadow: 0 0 22px rgba(57,255,136,0.2);}}
.verdict b {{text-shadow: 0 0 10px currentColor;}}

/* Phones */
@media (max-width: 640px) {{
  .block-container {{padding: 0.9rem 0.75rem 2.5rem;}}
  h1 {{font-size: 2rem !important;}}
  h3 {{font-size: 1.15rem !important;}}
  .statusbar {{gap: 0.35rem 0.9rem; font-size: 0.68rem; padding: 0.45rem 0.7rem; margin-bottom: 0.7rem;}}
  .sevcards {{grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 8px;}}
  .sevcard {{padding: 10px 12px; gap: 10px;}}
  .sevcard-num {{font-size: 1.35rem;}}
  .st-key-kpis [data-testid="stHorizontalBlock"] {{flex-direction: row !important; flex-wrap: wrap !important;
    gap: 0.5rem !important;}}
  .st-key-kpis [data-testid="stColumn"] {{flex: 1 1 calc(50% - 0.5rem) !important; min-width: calc(50% - 0.5rem) !important;
    width: calc(50% - 0.5rem) !important;}}
  [data-testid="stMetric"] {{padding: 0.55rem 0.75rem;}}
  [data-testid="stMetricValue"] {{font-size: 1.35rem;}}
  [data-testid="stMetricLabel"] p {{font-size: 0.75rem;}}
  iframe {{height: 430px !important;}}
  [data-testid="stElementContainer"]:has(> iframe) {{flex: 0 0 auto !important; height: auto !important;
    min-height: 0 !important;}}
  .siem-table-wrap {{overflow-x: auto; -webkit-overflow-scrolling: touch;}}
  .siem-table {{font-size: 0.72rem;}}
  .siem-table th, .siem-table td {{padding: 6px 8px;}}
  .verdict {{font-size: 0.85rem; word-break: break-all;}}
}}
</style>
""", unsafe_allow_html=True)


# =============================================================================
# Data connectors
# =============================================================================
#  table name        display name                 what it is                    loader                       refresh
CONNECTORS = [
    ("kev", "CISA KEV", "Exploited vulnerabilities", feeds.get_kev, "1 hour", feeds.KEV_URL),
    ("epss", "FIRST EPSS", "Exploit likelihood for every KEV CVE", feeds.get_epss, "12 hours", "https://www.first.org/epss/"),
    ("malicious_ips", "IPsum", "Malicious IPs", feeds.get_ipsum, "6 hours", feeds.IPSUM_URL),
    ("botnet_c2", "abuse.ch Feodo Tracker", "Botnet C2 servers", feeds.get_feodo, "6 hours", feeds.FEODO_URL),
    ("attack_reports", "blocklist.de", "Attacks by type (SSH, web, mail...)", feeds.get_blocklist_de, "6 hours",
     "https://www.blocklist.de/en/export.html"),
    ("cins_army", "CINS Army", "Scanners and poorly rated IPs", feeds.get_cins, "6 hours", feeds.CINS_URL),
    ("tor_exits", "Tor Project", "Tor exit nodes", feeds.get_tor_exits, "6 hours", feeds.TOR_EXITS_URL),
    ("greensnow", "GreenSnow", "Brute-force and scanning IPs", feeds.get_greensnow, "6 hours", feeds.GREENSNOW_URL),
    ("binary_defense", "Binary Defense", "IPs hitting their honeypots", feeds.get_binary_defense, "6 hours",
     feeds.BINARY_DEFENSE_URL),
    ("top_attacking_subnets", "SANS ISC DShield", "Top 20 attacking networks", feeds.get_dshield_subnets, "3 hours",
     feeds.DSHIELD_URL),
    ("dshield_top_ips", "SANS ISC DShield", "Top 1,000 attacking IPs worldwide", feeds.get_dshield_top_ips, "3 hours",
     "https://isc.sans.edu/api/"),
    ("ip_country", "IPtoASN (ip-location-db)", "Country for every IP (public domain)", feeds.get_ip_country_table,
     "24 hours", feeds.IP_COUNTRY_URL),
    ("hijacked_netblocks", "Spamhaus DROP", "Hijacked or criminal-run networks", feeds.get_spamhaus_drop, "12 hours",
     feeds.SPAMHAUS_DROP_URL),
    ("phishing_urls", "OpenPhish", "Phishing URLs", feeds.get_openphish, "6 hours", feeds.OPENPHISH_URL),
    ("phishing_domains", "Phishing Army + CERT Polska", "Phishing and scam domains", feeds.get_phishing_domains,
     "6 hours", feeds.PHISHING_ARMY_URL),
    ("ransomware_victims", "Ransomware.live", "Latest ransomware leak-site victims", feeds.get_ransomware_victims,
     "1 hour", "https://www.ransomware.live"),
    ("data_breaches", "Have I Been Pwned", "Public data breaches", feeds.get_breaches, "12 hours",
     "https://haveibeenpwned.com/PwnedWebsites"),
    ("scam_calls", "FTC Do Not Call", "Scam and robocall reports", feeds.get_ftc_complaints, "6 hours",
     "https://www.ftc.gov/policy-notices/open-government/data-sets/do-not-call-data"),
    ("disposable_domains", "Disposable email domains", "Throwaway email providers", feeds.get_disposable_domains,
     "24 hours", feeds.DISPOSABLE_URL),
]
LOADERS = {c[0]: c[3] for c in CONNECTORS}


@st.cache_resource(ttl=600, show_spinner=False)
def load_connector(key):
    """Load one feed. If it fails, remember the error for 10 minutes instead of retrying every click."""
    try:
        return LOADERS[key](), None, datetime.now(timezone.utc)
    except Exception as error:
        detail = f"{type(error).__name__}: {error}" if str(error) else type(error).__name__
        return None, redact(detail)[:160], datetime.now(timezone.utc)


@st.cache_resource(ttl=3600, max_entries=3, show_spinner="Indexing data for search...")
def get_database(version, _tables):
    """Build the searchable database. 'version' changes whenever the data does."""
    conn = qe.build_database(_tables)
    return conn, qe.get_schema(conn)


def minutes_ago(when):
    """'5 min ago', '3 h ago', or '2 days ago' for a UTC timestamp."""
    minutes = max(0, int((pd.Timestamp.now(tz="UTC") - when).total_seconds() // 60))
    if minutes < 60:
        return f"{minutes} min ago"
    if minutes < 48 * 60:
        return f"{minutes // 60} h ago"
    return f"{minutes // 1440} days ago"


def naive(series):
    """Make every timestamp plain UTC so different feeds can be compared."""
    series = pd.to_datetime(series, errors="coerce", utc=True)
    return series.dt.tz_localize(None)


def format_phone(digits):
    return f"({digits[:3]}) {digits[3:6]}-{digits[6:]}" if len(digits) == 10 else digits


# =============================================================================
# Combined IP intelligence: every IP feed merged into one table
# =============================================================================
GROUP_ORDER = ["Botnet C2", "Brute force", "Web attacks", "Spam & mail", "Scanner", "Tor exit", "Blocklisted"]
ATTACK_GROUP = {"SSH brute force": "Brute force", "Login brute force": "Brute force", "FTP brute force": "Brute force",
                "Mail brute force": "Brute force", "VoIP (SIP) attacks": "Brute force",
                "Persistent attacker": "Brute force", "Web attacks": "Web attacks", "Bad bots": "Web attacks",
                "Spam / mail abuse": "Spam & mail", "Scanner (CINS)": "Scanner", "Tor exit": "Tor exit",
                "Botnet C2": "Botnet C2", "Blocklisted": "Blocklisted",
                "Brute force (GreenSnow)": "Brute force", "Honeypot attacker (Binary Defense)": "Brute force",
                "Top attacker (DShield)": "Scanner"}


@st.cache_resource(ttl=3600, show_spinner="Combining IP feeds...")
def build_ip_intel(version, _data):
    """One row per IP: which feeds list it, its attack types, blocklist score, and a risk score."""
    tagged = []
    feodo = _data["botnet_c2"]
    if feodo is not None and not feodo.empty:
        tagged.append(pd.DataFrame({"ip": feodo["ip_address"], "tag": "Botnet C2"}))
    if _data["attack_reports"] is not None:
        tagged.append(_data["attack_reports"].rename(columns={"attack_type": "tag"}))
    if _data["cins_army"] is not None:
        tagged.append(_data["cins_army"].assign(tag="Scanner (CINS)"))
    if _data["tor_exits"] is not None:
        tagged.append(_data["tor_exits"].assign(tag="Tor exit"))
    if _data["greensnow"] is not None:
        tagged.append(_data["greensnow"].assign(tag="Brute force (GreenSnow)"))
    if _data["binary_defense"] is not None:
        tagged.append(_data["binary_defense"].assign(tag="Honeypot attacker (Binary Defense)"))
    if _data["dshield_top_ips"] is not None:
        tagged.append(_data["dshield_top_ips"][["ip"]].assign(tag="Top attacker (DShield)"))
    ipsum = _data["malicious_ips"]
    if ipsum is not None:
        tagged.append(ipsum[["ip"]].assign(tag="Blocklisted"))
    if not tagged:
        return pd.DataFrame(columns=["ip", "country", "group", "tags", "attack_types", "score", "risk"])

    df = pd.concat(tagged, ignore_index=True).drop_duplicates()
    intel = df.groupby("ip")["tag"].agg(lambda t: "; ".join(sorted(set(t)))).rename("tags").reset_index()
    attack_types = df[~df["tag"].isin(["Blocklisted", "Tor exit"])].groupby("ip")["tag"].nunique()
    intel["attack_types"] = intel["ip"].map(attack_types).fillna(0).astype(int)
    intel["score"] = intel["ip"].map(ipsum.set_index("ip")["score"]).fillna(0).astype(int) if ipsum is not None else 0

    def primary(tags):
        groups = {ATTACK_GROUP.get(t, "Blocklisted") for t in tags.split("; ")}
        return next(g for g in GROUP_ORDER if g in groups)

    intel["group"] = intel["tags"].map(primary)
    intel["risk"] = intel["score"] + 2 * intel["attack_types"] + 10 * intel["tags"].str.contains("Botnet C2")
    intel["country"] = feeds.countries_for(intel["ip"], _data["ip_country"]).values  # registered country
    return intel[["ip", "country", "group", "tags", "attack_types", "score", "risk"]]


MAP_BUDGET = {"Botnet C2": 200, "Brute force": 350, "Web attacks": 220, "Spam & mail": 160,
              "Scanner": 220, "Blocklisted": 250}  # ~1,400 IPs
PER_COUNTRY = 12  # first pass: up to this many IPs per country, so every region shows up


def map_ips(threat_ips, intel):
    """Pick IPs for the globe: the riskiest ones, spread across as many countries as possible."""
    pool = threat_ips
    picks = []
    for group, budget in MAP_BUDGET.items():
        frame = pool[pool["group"] == group].sort_values("risk", ascending=False)
        # Round-robin by country: everyone's #1 first, then everyone's #2...
        frame = frame.assign(turn=frame.groupby(frame["country"].fillna("??")).cumcount())
        picks.append(frame.sort_values(["turn", "risk"], ascending=[True, False]).head(budget).drop(columns="turn"))
    picked = pd.concat(picks)
    geo = feeds.geolocate(tuple(picked["ip"]))
    located = picked.merge(geo.drop(columns=["country"], errors="ignore"), on="ip", how="left")
    # Not looked up yet (free tier limit)? Place it near its country's center for now.
    missing = located["lat"].isna()
    for i in located.index[missing]:
        lat, lon = globe3d.country_point(located.at[i, "country"], located.at[i, "ip"])
        located.at[i, "lat"], located.at[i, "lon"] = lat, lon
    located["isp"] = located["isp"].fillna("Location approximate (country)")
    return located.dropna(subset=["lat", "lon"])


# =============================================================================
# Detections (alert rules)
# =============================================================================
HIGH_IMPACT_VENDORS = {"fortinet", "ivanti", "citrix", "palo alto networks", "cisco", "f5", "sonicwall", "juniper",
                       "check point", "vmware", "microsoft", "progress", "zyxel", "sophos", "atlassian", "apple", "google"}
FINANCIAL_BRANDS = {"paypal.com", "chase.com", "wellsfargo.com", "bankofamerica.com", "coinbase.com", "binance.com",
                    "irs.gov"}
FREE_HOSTING = ("vercel.app", "github.io", "pages.dev", "netlify.app", "workers.dev", "web.app", "firebaseapp.com",
                "weebly.com", "wixsite.com", "glitch.me", "onrender.com", "blogspot.com", "sites.google.com")
CRITICAL_SECTORS = {"healthcare", "hospital", "government", "public sector", "education", "financial services",
                    "finance", "banking", "energy", "utilities", "critical infrastructure", "transportation/logistics"}
CAP = 20  # most alerts per rule, so one noisy rule can't bury the rest


def build_alerts(data, intel, honeypot):
    alerts = []

    def add(severity, rule, entity, details, when, source, lat=None, lon=None):
        alerts.append({"Severity": severity, "Alert": rule, "Entity": entity, "Details": details,
                       "Time": when, "Source": source, "lat": lat, "lon": lon})

    now = pd.Timestamp.now()
    located = feeds._location_cache()

    def where(ip):
        """Map coordinates for an IP, if we've already looked it up."""
        loc = located.get(ip) or {}
        return loc.get("lat"), loc.get("lon")

    # Exploited vulnerabilities
    kev = data["kev"]
    if kev is not None:
        recent = kev[kev["dateAdded"] >= now - pd.Timedelta(days=30)]
        for _, r in recent.iterrows():
            age = (now - r["dateAdded"]).days
            ransomware = r["knownRansomwareCampaignUse"] == "Known"
            high_impact = str(r["vendorProject"]).lower() in HIGH_IMPACT_VENDORS
            epss = r.get("epss")
            likely = pd.notna(epss) and epss >= 0.7
            what = f"{r['vendorProject']} {r['product']}: {r['vulnerabilityName']}"
            if pd.notna(epss):
                what += f" · EPSS {epss:.0%}"
            if ransomware and age <= 7:
                add("Critical", "Ransomware-linked CVE just added to KEV", r["cveID"], what, r["dateAdded"], "CISA KEV")
            elif ransomware:
                add("High", "Ransomware-linked CVE exploited", r["cveID"], what, r["dateAdded"], "CISA KEV")
            elif high_impact and age <= 14:
                add("High", "Exploited CVE in widely used product", r["cveID"], what, r["dateAdded"], "CISA KEV")
            elif likely and age <= 14:
                add("High", "Exploited CVE with high EPSS score", r["cveID"], what, r["dateAdded"], "CISA KEV")
            elif age <= 14:
                add("Medium", "New actively exploited CVE", r["cveID"], what, r["dateAdded"], "CISA KEV")
            else:
                add("Low", "Recently exploited CVE", r["cveID"], what, r["dateAdded"], "CISA KEV")

    # Malicious IPs
    if intel is not None and not intel.empty:
        feodo = data["botnet_c2"]
        if feodo is not None and not feodo.empty:
            for _, r in feodo.head(CAP).iterrows():
                online = str(r.get("status", "")).lower() == "online"
                add("High" if online else "Medium", "Active botnet C2 server" if online else "Botnet C2 server (offline)",
                    r["ip_address"], f"{r.get('malware', 'Unknown')} malware · port {r.get('port', '?')}",
                    r.get("last_online") or now, "Feodo Tracker", *where(r["ip_address"]))
        for _, r in intel[intel["score"] >= 8].nlargest(CAP, "risk").iterrows():
            add("High", "IP on 8+ blocklists", r["ip"], r["tags"], now, "IPsum", *where(r["ip"]))
        multi = intel[(intel["attack_types"] >= 3) & (intel["score"] < 8)]
        for _, r in multi.nlargest(CAP, "risk").iterrows():
            add("Medium", "Multi-vector attacker", r["ip"], r["tags"], now, "blocklist.de", *where(r["ip"]))
        tor = intel[intel["tags"].str.contains("Tor exit") & (intel["score"] >= 3)]
        for _, r in tor.nlargest(CAP // 2, "risk").iterrows():
            add("Low", "Tor exit node with abuse reports", r["ip"], r["tags"], now, "Tor Project", *where(r["ip"]))

    # Scam calls
    calls = data["scam_calls"]
    if calls is not None and not calls.empty:
        counts = calls["phone"].value_counts()
        big = len(calls) >= 10_000  # the API fallback is a much smaller sample
        high_t, medium_t = (60, 25) if big else (8, 3)
        for phone, n in counts[counts >= medium_t].head(CAP).items():
            rows = calls[calls["phone"] == phone]
            topic = rows["subject"].mode().iat[0] if rows["subject"].notna().any() else "Unknown topic"
            robocalls = rows["robocall"].mean()
            state = rows["state"].map(US_STATES).mode()
            lat, lon = globe3d.STATE_CENTERS.get(state.iat[0], (None, None)) if not state.empty else (None, None)
            severity = "High" if n >= high_t else "Medium"
            rule = "Robocall campaign" if robocalls >= 0.8 else "Mass-reported scam number"
            add(severity, rule, format_phone(phone), f"{n} FTC reports · {robocalls:.0%} robocalls · {topic}",
                rows["reported"].max(), "FTC", lat, lon)

    # Phishing
    phish = data["phishing_urls"]
    if phish is not None:
        free_hosted = 0
        for domain in phish["domain"].unique():
            url = phish.loc[phish["domain"] == domain, "url"].iat[0]
            brand = checks.lookalike_brand(domain)
            if brand:
                add("High" if brand in FINANCIAL_BRANDS else "Medium", f"Phishing site impersonating {brand}",
                    domain, url, now, "OpenPhish")
            elif domain.endswith(FREE_HOSTING) and free_hosted < CAP:
                free_hosted += 1
                add("Low", "Phishing page on free hosting", domain, url, now, "OpenPhish")

    # Ransomware leak-site victims
    victims = data["ransomware_victims"]
    if victims is not None and not victims.empty:
        recent = victims[victims["discovered"] >= now - pd.Timedelta(days=7)]
        counts = {"High": 0, "Medium": 0}
        for r in recent.itertuples():
            sector = str(getattr(r, "sector", "") or "")
            important = r.country == "US" or sector.lower() in CRITICAL_SECTORS
            severity = "High" if important else "Medium"
            if counts[severity] >= CAP:
                continue
            counts[severity] += 1
            lat, lon = globe3d.country_point(r.country, r.victim)
            add(severity, "Ransomware victim posted on leak site", r.victim,
                f"{r.gang} · {sector or 'Unknown sector'} · {r.country or '??'}", r.discovered, "Ransomware.live",
                lat, lon)

    # New data breaches
    breaches = data["data_breaches"]
    if breaches is not None and not breaches.empty:
        for r in breaches[breaches["added"] >= now - pd.Timedelta(days=30)].head(CAP).itertuples():
            big = r.accounts >= 1_000_000 or "Passwords" in r.data_exposed
            add("High" if big else "Medium", "New data breach disclosed", r.breach,
                f"{r.accounts:,} accounts · {r.data_exposed}", r.added, "Have I Been Pwned")

    # Top attacking networks
    subnets = data["top_attacking_subnets"]
    if subnets is not None and not subnets.empty:
        for i, r in enumerate(subnets.sort_values("targets", ascending=False).itertuples()):
            add("High" if i < 3 else "Medium", "Top attacking network (DShield)", r.network,
                f"{r.targets:,} targets attacked · {r.name} · {r.country}", now, "DShield", *where(r.start_ip))

    # Honeypot
    if honeypot is not None and not honeypot.empty:
        has_time = "time" in honeypot
        attempts = honeypot.groupby("ip").agg(attempts=("ip", "size"),
                                              last=("time", "max") if has_time else ("ip", "size"))
        last_seen = naive(attempts["last"]) if has_time else pd.Series(now, index=attempts.index)
        info = intel.set_index("ip") if intel is not None else pd.DataFrame()
        for ip, r in attempts.iterrows():
            tags = info["tags"].get(ip, "") if not info.empty else ""
            score = int(info["score"].get(ip, 0)) if not info.empty else 0
            if "Botnet C2" in tags:
                add("Critical", "Botnet C2 server attacked honeypot", ip, f"{r.attempts:,} attempts · {tags}",
                    last_seen[ip], "Honeypot", *where(ip))
            elif score >= 5:
                add("High", "Known-bad IP attacked honeypot", ip, f"{r.attempts:,} attempts · on {score} blocklists",
                    last_seen[ip], "Honeypot", *where(ip))
            elif r.attempts >= 100:
                add("Medium", "High-volume brute force", ip, f"{r.attempts:,} attempts", last_seen[ip],
                    "Honeypot", *where(ip))
            elif "Tor exit" in tags:
                add("Low", "Attack from Tor exit node", ip, f"{r.attempts:,} attempts", last_seen[ip],
                    "Honeypot", *where(ip))

    df = pd.DataFrame(alerts, columns=["Severity", "Alert", "Entity", "Details", "Time", "Source", "lat", "lon"])
    if df.empty:
        return df
    df["Time"] = naive(df["Time"])
    df["rank"] = df["Severity"].map(SEVERITY_ORDER)
    # Within each severity, take turns between rules so one busy rule doesn't fill the top of the queue
    df = df.sort_values("Time", ascending=False)
    df["turn"] = df.groupby(["Severity", "Alert"]).cumcount()
    return (df.sort_values(["rank", "turn", "Time"], ascending=[True, True, False])
              .drop(columns=["rank", "turn"]).reset_index(drop=True))


def show_alerts(df, height=None, details=True):
    headers = ["Severity", "Alert", "Entity"] + (["Details", "Time"] if details else []) + ["Source"]
    rows = []
    for r in df.itertuples():
        row = [f'<td class="nowrap">{sev_badge(r.Severity)}</td>', f'<td class="nowrap">{esc(r.Alert)}</td>',
               f'<td class="mono">{esc(r.Entity)}</td>']
        if details:
            when = r.Time.strftime("%Y-%m-%d %H:%M") if pd.notna(r.Time) else "—"
            row += [f'<td class="clip" title="{esc(r.Details)}">{esc(r.Details)}</td>', f'<td class="dim">{when}</td>']
        row.append(f'<td class="dim">{esc(r.Source)}</td>')
        rows.append(row)
    html_table(headers, rows, height)


# =============================================================================
# Charts
# =============================================================================
US_STATES = {
    "Alabama": "AL", "Alaska": "AK", "Arizona": "AZ", "Arkansas": "AR", "California": "CA", "Colorado": "CO",
    "Connecticut": "CT", "Delaware": "DE", "District of Columbia": "DC", "Florida": "FL", "Georgia": "GA",
    "Hawaii": "HI", "Idaho": "ID", "Illinois": "IL", "Indiana": "IN", "Iowa": "IA", "Kansas": "KS",
    "Kentucky": "KY", "Louisiana": "LA", "Maine": "ME", "Maryland": "MD", "Massachusetts": "MA", "Michigan": "MI",
    "Minnesota": "MN", "Mississippi": "MS", "Missouri": "MO", "Montana": "MT", "Nebraska": "NE", "Nevada": "NV",
    "New Hampshire": "NH", "New Jersey": "NJ", "New Mexico": "NM", "New York": "NY", "North Carolina": "NC",
    "North Dakota": "ND", "Ohio": "OH", "Oklahoma": "OK", "Oregon": "OR", "Pennsylvania": "PA", "Rhode Island": "RI",
    "South Carolina": "SC", "South Dakota": "SD", "Tennessee": "TN", "Texas": "TX", "Utah": "UT", "Vermont": "VT",
    "Virginia": "VA", "Washington": "WA", "West Virginia": "WV", "Wisconsin": "WI", "Wyoming": "WY",
}
CHART_LAYOUT = dict(margin=dict(l=0, r=0, t=10, b=0), paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                    font=dict(color="#C5D5EE"))


def bar_chart(series, label, height=400):
    fig = px.bar(series.sort_values(), orientation="h", labels={"value": label, "index": ""},
                 color_discrete_sequence=[RED])
    fig.update_layout(height=height, showlegend=False, yaxis_title=None, **CHART_LAYOUT)
    return fig


def geo_points(ip_counts, value_col, limit):
    """ip_counts: DataFrame with 'ip' and a numeric column. Adds lat/lon/country."""
    top = ip_counts.nlargest(limit, value_col)
    geo = feeds.geolocate(tuple(top["ip"]))
    return top.merge(geo, on="ip") if not geo.empty else None


def map_with_countries(points, value_col, label):
    if points is None:
        st.info("The location service is busy. Refresh in a minute to see the map.")
        return
    left, right = st.columns([2, 1])
    with left:
        globe3d.show_honeypot_globe(points, HONEYPOT_LOCATION)
    right.plotly_chart(bar_chart(points.groupby("country")[value_col].sum().nlargest(10), label, 560))


# =============================================================================
# Shared state: sidebar, data, alerts
# =============================================================================
with st.sidebar:
    st.markdown(f'<div class="brand">{MOTH_LOGO}<div><div class="brand-name">MOTHLIGHT</div>'
                '<div class="brand-tag">They always come to the light</div></div></div>',
                unsafe_allow_html=True)

data, status = {}, {}
with st.spinner(f"Loading {len(CONNECTORS)} threat feeds... the first load after starting takes about a minute."):
    for key, *_ in CONNECTORS:
        data[key], error, loaded_at = load_connector(key)
        status[key] = (error, loaded_at)

with st.sidebar:
    st.divider()
    min_score = st.slider("Malicious IP threshold", 1, 10, 3,
                          help="How many public blocklists an IP must be on to count as malicious.")
    uploaded = st.file_uploader("Honeypot log (CSV)", type="csv",
                                help="Any CSV with an IP column. Or save it as honeypot.csv in the project folder.")
    if st.button("Refresh all data", width="stretch"):
        if allow("refresh", 1, 1, 900):
            st.cache_data.clear()
            load_connector.clear()
            st.rerun()
        else:
            st.warning("The data was refreshed in the last 15 minutes. Feeds update automatically.")
    with st.expander("Use your own API keys"):
        st.caption("Optional. Adds AbuseIPDB and IPQualityScore checks to Investigate. Your keys stay in this "
                   "browser session only: they're never saved, logged, or shown, and they're gone when you close the tab. "
                   "Everything else works without keys.")
        byo = {"ABUSEIPDB_API_KEY": st.text_input("AbuseIPDB key", type="password", key="byo_abuseipdb",
                                                  autocomplete="new-password"),
               "IPQS_API_KEY": st.text_input("IPQualityScore key", type="password", key="byo_ipqs",
                                             autocomplete="new-password")}
        bad = [n for n, v in byo.items() if v.strip() and not feeds.KEY_FORMAT.match(v.strip())]
        if bad:
            st.error("That doesn't look like an API key (letters and numbers only).")
        st.session_state.user_keys = {n: v.strip() for n, v in byo.items() if v.strip() and n not in bad}
    user_keys = st.session_state.get("user_keys", {})

    def key_status(name):
        if name in user_keys:
            return NEON_GREEN, "yours"
        return (NEON_GREEN, "on") if feeds.get_secret(name) else (NEON_GRAY, "off")

    rows = []
    for label, name in KEY_ENV.items():
        color, state = key_status(name)
        rows.append(status_badge(f"{label} · {state}", color))
    st.markdown('<div style="font-size:0.8rem;color:#8FA6C8;line-height:2">API keys<br>' + "<br>".join(rows) + "</div>",
                unsafe_allow_html=True)
    st.caption("No accounts, ads, or trackers. See Privacy & Terms.")
    st.caption("Built by Zephaniah Johnson, Zakari Gilmer, and Bofelo Gaeonale.")

# Honeypot: an uploaded CSV wins, then the live Cowrie feed, then a local honeypot.csv
honeypot, honeypot_source, honeypot_error = None, None, None
if uploaded is not None:
    try:
        honeypot, honeypot_source = feeds.load_honeypot(uploaded), "upload"
    except Exception as error:
        st.sidebar.error(f"Couldn't read the honeypot file: {redact(error)[:160]}")
if honeypot is None:
    try:
        honeypot = feeds.get_live_honeypot()
        honeypot_source = "live" if honeypot is not None else None
    except Exception as error:
        honeypot_error = redact(error)[:160]
if honeypot is None:
    try:
        honeypot = feeds.load_honeypot()
        honeypot_source = "file" if honeypot is not None else None
    except Exception as error:
        st.sidebar.error(f"Couldn't read honeypot.csv: {redact(error)[:160]}")

# Add EPSS (exploit likelihood) to every exploited CVE
if data["kev"] is not None and data["epss"] is not None:
    data["kev"] = data["kev"].merge(data["epss"].rename(columns={"cve": "cveID", "percentile": "epss_percentile"}),
                                    on="cveID", how="left")

ipsum = data["malicious_ips"]
intel = build_ip_intel(tuple((k, len(v)) for k, v in data.items() if v is not None), data)
# "Malicious" = any attack/C2/scanner feed, or IPsum at or above the threshold. Tor exits alone don't count.
threat_ips = intel[(intel["group"] != "Tor exit") &
                   ~((intel["group"] == "Blocklisted") & (intel["score"] < min_score))]
alerts = build_alerts(data, intel, honeypot)

# Searchable database (rebuilt only when the data changes)
tables = {k: v for k, v in data.items() if v is not None and k != "ip_country"}
tables["ip_intel"] = intel
if honeypot is not None and not honeypot.empty:
    tables["honeypot"] = honeypot
version = tuple((k, len(v)) for k, v in tables.items())
if honeypot is not None:
    version += (int(pd.util.hash_pandas_object(honeypot, index=False).sum()),)
db, schema = get_database(version, tables)

# Status bar shown on every page
healthy = sum(1 for err, _ in status.values() if err is None)
oldest = min(t for _, t in status.values())
high = int(alerts["Severity"].isin(["Critical", "High"]).sum()) if not alerts.empty else 0
live = ("ok", "LIVE") if healthy == len(CONNECTORS) else ("bad", "OFFLINE") if healthy == 0 else ("warn", "DEGRADED")
st.markdown(
    f'<div class="statusbar"><span class="{live[0]}">● {live[1]}</span>'
    f'<span class="{"ok" if healthy == len(CONNECTORS) else "warn"}">Connectors {healthy}/{len(CONNECTORS)} healthy</span>'
    f'<span class="{"bad" if high else "dim"}">{len(alerts)} alerts · {high} critical/high</span>'
    f'<span class="dim">Data as of {oldest:%Y-%m-%d %H:%M} UTC</span></div>',
    unsafe_allow_html=True,
)


def count(df):
    return f"{len(df):,}" if df is not None else "—"


# =============================================================================
# Page: Overview
# =============================================================================
def page_overview():
    st.title("Overview")
    phishing_count = sum(len(data[k]) for k in ("phishing_urls", "phishing_domains") if data[k] is not None)
    recent_breaches = data["data_breaches"]
    if recent_breaches is not None:
        recent_breaches = recent_breaches[recent_breaches["added"] >= pd.Timestamp.now() - pd.Timedelta(days=90)]
    kpis = st.container(key="kpis")
    row1, row2 = kpis.columns(4), kpis.columns(4)
    row1[0].metric("Exploited CVEs", count(data["kev"]), border=True)
    row1[1].metric("Malicious IPs", count(threat_ips), border=True,
                   help=f"In any attack, botnet, or scanner feed, or on {min_score}+ blocklists")
    row1[2].metric("Botnet C2", count(data["botnet_c2"]), border=True)
    row1[3].metric("Phishing sites", f"{phishing_count:,}", border=True, help="OpenPhish URLs + phishing domains")
    row2[0].metric("Ransomware victims", count(data["ransomware_victims"]), border=True,
                   help="Latest victims posted on ransomware leak sites")
    row2[1].metric("Breaches (90 days)", count(recent_breaches), border=True, help="Added to Have I Been Pwned")
    row2[2].metric("Scam call reports", count(data["scam_calls"]), border=True, help="FTC reports")
    row2[3].metric("Honeypot attacks", count(honeypot), border=True)

    st.subheader("Threat globe")
    with st.spinner("Locating threats..."):
        points = map_ips(threat_ips, intel)
        calls = data["scam_calls"]
        state_counts = calls["state"].map(US_STATES).value_counts() if calls is not None and not calls.empty else None
        honeypot_points = None
        if honeypot is not None and not honeypot.empty:
            hp_counts = honeypot["ip"].value_counts().rename_axis("ip").reset_index(name="attempts")
            located = feeds.geolocate(tuple(hp_counts["ip"].head(300)))
            honeypot_points = hp_counts.merge(located, on="ip") if not located.empty else None
        if data["top_attacking_subnets"] is not None:
            feeds.geolocate(tuple(data["top_attacking_subnets"]["start_ip"]))
        live_alerts = build_alerts(data, intel, honeypot)  # again, now that more IPs have locations
    heat = threat_ips.dropna(subset=["country"]).groupby(["country", "group"]).size().unstack(fill_value=0)
    globe3d.threat_globe(points, state_counts, live_alerts, honeypot_points, HONEYPOT_LOCATION,
                         victims=data["ransomware_victims"], country_heat=heat)
    shown = len(points) if points is not None else 0
    countries = threat_ips["country"].nunique()
    st.caption(f"Countries glow by how many malicious IPs they host ({len(threat_ips):,} IPs across {countries} countries). "
               f"Spikes are {shown:,} sample IPs spread across those countries, plus ransomware victims, scam calls "
               "by state, and alerts as pulsing rings. "
               "Malicious IP dots are colored by type: red botnet C2, orange brute force, yellow web attacks, "
               "sky blue spam, green scanners, pale blue blocklisted. Tap a layer to show or hide it. "
               "Drag to spin, use ＋/－ to zoom, hover for details.")

    left, right = st.columns([3, 2])
    with left:
        st.subheader("Alert queue")
        if alerts.empty:
            st.success("No open alerts.")
        else:
            show_alerts(alerts.head(15), height=420, details=False)
            if st.button(f"View all {len(alerts)} alerts →"):
                st.switch_page(PAGES["alerts"])
    with right:
        st.subheader("Top source countries")
        if not threat_ips.empty:
            top = threat_ips["country"].value_counts().head(12)
            top.index = [globe3d.COUNTRY_NAMES.get(c, c) for c in top.index]
            st.plotly_chart(bar_chart(top, "Malicious IPs", 330))
        st.subheader("Threats by type")
        if not threat_ips.empty:
            by_group = threat_ips["group"].value_counts().reindex(GROUP_ORDER).dropna()
            fig = px.bar(by_group.sort_values(), orientation="h", color=by_group.sort_values().index,
                         color_discrete_map=globe3d.LAYER_COLORS)
            fig.update_layout(height=280, showlegend=False, yaxis_title=None, xaxis_title="Malicious IPs",
                              **CHART_LAYOUT)
            st.plotly_chart(fig)

    st.subheader("Live threat feeds")
    tabs = st.tabs(["Exploited CVEs", "Malicious IPs", "Botnet C2", "Attacking networks", "Phishing",
                    "Ransomware", "Breaches", "Scam calls"])
    with tabs[0]:
        kev = data["kev"]
        if kev is not None:
            cols = [c for c in ["cveID", "vendorProject", "product", "vulnerabilityName", "dateAdded",
                                "knownRansomwareCampaignUse", "epss"] if c in kev.columns]
            st.dataframe(kev[cols].head(150), hide_index=True,
                         column_config={"cveID": "CVE", "vendorProject": "Vendor", "product": "Product",
                                        "vulnerabilityName": "Name", "knownRansomwareCampaignUse": "Ransomware",
                                        "dateAdded": st.column_config.DateColumn("Added", format="YYYY-MM-DD"),
                                        "epss": st.column_config.ProgressColumn("EPSS", min_value=0, max_value=1,
                                                                                format="percent")})
    with tabs[1]:
        st.dataframe(threat_ips.nlargest(200, "risk"), hide_index=True, column_config={
            "ip": "IP address", "group": "Type", "tags": st.column_config.TextColumn("Seen in", width="large"),
            "attack_types": "Attack types",
            "score": st.column_config.ProgressColumn("Blocklist score", min_value=0, max_value=10, format="%d"),
            "risk": "Risk"})
    with tabs[2]:
        feodo = data["botnet_c2"]
        if feodo is not None and not feodo.empty:
            st.dataframe(feodo, hide_index=True)
        else:
            st.info("No active botnet servers listed right now.")
    with tabs[3]:
        subnets = data["top_attacking_subnets"]
        if subnets is not None:
            st.caption("SANS ISC DShield: the 20 networks that attacked the most sensors in the last 3 days.")
            st.dataframe(subnets.drop(columns="start_ip"), hide_index=True)
        drop = data["hijacked_netblocks"]
        if drop is not None:
            st.caption(f"Spamhaus DROP: {len(drop):,} hijacked or criminal-run networks. Block all traffic to these.")
            st.dataframe(drop, hide_index=True, height=250)
    with tabs[4]:
        if data["phishing_urls"] is not None:
            st.caption("OpenPhish: live phishing URLs")
            st.dataframe(data["phishing_urls"], hide_index=True, height=300,
                         column_config={"url": st.column_config.TextColumn("Phishing URL", width="large")})
        if data["phishing_domains"] is not None:
            st.caption(f"Phishing Army and CERT Polska: {len(data['phishing_domains']):,} phishing and scam domains")
            st.dataframe(data["phishing_domains"].head(1000), hide_index=True, height=300)
    with tabs[5]:
        victims = data["ransomware_victims"]
        if victims is not None:
            gangs = victims["gang"].value_counts().head(10)
            a, b = st.columns([3, 2])
            a.dataframe(victims.drop(columns=["details_url"], errors="ignore"), hide_index=True, height=420,
                        column_config={"discovered": st.column_config.DatetimeColumn("Posted", format="YYYY-MM-DD HH:mm"),
                                       "attack_date": st.column_config.DatetimeColumn("Attacked", format="YYYY-MM-DD")})
            b.markdown("**Most active gangs**")
            b.plotly_chart(bar_chart(gangs, "Victims", 400))
    with tabs[6]:
        breaches = data["data_breaches"]
        if breaches is not None:
            st.dataframe(breaches.head(200), hide_index=True, height=420, column_config={
                "added": st.column_config.DatetimeColumn("Added to HIBP", format="YYYY-MM-DD"),
                "breach_date": st.column_config.DateColumn("Breach date", format="YYYY-MM-DD"),
                "accounts": st.column_config.NumberColumn("Accounts", format="localized"),
                "data_exposed": st.column_config.TextColumn("Data exposed", width="large")})
    with tabs[7]:
        calls = data["scam_calls"]
        if calls is not None and not calls.empty:
            a, b = st.columns(2)
            top_numbers = calls["phone"].value_counts().head(15)
            top_numbers.index = top_numbers.index.map(format_phone)
            a.markdown("**Most-reported numbers**")
            a.plotly_chart(bar_chart(top_numbers, "Reports", 420))
            b.markdown("**What the calls were about**")
            b.plotly_chart(bar_chart(calls["subject"].value_counts().head(10), "Reports", 420))


# =============================================================================
# Page: Alerts
# =============================================================================
def page_alerts():
    st.title("Alerts")
    if alerts.empty:
        st.success("No open alerts.")
        return
    cards = "".join(
        f'<div class="sevcard" style="--c:{SEVERITY_STYLE[sev][0]}">'
        f'{neon_dot(SEVERITY_STYLE[sev][0], pulse=sev in ("Critical", "High"), size=13)}'
        f'<div><div class="sevcard-label">{sev}</div>'
        f'<div class="sevcard-num">{int((alerts["Severity"] == sev).sum())}</div></div></div>'
        for sev in ["Critical", "High", "Medium", "Low"])
    st.markdown(f'<div class="sevcards">{cards}</div>', unsafe_allow_html=True)
    f1, f2 = st.columns(2)
    severities = f1.pills("Severity", ["Critical", "High", "Medium", "Low"], selection_mode="multi",
                          default=["Critical", "High", "Medium", "Low"])
    sources = f2.pills("Source", sorted(alerts["Source"].unique()), selection_mode="multi",
                       default=sorted(alerts["Source"].unique()))
    shown = alerts[alerts["Severity"].isin(severities or []) & alerts["Source"].isin(sources or [])]
    show_alerts(shown, height=620)
    st.download_button("Export alerts (CSV)", csv_safe(shown.drop(columns=["lat", "lon"])),
                       "alerts.csv", "text/csv")
    with st.expander("Detection rules"):
        st.markdown(unsafe_allow_html=True, body=
            "| Severity | Rule |\n|---|---|\n"
            "| " + sev_badge("Critical") + " | Ransomware-linked CVE added to CISA KEV in the last 7 days |\n"
            "| " + sev_badge("Critical") + " | Botnet C2 server attacked our honeypot |\n"
            "| " + sev_badge("High") + " | Ransomware-linked CVE added in the last 30 days |\n"
            "| " + sev_badge("High") + " | Exploited CVE in a widely used product (Fortinet, Ivanti, Cisco, Microsoft...) in the last 14 days |\n"
            "| " + sev_badge("High") + " | Botnet C2 server is online (Feodo Tracker) |\n"
            "| " + sev_badge("High") + " | IP is on 8+ public blocklists |\n"
            "| " + sev_badge("High") + " | Phishing site impersonating a bank, crypto exchange, PayPal, or the IRS |\n"
            "| " + sev_badge("High") + " | Scam number with a large spike in FTC reports |\n"
            "| " + sev_badge("High") + " | IP on 5+ blocklists attacked our honeypot |\n"
            "| " + sev_badge("High") + " | Exploited CVE with a high EPSS score (70%+ chance of exploitation) |\n"
            "| " + sev_badge("High") + " | Ransomware victim in the US or a critical sector (healthcare, government, education, finance, energy) |\n"
            "| " + sev_badge("High") + " | New data breach with 1M+ accounts or exposed passwords |\n"
            "| " + sev_badge("High") + " | One of the top 3 attacking networks today (DShield) |\n"
            "| " + sev_badge("Medium") + " | Any other CVE added in the last 14 days |\n"
            "| " + sev_badge("Medium") + " | Attacker seen doing 3+ kinds of attacks (blocklist.de) |\n"
            "| " + sev_badge("Medium") + " | Phishing site impersonating any other major brand |\n"
            "| " + sev_badge("Medium") + " | Mass-reported scam number |\n"
            "| " + sev_badge("Medium") + " | 100+ attempts from one IP against our honeypot |\n"
            "| " + sev_badge("Medium") + " | Any other new ransomware victim (last 7 days) |\n"
            "| " + sev_badge("Medium") + " | Any other new data breach (last 30 days) |\n"
            "| " + sev_badge("Medium") + " | Other top-20 attacking networks (DShield) |\n"
            "| " + sev_badge("Low") + " | CVE added 15 to 30 days ago |\n"
            "| " + sev_badge("Low") + " | Tor exit node with abuse reports, or attacking our honeypot |\n"
            "| " + sev_badge("Low") + " | Phishing page hosted on a free platform (Vercel, GitHub Pages, Netlify...) |\n\n"
            f"Each rule shows at most {CAP} alerts so one noisy rule can't bury the rest.")


# =============================================================================
# Page: Search (KQL / SPL / SQL)
# =============================================================================
CHEAT_SHEET = {
    "KQL": "table | where col == \"x\" and num > 5 | where col contains \"text\"\n"
           "| project a, b, new = expr | extend x = expr | project-away col\n"
           "| summarize Total = count(), dcount(col) by col, bin(time, 1h)\n"
           "| sort by col desc | top 10 by col | take 10 | distinct col | count\n"
           "Functions: ago(7d), now(), countif(), tolower(), isnotempty(), between (a .. b), in (\"a\",\"b\")",
    "SPL": "index=table field=value field>5 field=wild* NOT field=x \"free text\"\n"
           "| where num > 5 AND like(field, \"%x%\") | search more terms\n"
           "| stats count, dc(field) as unique by field | top limit=5 field | rare field\n"
           "| table a b | fields - a | rename a as b | eval x = expr | dedup field\n"
           "| sort -count | head 10",
    "SQL": "SELECT col, COUNT(*) AS n FROM table WHERE col = 'x' GROUP BY col ORDER BY n DESC LIMIT 10;\n"
           "JOINs, CTEs (WITH), and SQLite functions all work. Read-only.",
}
TIME_COLUMNS = ("time", "dateadded", "reported", "call_time", "first_seen", "last_online", "timestamp")


def set_language():
    st.session_state.query_text = next(iter(qe.EXAMPLES[st.session_state.lang].values()))
    st.session_state.search_result = None


def load_example():
    name = st.session_state.example
    if name:
        st.session_state.query_text = qe.EXAMPLES[st.session_state.lang][name]
        st.session_state.example = None


def run_search():
    st.session_state.saved_query = st.session_state.query_text
    if not allow("search", 20, 400, 60):
        st.session_state.search_result = {"error": "Too many searches in the last minute. Wait a moment and try again."}
        return
    try:
        results, sql, ms = qe.run_query(db, st.session_state.lang, st.session_state.query_text)
        st.session_state.search_result = {"df": results, "sql": sql, "ms": ms}
    except qe.QueryError as error:
        st.session_state.search_result = {"error": str(error)}


def page_search():
    st.title("Search")
    state = st.session_state
    if "pending_query" in state:  # sent from the Investigate page
        state.lang, state.query_text = state.pop("pending_lang"), state.pop("pending_query")
        run_search()
    state.setdefault("lang", "KQL")
    state.setdefault("query_text", state.get("saved_query") or next(iter(qe.EXAMPLES["KQL"].values())))

    main, side = st.columns([3, 1])
    with main:
        c1, c2 = st.columns([1, 2])
        c1.segmented_control("Language", ["KQL", "SPL", "SQL"], key="lang", required=True, on_change=set_language)
        c2.selectbox("Example queries", list(qe.EXAMPLES[state.lang]), index=None, key="example",
                     placeholder="Load an example...", on_change=load_example)
        st.text_area("Query", key="query_text", height=150, label_visibility="collapsed")
        st.button("▶ Run query", type="primary", on_click=run_search)

        res = state.get("search_result")
        if res and "error" in res:
            st.error(res["error"])
        elif res:
            df = res["df"]
            capped = " (limit reached)" if len(df) >= qe.MAX_ROWS else ""
            st.caption(f"**{len(df):,} results**{capped} · {res['ms']:.0f} ms")
            if state.lang != "SQL":
                with st.expander("Translated to SQL"):
                    st.code(res["sql"], language="sql")
            time_col = next((c for c in df.columns if c.lower() in TIME_COLUMNS), None)
            if time_col and len(df) > 1:
                times = pd.to_datetime(df[time_col], errors="coerce").dropna()
                if len(times) > 1:
                    fig = px.histogram(times, nbins=min(60, len(times)), color_discrete_sequence=[RED])
                    fig.update_layout(height=160, showlegend=False, xaxis_title=None, yaxis_title="Events",
                                      **CHART_LAYOUT)
                    st.plotly_chart(fig)
            st.dataframe(df, hide_index=True, height=min(600, 38 + 35 * len(df)))
            st.download_button("Export CSV", csv_safe(df), "search_results.csv", "text/csv")

    with side:
        st.markdown("**Tables**")
        for table, cols in schema.items():
            rows = len(tables[table]) if table in tables else 0
            with st.expander(f"{table} · {rows:,}"):
                st.markdown("\n".join(f"- `{name}` <span style='color:#8B949E'>{typ.lower()}</span>"
                                      for name, typ in cols), unsafe_allow_html=True)
        with st.expander(f"{state.lang} cheat sheet"):
            st.code(CHEAT_SHEET[state.lang], language=None)


# =============================================================================
# Page: Investigate
# =============================================================================
def hunt_query(kind, value):
    """A follow-up KQL query for the Search page."""
    if kind == "ip":
        return (f'honeypot\n| where ip == "{value}"\n| summarize Attempts = count() by bin(time, 1h)'
                if "honeypot" in tables else f'malicious_ips\n| where ip == "{value}"')
    if kind == "phone":
        digits = "".join(c for c in value if c.isdigit())[-10:]
        return f'scam_calls\n| where phone == "{digits}"\n| summarize Reports = count() by subject\n| sort by Reports desc'
    if kind in ("email", "domain"):
        domain = value.split("@")[-1].lower()
        return f'phishing_urls\n| where domain endswith "{domain}"'
    if kind == "cve":
        return f'kev\n| where cveID == "{value.upper()}"'
    return None


def pivot_to_search(query):
    st.session_state.pending_lang, st.session_state.pending_query = "KQL", query
    st.switch_page(PAGES["search"])


def page_investigate():
    st.title("Investigate")
    st.caption("Check any indicator against every feed: IP address, CVE, email, phone number, or domain.")
    value = st.text_input("Indicator", placeholder="185.220.101.1 · CVE-2024-3400 · billing@paypa1.com · "
                                                  "(844) 502-3148 · paypal-login.net",
                          label_visibility="collapsed", autocomplete="off", max_chars=254).strip()
    if not value:
        return
    if len(value) > 254:
        st.error("That's too long to be an indicator.")
        return
    # Throttle lookups so the public site can't be used to hammer the free APIs behind it
    if value != st.session_state.get("last_lookup"):
        if not allow("lookup", 30, 300, 600):
            st.warning("Lookup limit reached (30 every 10 minutes). Try again in a few minutes.")
            return
        st.session_state.last_lookup = value
    kind = feeds.detect_type(value)
    labels = {"ip": "IP address", "cve": "CVE", "email": "Email address", "phone": "Phone number", "domain": "Domain"}
    if kind == "private_ip":
        st.info("That's a private or reserved IP. It only exists inside local networks, so there's nothing to look up.")
        return
    if kind == "unknown":
        st.error("Enter an IP address, CVE ID, email address, phone number, or domain.")
        return

    with st.spinner(f"Checking {labels[kind].lower()} against every source..."):
        if kind == "ip":
            report = checks.check_ip(value, ipsum, data["botnet_c2"], honeypot, intel,
                                     data["hijacked_netblocks"], data["top_attacking_subnets"])
        elif kind == "cve":
            report = checks.check_cve(value, data["kev"])
        elif kind == "email":
            report = checks.check_email(value, data["disposable_domains"], data["phishing_urls"],
                                        data["phishing_domains"], data["data_breaches"], data["ransomware_victims"])
        elif kind == "phone":
            report = checks.check_phone(value, data["scam_calls"])
        else:
            report = checks.check_domain(value, data["disposable_domains"], data["phishing_urls"],
                                         data["phishing_domains"], data["data_breaches"], data["ransomware_victims"])

    verdict = report["verdict"]
    st.markdown(f'<div class="verdict {verdict}"><b>{verdict.upper()}</b> · {labels[kind]} '
                f'<code>{esc(value)}</code> · risk score <b>{report["risk"]}</b>/100</div>', unsafe_allow_html=True)

    left, right = st.columns([1, 1])
    with left:
        st.markdown("**Signals**")
        for level, text in report["signals"]:
            color = SIGNAL_COLOR.get(level, NEON_GRAY)
            st.markdown(f'<div class="signal">{neon_dot(color, pulse=level == "danger")}<span>{esc(text)}</span></div>',
                        unsafe_allow_html=True)
        query = hunt_query(kind, value)
        if query and st.button("Hunt for this in Search →"):
            pivot_to_search(query)
    with right:
        st.markdown("**Details**")
        details = pd.DataFrame({"Field": list(report["details"]), "Value": [str(v) for v in report["details"].values()]})
        st.dataframe(details, hide_index=True, column_config={"Value": st.column_config.TextColumn(width="large")})
    if any(report["raw"].values()):
        with st.expander("Raw data"):
            st.json(report["raw"], expanded=False)
    if kind in ("phone", "email"):
        st.caption("Reputation check only: this shows reports of scams, spam, and phishing, not who owns it.")


# =============================================================================
# Page: Honeypot
# =============================================================================
def page_honeypot():
    st.title("Honeypot")
    if honeypot_source == "live":
        latest = honeypot["time"].max()
        ago = f"last attack {minutes_ago(latest)}" if pd.notna(latest) else "no attacks yet"
        st.markdown(f'{status_badge("LIVE", NEON_RED, pulse=True)} <span style="color:#8FA6C8;font-size:0.85rem">'
                    f'Real SSH attacks on our Cowrie honeypot (Oracle Cloud, Montreal) · last 7 days · {ago} · '
                    f'updates every 5 minutes · <a href="{feeds.HONEYPOT_REPO}" target="_blank">raw data</a></span>',
                    unsafe_allow_html=True)
    elif honeypot_source == "upload":
        st.caption("Showing the file you uploaded. Remove it in the sidebar to go back to the live honeypot.")
    if honeypot is None or honeypot.empty:
        st.info("No honeypot data yet. The live honeypot feed hasn't published anything, or you can upload a CSV in "
                "the sidebar. Any export with an IP column works, like failed sign-ins from Sentinel or Log Analytics.")
        return
    counts = honeypot["ip"].value_counts().rename_axis("ip").reset_index(name="attempts")
    on_lists = f"{counts['ip'].isin(ipsum['ip']).mean():.0%}" if ipsum is not None else "—"
    c = st.columns(4)
    c[0].metric("Attack events" if "event" in honeypot else "Total attempts", f"{len(honeypot):,}", border=True)
    c[1].metric("Unique attacker IPs", f"{len(counts):,}", border=True)
    c[2].metric("Already on blocklists", on_lists, border=True,
                help="Share of attacker IPs that other defenders had already flagged")
    c[3].metric("Alerts", int((alerts["Source"] == "Honeypot").sum()) if not alerts.empty else 0, border=True)

    map_with_countries(geo_points(counts, "attempts", 300), "attempts", "Attempts")

    if "time" in honeypot.columns and honeypot["time"].notna().any():
        per_hour = honeypot.dropna(subset=["time"]).set_index("time").resample("h").size()
        fig = px.area(per_hour, color_discrete_sequence=[RED])
        fig.update_layout(height=240, showlegend=False, xaxis_title=None, yaxis_title="Attempts per hour",
                          **CHART_LAYOUT)
        st.plotly_chart(fig)

    table = counts.head(100)
    if ipsum is not None:
        table = table.merge(ipsum, on="ip", how="left").fillna({"score": 0})
    feodo = data["botnet_c2"]
    table["botnet_c2"] = table["ip"].isin(set(feodo["ip_address"]) if feodo is not None and not feodo.empty else set())
    st.dataframe(table, hide_index=True, column_config={
        "ip": "Attacker IP", "attempts": "Attempts", "score": "Blocklist score", "botnet_c2": "Botnet C2"})

    if "event" in honeypot:
        # Everything below was typed by attackers: only ever shown in escaped tables
        logins = honeypot[honeypot["event"].str.startswith("login")]
        commands = honeypot[honeypot["event"] == "command"]

        def top(series, label):
            series = series[series.str.len() > 0]
            return series.value_counts().head(15).rename_axis(label).reset_index(name="Tries")

        st.subheader("What attackers tried")
        cols = st.columns(3)
        cols[0].caption("Usernames")
        cols[0].dataframe(top(logins["username"], "Username"), hide_index=True)
        cols[1].caption("Passwords")
        cols[1].dataframe(top(logins["password"], "Password"), hide_index=True)
        cols[2].caption("Commands after getting a (fake) shell")
        cols[2].dataframe(top(commands["command"], "Command"), hide_index=True)
        st.caption(f"{len(logins):,} login attempts · {int((honeypot['event'] == 'login_success').sum()):,} let into "
                   f"the fake shell · {len(commands):,} commands run · "
                   f"{int((honeypot['event'] == 'download').sum()):,} malware download attempts")


# =============================================================================
# Page: Connectors
# =============================================================================
def page_connectors():
    st.title("Data connectors")
    rows = []
    for key, name, kind, _, refresh, url in CONNECTORS:
        error, loaded_at = status[key]
        badge = status_badge("Connected", NEON_GREEN) if error is None else status_badge("Error", NEON_RED, pulse=True)
        records = f"{len(data[key]):,}" if data[key] is not None else "0"
        note = f'<br><span style="color:#FF9DB3;font-size:0.75rem">{esc(error)}</span>' if error else ""
        rows.append([f"<td>{badge}{note}</td>", f"<td>{esc(name)}</td>", f'<td class="dim">{esc(kind)}</td>',
                     f'<td class="mono">{key}</td>', f'<td class="mono">{records}</td>', f'<td class="dim">{refresh}</td>',
                     f'<td class="dim">{loaded_at:%Y-%m-%d %H:%M}</td>',
                     f'<td class="clip"><a href="{esc(url)}" target="_blank">{esc(url)}</a></td>'])
    loaded = honeypot is not None
    if honeypot_error:
        badge = status_badge("Error", NEON_RED, pulse=True) + \
            f'<br><span style="color:#FF9DB3;font-size:0.75rem">{esc(honeypot_error)}</span>'
    elif honeypot_source == "live":
        badge = status_badge("Live", NEON_GREEN, pulse=True)
    else:
        badge = status_badge("Loaded" if loaded else "Waiting", NEON_GREEN if loaded else NEON_GRAY)
    latest = honeypot["time"].max() if loaded and "time" in honeypot else None
    rows.append([f"<td>{badge}</td>", "<td>Our honeypot (Cowrie, Oracle Cloud)</td>",
                 '<td class="dim">Live SSH attacks</td>', '<td class="mono">honeypot</td>',
                 f'<td class="mono">{len(honeypot) if loaded else 0:,}</td>',
                 f'<td class="dim">{"Upload" if honeypot_source == "upload" else "5 minutes"}</td>',
                 f'<td class="dim">{latest:%Y-%m-%d %H:%M}</td>' if latest is not None and pd.notna(latest)
                 else '<td class="dim">—</td>',
                 f'<td class="clip"><a href="{feeds.HONEYPOT_REPO}" target="_blank">{feeds.HONEYPOT_REPO}</a></td>'])
    html_table(["Status", "Connector", "Data", "Table", "Records", "Refresh", "Last pulled (UTC)", "Source"], rows)

    st.subheader("On-demand enrichment")
    services = [("ip-api.com", "IP geolocation", None), ("Shodan InternetDB", "Open ports and vulnerabilities", None),
                ("Google Public DNS", "MX, SPF, and DMARC records", None), ("RDAP", "Domain registration date", None),
                ("AbuseIPDB", "IP abuse score", "AbuseIPDB"),
                ("IPQualityScore", "Phone and email fraud score", "IPQualityScore"),
                ("FTC API (api.data.gov)", "Scam call reports if the CSV download fails", "data.gov"),
                ("Ransomware.live API", "Ransomware victims (free key, more reliable than the no-key API)",
                 "Ransomware.live")]
    rows = []
    for service, use, key_name in services:
        if key_name is None:
            badge = status_badge("No key needed", NEON_GREEN)
        elif key_status(KEY_ENV[key_name])[1] != "off":
            badge = status_badge("Your key" if key_status(KEY_ENV[key_name])[1] == "yours" else "Key added", NEON_GREEN)
        else:
            badge = status_badge("Optional key", NEON_GRAY)
        rows.append([f"<td>{badge}</td>", f"<td>{service}</td>", f'<td class="dim">{use}</td>'])
    html_table(["Status", "Service", "Used for"], rows)


# =============================================================================
# Page: Privacy & Terms
# =============================================================================
def page_privacy():
    st.title("Privacy & Terms")
    st.caption(f"Mothlight is built and run by {legal.TEAM}. Effective {legal.EFFECTIVE}.")
    privacy, terms = st.tabs(["Privacy Policy", "Terms of Use"])
    privacy.markdown(legal.PRIVACY)
    terms.markdown(legal.TERMS)


# =============================================================================
# Navigation
# =============================================================================
PAGES = {
    "overview": st.Page(page_overview, title="Overview", icon=":material/dashboard:", default=True),
    "alerts": st.Page(page_alerts, title="Alerts", icon=":material/notifications_active:"),
    "search": st.Page(page_search, title="Search", icon=":material/terminal:"),
    "investigate": st.Page(page_investigate, title="Investigate", icon=":material/travel_explore:"),
    "honeypot": st.Page(page_honeypot, title="Honeypot", icon=":material/hive:"),
    "connectors": st.Page(page_connectors, title="Connectors", icon=":material/cable:"),
    "privacy": st.Page(page_privacy, title="Privacy & Terms", icon=":material/policy:", url_path="privacy"),
}
st.navigation({
    "Monitor": [PAGES["overview"], PAGES["alerts"]],
    "Hunt": [PAGES["search"], PAGES["investigate"]],
    "Data": [PAGES["honeypot"], PAGES["connectors"]],
    "About": [PAGES["privacy"]],
}).run()
