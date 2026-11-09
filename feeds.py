# feeds.py - Downloads and cleans up threat intelligence data.
# app.py calls these functions; this file has no web page code in it.

import hashlib
import io
import json
import os
import re
import ipaddress
from pathlib import Path
from urllib.parse import urlparse

import numpy as np
import pandas as pd
import requests
import streamlit as st

# ---------------------------------------------------------------------------
# Where the data comes from (all free and public)
# ---------------------------------------------------------------------------
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
IPSUM_URL = "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt"
FEODO_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
GEO_BATCH_URL = "http://ip-api.com/batch?fields=status,query,country,countryCode,lat,lon,isp"
GEO_SINGLE_URL = "http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,lat,lon,isp,org,as"
INTERNETDB_URL = "https://internetdb.shodan.io/{ip}"
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
FTC_DNC_URL = "https://www.ftc.gov/sites/default/files/DNC_Complaint_Numbers_{date}.csv"
DISPOSABLE_URL = "https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/main/disposable_email_blocklist.conf"
OPENPHISH_URL = "https://raw.githubusercontent.com/openphish/public_feed/main/feed.txt"

FTC_API_URL = "https://api.ftc.gov/v0/dnc-complaints"
BLOCKLIST_DE_URL = "https://lists.blocklist.de/lists/{name}.txt"
CINS_URL = "https://cinsscore.com/list/ci-badguys.txt"
TOR_EXITS_URL = "https://check.torproject.org/torbulkexitlist"
GREENSNOW_URL = "https://blocklist.greensnow.co/greensnow.txt"
BINARY_DEFENSE_URL = "https://www.binarydefense.com/banlist.txt"
DSHIELD_URL = "https://feeds.dshield.org/block.txt"
SPAMHAUS_DROP_URL = "https://www.spamhaus.org/drop/drop_v4.json"
RANSOMWARE_URL = "https://api.ransomware.live/v2/recentvictims"          # free, no key (personal use)
RANSOMWARE_PRO_URL = "https://api-pro.ransomware.live/victims/recent"    # free key from ransomware.live/my
HIBP_BREACHES_URL = "https://haveibeenpwned.com/api/v3/breaches"
EPSS_URL = "https://api.first.org/data/v1/epss"
PHISHING_ARMY_URL = "https://phishing.army/download/phishing_army_blocklist.txt"
CERT_PL_URL = "https://hole.cert.pl/domains/v2/domains.txt"
DSHIELD_TOP_IPS_URL = "https://isc.sans.edu/api/sources/attacks/1000?json"
IP_COUNTRY_URL = "https://github.com/sapics/ip-location-db/releases/download/latest/iptoasn-country-ipv4-num.csv"

# blocklist.de publishes one list per attack type
BLOCKLIST_DE_LISTS = {
    "ssh": "SSH brute force", "bruteforcelogin": "Login brute force", "ftp": "FTP brute force",
    "imap": "Mail brute force", "mail": "Spam / mail abuse", "apache": "Web attacks",
    "bots": "Bad bots", "sip": "VoIP (SIP) attacks", "strongips": "Persistent attacker",
}

# Identify this app honestly to the sites it pulls from
HEADERS = {"User-Agent": "Mothlight/1.0 (open-source threat intel SIEM)"}
HONEYPOT_FILE = Path(__file__).parent / "honeypot.csv"
HONEYPOT_REPO = "https://github.com/realzephaniahjohnson/mothlight-honeypot-data"
HONEYPOT_LIVE_URL = "https://raw.githubusercontent.com/realzephaniahjohnson/mothlight-honeypot-data/main/honeypot.csv"
HONEYPOT_MAX_BYTES = 20_000_000
HONEYPOT_EVENTS = {"login_failed", "login_success", "command", "download"}
TIMEOUT = 30  # seconds to wait for a website before giving up


KEY_FORMAT = re.compile(r"^[A-Za-z0-9_-]{8,128}$")


def get_key(name):
    """The visitor's own key (kept only in their browser session), otherwise the site owner's key.
    Keys are only ever used server-side to call the provider; they are never sent to the page."""
    try:
        user_key = st.session_state.get("user_keys", {}).get(name)
    except Exception:
        user_key = None
    return user_key or get_secret(name)


def key_id(key):
    """A one-way fingerprint so cached results are kept separate per key without storing the key itself."""
    return hashlib.sha256(key.encode()).hexdigest()[:16]


def get_secret(name):
    """Read an API key from .env (on your Mac) or Streamlit secrets (when deployed)."""
    value = os.getenv(name)
    if value:
        return value
    try:
        return st.secrets.get(name)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Level 2: CISA Known Exploited Vulnerabilities
# ---------------------------------------------------------------------------
@st.cache_data(ttl=3600, show_spinner="Loading exploited CVEs...")
def get_kev():
    response = requests.get(KEV_URL, headers=HEADERS, timeout=TIMEOUT)
    response.raise_for_status()
    df = pd.DataFrame(response.json()["vulnerabilities"])
    df["dateAdded"] = pd.to_datetime(df["dateAdded"])
    return df.sort_values("dateAdded", ascending=False).reset_index(drop=True)


# ---------------------------------------------------------------------------
# Level 3: Malicious IPs
# ---------------------------------------------------------------------------
@st.cache_data(ttl=3600 * 6, show_spinner="Loading malicious IPs...")
def get_ipsum():
    """IPsum: IPs seen on many public blocklists. 'score' = how many lists flagged it."""
    response = requests.get(IPSUM_URL, headers=HEADERS, timeout=TIMEOUT)
    response.raise_for_status()
    rows = []
    for line in response.text.splitlines():
        if not line or line.startswith("#"):
            continue  # skip blank lines and comments
        parts = line.split()
        if len(parts) == 2:
            rows.append({"ip": parts[0], "score": int(parts[1])})
    return pd.DataFrame(rows, columns=["ip", "score"])


@st.cache_data(ttl=3600 * 6, show_spinner="Loading botnet servers...")
def get_feodo():
    """Feodo Tracker (abuse.ch): command-and-control servers for banking-malware botnets."""
    response = requests.get(FEODO_URL, headers=HEADERS, timeout=TIMEOUT)
    response.raise_for_status()
    df = pd.DataFrame(response.json())
    if df.empty:
        return df
    keep = ["ip_address", "port", "status", "malware", "country", "as_name", "first_seen", "last_online"]
    return df[[c for c in keep if c in df.columns]]


# ---------------------------------------------------------------------------
# Phone and email threat data
# ---------------------------------------------------------------------------
FTC_COLUMNS = {  # API field name -> CSV column name
    "company-phone-number": "Company_Phone_Number", "created-date": "Created_Date",
    "violation-date": "Violation_Date", "consumer-state": "Consumer_State",
    "subject": "Subject", "recorded-message-or-robocall": "Recorded_Message_Or_Robocall",
}


@st.cache_data(ttl=3600 * 6, show_spinner="Loading scam call reports...")
def get_ftc_complaints():
    """FTC Do Not Call complaints: phone numbers people reported for robocalls and scams.
    Tries the daily CSV files first. If ftc.gov refuses them, uses FTC's official API."""
    try:
        raw = ftc_from_csv()
    except ConnectionError as csv_error:
        try:
            raw = ftc_from_api()
        except ConnectionError as api_error:
            raise ConnectionError(f"{csv_error} {api_error}") from api_error
    return clean_ftc(raw)


def ftc_from_csv(days_back=14, max_files=7):
    """The FTC posts one CSV per business day, so grab the most recent ones."""
    frames, codes = [], set()
    today = pd.Timestamp.now(tz="America/New_York").normalize()
    for offset in range(days_back):
        day = (today - pd.Timedelta(days=offset)).strftime("%Y-%m-%d")
        try:
            response = requests.get(FTC_DNC_URL.format(date=day), headers=HEADERS, timeout=TIMEOUT)
        except (requests.ConnectionError, requests.Timeout):
            codes.add("unreachable")
            break
        codes.add(str(response.status_code))
        if response.status_code == 200 and "Company_Phone_Number" in response.text[:200]:
            frames.append(pd.read_csv(io.StringIO(response.text), dtype=str))
        if len(frames) >= max_files:
            break
    if not frames:
        raise ConnectionError(f"CSV files: HTTP {', '.join(sorted(codes))}.")
    return pd.concat(frames, ignore_index=True)


def ftc_from_api():
    """FTC's official API. Works with DEMO_KEY, but a free api.data.gov key allows far more requests."""
    key = get_secret("DATA_GOV_API_KEY") or "DEMO_KEY"
    pages = 40 if key != "DEMO_KEY" else 8  # 50 complaints per page
    rows = []
    for page in range(pages):
        try:
            response = requests.get(FTC_API_URL, headers=HEADERS, timeout=TIMEOUT,
                                    params={"api_key": key, "items_per_page": 50, "offset": page * 50})
        except requests.RequestException:
            break
        if response.status_code != 200:
            if not rows:
                hint = " Rate limited: add a free DATA_GOV_API_KEY." if response.status_code == 429 else ""
                raise ConnectionError(f"API: HTTP {response.status_code}.{hint}")
            break
        batch = response.json().get("data", [])
        if not batch:
            break
        rows.extend(item.get("attributes", {}) for item in batch)
    if not rows:
        raise ConnectionError("API: no data returned.")
    return pd.DataFrame(rows).rename(columns=FTC_COLUMNS)


def clean_ftc(df):
    out = pd.DataFrame({
        "phone": df["Company_Phone_Number"].fillna("").astype(str).str.replace(r"\D", "", regex=True),
        "reported": pd.to_datetime(df["Created_Date"], errors="coerce", utc=True).dt.tz_localize(None),
        "call_time": pd.to_datetime(df["Violation_Date"], errors="coerce", utc=True).dt.tz_localize(None),
        "state": df["Consumer_State"],
        "subject": df["Subject"],
        "robocall": df["Recorded_Message_Or_Robocall"].eq("Y"),
    })
    # Drop the US country code, blanks, and placeholder numbers like 0000000000
    out["phone"] = out["phone"].str.replace(r"^1(\d{10})$", r"\1", regex=True)
    out = out[out["phone"].str.fullmatch(r"\d{10}") & ~out["phone"].str.fullmatch(r"(\d)\1+")]
    return out.reset_index(drop=True)


@st.cache_data(ttl=3600 * 24, show_spinner=False)
def get_disposable_domains():
    """Throwaway email providers (10minutemail, mailinator, etc.)."""
    response = requests.get(DISPOSABLE_URL, headers=HEADERS, timeout=TIMEOUT)
    response.raise_for_status()
    return pd.DataFrame({"domain": [d.strip().lower() for d in response.text.splitlines() if d.strip()]})


@st.cache_data(ttl=3600 * 6, show_spinner=False)
def get_openphish():
    """OpenPhish community feed: live phishing URLs (free for non-commercial use)."""
    response = requests.get(OPENPHISH_URL, headers=HEADERS, timeout=TIMEOUT)
    response.raise_for_status()
    urls = [u.strip() for u in response.text.splitlines() if u.strip()]
    domains = [urlparse(u).hostname or "" for u in urls]
    return pd.DataFrame({"url": urls, "domain": [d.lower().removeprefix("www.") for d in domains]})


# ---------------------------------------------------------------------------
# More IP threat feeds (plain text, one IP per line)
# ---------------------------------------------------------------------------
IPV4 = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def ip_list(url):
    response = requests.get(url, headers=HEADERS, timeout=TIMEOUT)
    response.raise_for_status()
    return [line.strip() for line in response.text.splitlines() if IPV4.match(line.strip())]


@st.cache_data(ttl=3600 * 6, show_spinner="Loading attack reports...")
def get_blocklist_de():
    """blocklist.de: IPs caught attacking servers, labeled by attack type."""
    rows, failed = [], []
    for name, category in BLOCKLIST_DE_LISTS.items():
        try:
            rows.extend({"ip": ip, "attack_type": category} for ip in ip_list(BLOCKLIST_DE_URL.format(name=name)))
        except requests.RequestException:
            failed.append(name)
    if not rows:
        raise ConnectionError(f"No blocklist.de lists could be downloaded ({', '.join(failed)}).")
    return pd.DataFrame(rows).drop_duplicates()


@st.cache_data(ttl=3600 * 6, show_spinner=False)
def get_cins():
    """CINS Army: IPs with very poor reputation from Sentinel IPS sensors (mostly scanners)."""
    return pd.DataFrame({"ip": ip_list(CINS_URL)})


@st.cache_data(ttl=3600 * 6, show_spinner=False)
def get_tor_exits():
    """Tor Project: current Tor exit nodes. Not malicious by themselves, but they hide who's behind them."""
    return pd.DataFrame({"ip": ip_list(TOR_EXITS_URL)})


@st.cache_data(ttl=3600 * 6, show_spinner=False)
def get_greensnow():
    """GreenSnow: IPs caught brute-forcing and scanning their sensors."""
    return pd.DataFrame({"ip": ip_list(GREENSNOW_URL)})


@st.cache_data(ttl=3600 * 6, show_spinner=False)
def get_binary_defense():
    """Binary Defense Artillery banlist: IPs that hit their honeypots (non-commercial use only)."""
    return pd.DataFrame({"ip": ip_list(BINARY_DEFENSE_URL)})


@st.cache_data(ttl=3600 * 3, show_spinner=False)
def get_dshield_subnets():
    """SANS ISC DShield: the top 20 attacking /24 networks of the last 3 days (CC BY-NC-SA)."""
    response = requests.get(DSHIELD_URL, headers=HEADERS, timeout=TIMEOUT)
    response.raise_for_status()
    rows = []
    for line in response.text.splitlines():
        parts = line.split("\t")
        if line.startswith("#") or len(parts) < 6 or not IPV4.match(parts[0]):
            continue
        rows.append({"network": f"{parts[0]}/{parts[2]}", "start_ip": parts[0], "targets": int(parts[3]),
                     "name": parts[4], "country": parts[5]})
    return pd.DataFrame(rows)


@st.cache_data(ttl=3600 * 12, show_spinner=False)
def get_spamhaus_drop():
    """Spamhaus DROP: networks hijacked or run entirely by criminals. Never route traffic to these."""
    response = requests.get(SPAMHAUS_DROP_URL, headers=HEADERS, timeout=TIMEOUT)
    response.raise_for_status()
    rows = []
    for line in response.text.splitlines():
        try:
            item = json.loads(line)
        except ValueError:
            continue
        if "cidr" in item:
            rows.append({"network": item["cidr"], "sbl_id": item.get("sblid"), "registry": item.get("rir")})
    return pd.DataFrame(rows)


@st.cache_data(ttl=3600, show_spinner=False)
def get_ransomware_victims():
    """Ransomware.live: the latest victims posted on ransomware gangs' leak sites.
    Uses the free keyed API if RANSOMWARE_LIVE_API_KEY is set, otherwise the free no-key API."""
    key = get_secret("RANSOMWARE_LIVE_API_KEY")
    if key:
        response = requests.get(RANSOMWARE_PRO_URL, headers={**HEADERS, "X-API-KEY": key}, timeout=TIMEOUT)
    else:
        response = requests.get(RANSOMWARE_URL, headers=HEADERS, timeout=TIMEOUT)
        if response.status_code == 404:
            raise ConnectionError("The free no-key API isn't responding. Add a free RANSOMWARE_LIVE_API_KEY "
                                  "from ransomware.live/my to your .env file.")
    response.raise_for_status()
    payload = response.json()
    if isinstance(payload, dict):  # the keyed API wraps the list
        payload = next((v for v in payload.values() if isinstance(v, list)), [])
    df = pd.DataFrame(payload)
    if "domain" not in df and "website" in df:
        df["domain"] = df["website"]
    if "url" not in df and "permalink" in df:
        df["url"] = df["permalink"]
    keep = {"victim": "victim", "group": "gang", "activity": "sector", "country": "country",
            "domain": "domain", "discovered": "discovered", "attackdate": "attack_date", "url": "details_url"}
    df = df[[c for c in keep if c in df.columns]].rename(columns=keep)
    for col in ("discovered", "attack_date"):
        if col in df:
            df[col] = pd.to_datetime(df[col], errors="coerce", utc=True).dt.tz_localize(None)
    if "domain" in df:
        df["domain"] = df["domain"].fillna("").astype(str).str.lower().str.replace(r"^(https?://)?(www\.)?", "", regex=True)
        df["domain"] = df["domain"].str.split("/").str[0]
    return df.sort_values("discovered", ascending=False).reset_index(drop=True)


@st.cache_data(ttl=3600 * 12, show_spinner=False)
def get_breaches():
    """Have I Been Pwned: every public data breach they've loaded (the catalog, not anyone's email)."""
    response = requests.get(HIBP_BREACHES_URL, headers=HEADERS, timeout=TIMEOUT)
    response.raise_for_status()
    df = pd.DataFrame(response.json())
    for flag in ("IsFabricated", "IsSpamList"):  # skip fake breaches and spam lists
        if flag in df:
            df = df[~df[flag].fillna(False).astype(bool)]
    out = pd.DataFrame({
        "breach": df["Title"], "domain": df["Domain"].fillna("").str.lower(),
        "breach_date": pd.to_datetime(df["BreachDate"], errors="coerce"),
        "added": pd.to_datetime(df["AddedDate"], errors="coerce", utc=True).dt.tz_localize(None),
        "accounts": df["PwnCount"].astype("int64"),
        "data_exposed": df["DataClasses"].map(lambda v: ", ".join(v) if isinstance(v, list) else ""),
        "verified": df["IsVerified"],
    })
    return out.sort_values("added", ascending=False).reset_index(drop=True)


@st.cache_data(ttl=3600 * 12, show_spinner="Scoring exploited CVEs (EPSS)...")
def get_epss():
    """FIRST EPSS: the chance each CVE gets exploited in the next 30 days. Scored for every KEV CVE."""
    cves = list(get_kev()["cveID"])
    rows = []
    for start in range(0, len(cves), 100):
        response = requests.get(EPSS_URL, params={"cve": ",".join(cves[start:start + 100]), "limit": 100},
                                headers=HEADERS, timeout=TIMEOUT)
        response.raise_for_status()
        rows.extend(response.json().get("data", []))
    df = pd.DataFrame(rows, columns=["cve", "epss", "percentile"])
    df["epss"] = df["epss"].astype(float)
    df["percentile"] = df["percentile"].astype(float)
    return df


@st.cache_data(ttl=3600, show_spinner=False)
def lookup_epss(cve):
    try:
        data = requests.get(EPSS_URL, params={"cve": cve}, headers=HEADERS, timeout=TIMEOUT).json().get("data", [])
        return {"epss": float(data[0]["epss"]), "percentile": float(data[0]["percentile"])} if data else None
    except Exception:
        return None


def domain_list(url):
    response = requests.get(url, headers=HEADERS, timeout=TIMEOUT)
    response.raise_for_status()
    return [d.strip().lower() for d in response.text.splitlines() if d.strip() and not d.startswith("#")]


@st.cache_data(ttl=3600 * 6, show_spinner="Loading phishing domains...")
def get_phishing_domains():
    """Phishing Army (personal use) and CERT Polska: known phishing and scam domains."""
    frames, failed = [], []
    for source, url in (("Phishing Army", PHISHING_ARMY_URL), ("CERT Polska", CERT_PL_URL)):
        try:
            frames.append(pd.DataFrame({"domain": domain_list(url), "source": source}))
        except requests.RequestException:
            failed.append(source)
    if not frames:
        raise ConnectionError(f"Couldn't download {', '.join(failed)}.")
    df = pd.concat(frames, ignore_index=True)
    return df.groupby("domain")["source"].agg(lambda s: ", ".join(sorted(set(s)))).reset_index()


@st.cache_data(ttl=3600 * 3, show_spinner=False)
def get_dshield_top_ips():
    """SANS ISC DShield: the 1,000 IPs that attacked the most sensors worldwide."""
    response = requests.get(DSHIELD_TOP_IPS_URL, headers=HEADERS, timeout=TIMEOUT)
    response.raise_for_status()
    df = pd.DataFrame(response.json())
    df = df.rename(columns={"attacks": "targets", "count": "reports", "firstseen": "first_seen", "lastseen": "last_seen"})
    df["ip"] = df["ip"].astype(str).str.replace(r"\b0+(\d)", r"\1", regex=True)  # ISC pads octets: 005 -> 5
    return df[df["ip"].str.match(IPV4)]


# ---------------------------------------------------------------------------
# IP -> country for every IP (offline lookup, no rate limits)
# ---------------------------------------------------------------------------
@st.cache_data(ttl=3600 * 24, show_spinner="Loading IP-to-country database...")
def get_ip_country_table():
    """IPtoASN country ranges (public domain, via sapics/ip-location-db): start, end, country."""
    response = requests.get(IP_COUNTRY_URL, headers=HEADERS, timeout=60)
    response.raise_for_status()
    df = pd.read_csv(io.StringIO(response.text), header=None, names=["start", "end", "country"],
                     dtype={"start": "int64", "end": "int64", "country": str})
    return df.sort_values("start").reset_index(drop=True)


def ip_to_int(ips):
    parts = pd.Series(ips, dtype=str).str.split(".", expand=True)
    if parts.shape[1] != 4:
        return np.full(len(ips), -1, dtype="int64")
    n = parts.apply(pd.to_numeric, errors="coerce").to_numpy(dtype="float64")
    bad = np.isnan(n).any(axis=1) | (n < 0).any(axis=1) | (n > 255).any(axis=1)
    n = np.nan_to_num(n).astype("int64")
    nums = (n[:, 0] << 24) | (n[:, 1] << 16) | (n[:, 2] << 8) | n[:, 3]
    return np.where(bad, -1, nums)


def countries_for(ips, table):
    """Country code for each IP using a binary search over the ranges. Fast for 100k+ IPs."""
    if table is None or table.empty or len(ips) == 0:
        return pd.Series([None] * len(ips), dtype=object)
    nums = ip_to_int(list(ips))
    starts, ends = table["start"].to_numpy(), table["end"].to_numpy()
    idx = np.searchsorted(starts, nums, side="right") - 1
    valid = (idx >= 0) & (nums >= 0)
    idx_safe = np.where(valid, idx, 0)
    inside = valid & (ends[idx_safe] >= nums)
    codes = table["country"].to_numpy()[idx_safe]
    return pd.Series(np.where(inside, codes, None), dtype=object)


# ---------------------------------------------------------------------------
# Location lookups (for the map)
# ---------------------------------------------------------------------------
@st.cache_resource
def _location_cache():
    """IP -> location, kept for the life of the app so each IP is looked up only once."""
    return {}


def geolocate(ips, max_requests=14):
    """Countries and map coordinates from ip-api.com: 100 IPs per request, 15 requests a minute on the free tier."""
    cache = _location_cache()
    wanted = list(dict.fromkeys(ips))
    missing = [ip for ip in wanted if ip not in cache]
    for start in range(0, min(len(missing), max_requests * 100), 100):
        chunk = missing[start:start + 100]
        try:
            response = requests.post(GEO_BATCH_URL, json=chunk, headers=HEADERS, timeout=TIMEOUT)
            if response.status_code != 200:
                break  # rate limited: try the rest on a later refresh
            for r in response.json():
                cache[r.get("query")] = r if r.get("status") == "success" else None
            if response.headers.get("X-Rl") == "0":
                break  # no requests left this minute
        except Exception:
            break
    rows = [cache[ip] for ip in wanted if cache.get(ip)]
    df = pd.DataFrame(rows, columns=["query", "country", "countryCode", "lat", "lon", "isp"])
    return df.rename(columns={"query": "ip"})


# ---------------------------------------------------------------------------
# Level 4: Lookup box
# ---------------------------------------------------------------------------
CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
EMAIL_PATTERN = re.compile(r"^[\w.+'-]+@([A-Za-z0-9-]+\.)+[A-Za-z]{2,}$")
PHONE_PATTERN = re.compile(r"^\+?[\d\s().-]{7,20}$")
DOMAIN_PATTERN = re.compile(r"^([A-Za-z0-9-]+\.)+[A-Za-z]{2,}$")


def detect_type(text):
    """Figure out what the user typed: IP, CVE, email, phone number, or domain."""
    text = text.strip()
    try:
        ip = ipaddress.ip_address(text)
        return "private_ip" if (ip.is_private or ip.is_reserved or ip.is_loopback) else "ip"
    except ValueError:
        pass
    if CVE_PATTERN.match(text):
        return "cve"
    if EMAIL_PATTERN.match(text):
        return "email"
    if PHONE_PATTERN.match(text) and sum(c.isdigit() for c in text) >= 7:
        return "phone"
    if DOMAIN_PATTERN.match(text):
        return "domain"
    return "unknown"


@st.cache_data(ttl=3600, show_spinner=False)
def lookup_geo(ip):
    try:
        data = requests.get(GEO_SINGLE_URL.format(ip=ip), timeout=TIMEOUT).json()
        return data if data.get("status") == "success" else None
    except Exception:
        return None


@st.cache_data(ttl=3600, show_spinner=False)
def lookup_internetdb(ip):
    """Shodan InternetDB: open ports, known vulnerabilities and tags for an IP. No key needed."""
    try:
        response = requests.get(INTERNETDB_URL.format(ip=ip), timeout=TIMEOUT)
        return response.json() if response.status_code == 200 else None
    except Exception:
        return None


def lookup_abuseipdb(ip):
    """AbuseIPDB abuse score. Only runs if there's an ABUSEIPDB_API_KEY (the visitor's or the site's)."""
    key = get_key("ABUSEIPDB_API_KEY")
    if not key or not KEY_FORMAT.match(key):
        return None
    return _abuseipdb(ip, key_id(key), key)


@st.cache_data(ttl=3600, show_spinner=False, max_entries=2000)
def _abuseipdb(ip, key_fingerprint, _key):
    """Cached per IP and per key fingerprint. Arguments starting with _ are never stored in the cache key."""
    key = _key
    try:
        response = requests.get(
            ABUSEIPDB_URL,
            headers={"Key": key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=TIMEOUT,
        )
        response.raise_for_status()
        return response.json().get("data")
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Level 6: Honeypot data
# ---------------------------------------------------------------------------
IP_COLUMN_NAMES = ["ip", "ipaddress", "ip_address", "src_ip", "sourceip", "source_ip",
                   "sourcehost", "clientip", "remoteip", "attacker_ip", "srcip"]
TIME_COLUMN_NAMES = ["timestamp", "timegenerated", "time", "date", "datetime", "eventtime"]


HONEYPOT_SOURCES = [  # tried in order, so one outage doesn't take the honeypot off the site
    ("GitHub raw", HONEYPOT_LIVE_URL, {}),
    ("GitHub API", "https://api.github.com/repos/realzephaniahjohnson/mothlight-honeypot-data/contents/honeypot.csv",
     {"Accept": "application/vnd.github.raw"}),
    ("jsDelivr CDN", "https://cdn.jsdelivr.net/gh/realzephaniahjohnson/mothlight-honeypot-data@main/honeypot.csv", {}),
]


@st.cache_resource
def _honeypot_last_good():
    return {}


def _parse_honeypot(content):
    """Everything in the file was typed by attackers: size-capped, validated, shown only in escaped tables."""
    if len(content) > HONEYPOT_MAX_BYTES:
        raise ValueError("The honeypot file is too large.")
    df = pd.read_csv(io.BytesIO(content), dtype=str, keep_default_na=False)
    missing = {"timestamp", "src_ip", "event"} - set(df.columns)
    if missing:
        raise ValueError(f"The honeypot file is missing columns: {', '.join(sorted(missing))}")
    out = pd.DataFrame({"ip": df["src_ip"].str.strip(),
                        "time": pd.to_datetime(df["timestamp"], errors="coerce", utc=True),
                        "event": df["event"].str.strip()})
    for column in ("username", "password", "command"):
        out[column] = df[column].str.slice(0, 200) if column in df else ""
    out = out[out["event"].isin(HONEYPOT_EVENTS) & out["ip"].apply(lambda x: detect_type(x) == "ip")]
    return out.reset_index(drop=True)


@st.cache_data(ttl=300, show_spinner=False)
def get_live_honeypot():
    """Live attacks on our Cowrie honeypot (published every 5 minutes), with backups.

    Returns (data, source). Tries each source in order; if all fail, falls back to the last
    good copy this server loaded. Returns (None, None) if nothing was ever published.
    """
    errors, not_found = [], 0
    for name, url, extra in HONEYPOT_SOURCES:
        try:
            response = requests.get(url, headers={**HEADERS, **extra}, timeout=15, stream=True)
            if response.status_code == 404:
                not_found += 1
                continue
            response.raise_for_status()
            df = _parse_honeypot(response.raw.read(HONEYPOT_MAX_BYTES + 1, decode_content=True))
            _honeypot_last_good().update(data=df, at=pd.Timestamp.now(tz="UTC"))
            return df, name
        except Exception as error:
            errors.append(f"{name}: {type(error).__name__}")
    last = _honeypot_last_good()
    if "data" in last:
        return last["data"], f"last good copy from {last['at']:%H:%M} UTC"
    if not_found == len(HONEYPOT_SOURCES):
        return None, None
    raise ConnectionError("The honeypot feed is temporarily unavailable.")


def load_honeypot(file=None):
    """Load honeypot logs from an uploaded CSV, or honeypot.csv in the project folder."""
    source = file if file is not None else (HONEYPOT_FILE if HONEYPOT_FILE.exists() else None)
    if source is None:
        return None
    df = pd.read_csv(source)
    lower = {c.lower().strip(): c for c in df.columns}
    ip_col = next((lower[n] for n in IP_COLUMN_NAMES if n in lower), None)
    if ip_col is None:
        raise ValueError(f"Couldn't find an IP column. Columns found: {', '.join(df.columns)}")
    out = pd.DataFrame({"ip": df[ip_col].astype(str).str.strip()})
    time_col = next((lower[n] for n in TIME_COLUMN_NAMES if n in lower), None)
    if time_col is not None:
        out["time"] = pd.to_datetime(df[time_col], errors="coerce", utc=True)
    # Keep only valid public IPs
    out = out[out["ip"].apply(lambda x: detect_type(x) == "ip")]
    return out.reset_index(drop=True)
