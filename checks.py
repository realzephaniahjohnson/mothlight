# checks.py - Reputation checks for phone numbers, emails, and domains.
# These answer "is this number/address/domain linked to scams, spam, or phishing?"
# They don't look up who owns a number or address.

import difflib
import ipaddress
import re
from datetime import datetime, timezone

import pandas as pd
import phonenumbers
import requests
import streamlit as st
from phonenumbers import PhoneNumberType, carrier, geocoder
from phonenumbers import timezone as phone_timezone

from feeds import KEY_FORMAT, TIMEOUT, get_key, key_id

DOH_URL = "https://dns.google/resolve"
RDAP_URL = "https://rdap.org/domain/{domain}"
IPQS_EMAIL_URL = "https://www.ipqualityscore.com/api/json/email/{key}/{email}"
IPQS_PHONE_URL = "https://www.ipqualityscore.com/api/json/phone/{key}/{phone}"

LINE_TYPES = {
    PhoneNumberType.MOBILE: "Mobile",
    PhoneNumberType.FIXED_LINE: "Landline",
    PhoneNumberType.FIXED_LINE_OR_MOBILE: "Landline or mobile",
    PhoneNumberType.VOIP: "VoIP",
    PhoneNumberType.TOLL_FREE: "Toll-free",
    PhoneNumberType.PREMIUM_RATE: "Premium rate",
    PhoneNumberType.SHARED_COST: "Shared cost",
    PhoneNumberType.PERSONAL_NUMBER: "Personal number",
    PhoneNumberType.PAGER: "Pager",
    PhoneNumberType.UAN: "UAN",
    PhoneNumberType.VOICEMAIL: "Voicemail",
}

FREE_EMAIL_PROVIDERS = {
    "gmail.com", "googlemail.com", "yahoo.com", "outlook.com", "hotmail.com", "live.com", "msn.com",
    "icloud.com", "me.com", "aol.com", "proton.me", "protonmail.com", "gmx.com", "mail.com",
    "yandex.com", "zoho.com",
}

# Brands phishers commonly impersonate, and the domains they really use
BRANDS = {
    "paypal": "paypal.com", "microsoft": "microsoft.com", "office365": "office.com", "outlook": "outlook.com",
    "apple": "apple.com", "icloud": "icloud.com", "google": "google.com", "amazon": "amazon.com",
    "netflix": "netflix.com", "facebook": "facebook.com", "instagram": "instagram.com", "chase": "chase.com",
    "wellsfargo": "wellsfargo.com", "bankofamerica": "bankofamerica.com", "coinbase": "coinbase.com",
    "binance": "binance.com", "usps": "usps.com", "fedex": "fedex.com", "ups": "ups.com", "dhl": "dhl.com",
    "irs": "irs.gov", "docusign": "docusign.com", "dropbox": "dropbox.com", "linkedin": "linkedin.com",
}


def result(risk, signals, details, raw=None):
    """Standard result shape used by every check. risk is 0-100."""
    risk = max(0, min(100, risk))
    verdict = "malicious" if risk >= 70 else "suspicious" if risk >= 30 else "clean"
    return {"risk": risk, "verdict": verdict, "signals": signals, "details": details, "raw": raw or {}}


# =============================================================================
# Phone numbers
# =============================================================================
def check_phone(text, complaints=None):
    """complaints = FTC Do Not Call data (DataFrame) or None."""
    try:
        number = phonenumbers.parse(text, "US")
    except phonenumbers.NumberParseException:
        return result(0, [("info", "That doesn't look like a real phone number.")], {})

    signals, risk = [], 0
    valid = phonenumbers.is_valid_number(number)
    line_type = LINE_TYPES.get(phonenumbers.number_type(number), "Unknown")
    region = phonenumbers.region_code_for_number(number) or "Unknown"
    details = {
        "Number": phonenumbers.format_number(number, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
        "Valid": "Yes" if valid else "No",
        "Line type": line_type,
        "Country": region,
        "Area": geocoder.description_for_number(number, "en") or "—",
        "Original carrier": carrier.name_for_number(number, "en") or "—",
        "Time zone": ", ".join(phone_timezone.time_zones_for_number(number)) or "—",
    }

    if not valid:
        risk += 25
        signals.append(("warning", "Not a valid number for its country. Spoofed caller IDs often look like this."))
    if line_type == "VoIP":
        risk += 15
        signals.append(("warning", "VoIP number. These are cheap and disposable, so scammers use them a lot."))
    if line_type == "Premium rate":
        risk += 30
        signals.append(("warning", "Premium-rate number. Calling it back can cost money."))

    # FTC complaints (US numbers only)
    reports = pd.DataFrame()
    if complaints is not None and number.country_code == 1:
        national = str(number.national_number)
        reports = complaints[complaints["phone"] == national]
    if not reports.empty:
        count = len(reports)
        robocall_pct = reports["robocall"].mean()
        top_subjects = reports["subject"].value_counts().head(3)
        risk += min(90, 25 + count * 15)
        signals.append(("danger", f"Reported to the FTC {count} time(s) in the last 2 weeks "
                                  f"({robocall_pct:.0%} robocalls)."))
        details["FTC reports"] = count
        details["Top complaint topics"] = "; ".join(f"{s} ({n})" for s, n in top_subjects.items())
        details["First / last report"] = f"{reports['reported'].min():%Y-%m-%d} / {reports['reported'].max():%Y-%m-%d}"
    elif complaints is not None and number.country_code == 1:
        signals.append(("ok", "No FTC scam or robocall reports in the last 2 weeks."))

    elif number.country_code != 1:
        signals.append(("info", "FTC scam-call reports only cover US and Canadian numbers."))

    raw = {"ftc_reports": reports.drop(columns=["state"], errors="ignore").head(50).to_dict("records")}
    ipqs = ipqs_phone(phonenumbers.format_number(number, phonenumbers.PhoneNumberFormat.E164))
    if ipqs:
        raw["ipqualityscore"] = ipqs
        risk = max(risk, ipqs.get("fraud_score", 0))
        details["IPQS fraud score"] = ipqs.get("fraud_score")
        if ipqs.get("carrier"):
            details["Current carrier"] = ipqs["carrier"]
        if ipqs.get("recent_abuse"):
            signals.append(("danger", "IPQualityScore: recent abuse reported for this number."))
        if ipqs.get("spammer"):
            signals.append(("danger", "IPQualityScore: flagged as a spammer."))
        if ipqs.get("active") is False:
            signals.append(("warning", "IPQualityScore: number isn't active."))
    if not any(level in ("danger", "warning") for level, _ in signals):
        signals.append(("ok", "No scam reports or risky line type found."))
    return result(risk, signals, details, raw)


def ipqs_phone(e164):
    key = get_key("IPQS_API_KEY")
    if not key or not KEY_FORMAT.match(key):
        return None
    return _ipqs_phone(e164, key_id(key), key)


# Phone numbers and emails are personal data: cache briefly (10 min) only to avoid repeat API calls
@st.cache_data(ttl=600, show_spinner=False, max_entries=500)
def _ipqs_phone(e164, key_fingerprint, _key):
    key = _key
    try:
        data = requests.get(IPQS_PHONE_URL.format(key=key, phone=e164.lstrip("+")), timeout=TIMEOUT).json()
        return data if data.get("success") else None
    except Exception:
        return None


# =============================================================================
# Domains (used for emails and on their own)
# =============================================================================
@st.cache_data(ttl=3600, show_spinner=False)
def dns_query(name, record_type):
    """Ask Google's public DNS. Returns (status, records): status 0 = OK, 3 = domain doesn't exist."""
    try:
        data = requests.get(DOH_URL, params={"name": name, "type": record_type}, timeout=TIMEOUT).json()
        return data.get("Status"), [a.get("data", "").strip('"') for a in data.get("Answer", [])]
    except Exception:
        return None, None


@st.cache_data(ttl=3600, show_spinner=False)
def domain_created(domain):
    """Registration date from RDAP (the modern WHOIS)."""
    try:
        data = requests.get(RDAP_URL.format(domain=domain), timeout=TIMEOUT).json()
        for event in data.get("events", []):
            if event.get("eventAction") == "registration":
                return datetime.fromisoformat(event["eventDate"].replace("Z", "+00:00"))
    except Exception:
        pass
    return None


LEGIT_DOMAINS = set(BRANDS.values()) | {
    "microsoftonline.com", "office365.com", "live.com", "office.com", "windows.net", "azure.com",
    "amazonaws.com", "googleusercontent.com", "gmail.com", "youtube.com", "paypal.me", "fb.com",
}


def registrable(domain):
    """'login.paypal.co.uk' -> ('paypal', 'paypal.co.uk')"""
    labels = domain.split(".")
    if len(labels) >= 3 and labels[-2] in ("co", "com", "org", "net", "gov", "ac", "edu") and len(labels[-1]) == 2:
        reg = labels[-3:]
    else:
        reg = labels[-2:]
    return reg[0], ".".join(reg)


def lookalike_brand(domain):
    """Spot domains pretending to be a big brand, like paypa1.com or paypal-login.net."""
    label, reg_domain = registrable(domain)
    if reg_domain in LEGIT_DOMAINS:
        return None
    subdomain_words = set(re.split(r"[-.]", domain[: -len(reg_domain)].strip(".")))
    label_words = set(label.split("-"))
    for brand, real in BRANDS.items():
        if label == brand:
            return None  # e.g. amazon.co.uk: same name, different country domain
        if brand in subdomain_words or brand in label_words:
            return real  # paypal.com.secure-login.net, paypal-verify.com
        if len(brand) >= 5 and (label.startswith(brand) or
                                difflib.SequenceMatcher(None, label, brand).ratio() >= 0.83):
            return real  # paypalsecure.com, paypa1.com
    return None


def check_domain(domain, disposable=None, phishing=None, phishing_domains=None, breaches=None, victims=None):
    domain = domain.lower().strip().removeprefix("www.")
    signals, risk, details = [], 0, {"Domain": domain}

    status, mx = dns_query(domain, "MX")
    if status == 3:
        return result(40, [("warning", "This domain doesn't exist. Emails from it are fake or spoofed.")], details)

    if disposable is not None and domain in set(disposable["domain"]):
        risk += 40
        signals.append(("warning", "Disposable email provider. Addresses here are throwaway."))
    if phishing is not None:
        exact = phishing[phishing["domain"] == domain]
        on_subdomains = phishing[phishing["domain"].str.endswith("." + domain)]
        if not exact.empty:
            risk += 80
            signals.append(("danger", f"Hosting {len(exact)} live phishing URL(s) (OpenPhish)."))
            details["Phishing URLs"] = ", ".join(exact["url"].head(3))
        elif not on_subdomains.empty:
            risk += 20
            signals.append(("warning", f"{len(on_subdomains)} live phishing URL(s) on its subdomains. "
                                       "It may be a hosting platform that attackers abuse."))
    if phishing_domains is not None and not phishing_domains.empty:
        hit = phishing_domains[phishing_domains["domain"] == domain]
        if not hit.empty:
            risk += 85
            signals.append(("danger", f"Listed as a phishing or scam domain ({hit['source'].iat[0]})."))
    base = registrable(domain)[1]
    if victims is not None and not victims.empty:
        hit = victims[victims["domain"].isin([domain, base])]
        if not hit.empty:
            r = hit.iloc[0]
            risk += 30
            signals.append(("danger", f"This organization was posted as a ransomware victim by {r['gang']} "
                                      f"on {r['discovered']:%Y-%m-%d}. Treat its email and files with caution."))
    if breaches is not None and not breaches.empty:
        hit = breaches[breaches["domain"].isin([domain, base])]
        if not hit.empty:
            r = hit.iloc[0]
            risk += 10
            signals.append(("warning", f"Had a data breach: {r['breach']} ({r['breach_date']:%Y-%m-%d}), "
                                       f"{r['accounts']:,} accounts exposed (Have I Been Pwned)."))
            details["Data breach"] = f"{r['breach']}: {r['data_exposed']}"

    impersonates = lookalike_brand(domain)
    if impersonates:
        risk += 45
        signals.append(("danger", f"Looks like it's impersonating {impersonates}."))

    created = domain_created(registrable(domain)[1])
    if created:
        age_days = (datetime.now(timezone.utc) - created).days
        details["Registered"] = f"{created:%Y-%m-%d} ({age_days:,} days ago)"
        if age_days < 30:
            risk += 35
            signals.append(("danger", f"Brand-new domain, registered {age_days} days ago. Common for phishing."))
        elif age_days < 180:
            risk += 15
            signals.append(("warning", f"Young domain, registered {age_days} days ago."))

    if mx is not None:
        details["Mail servers (MX)"] = ", ".join(r.split()[-1].rstrip(".") for r in mx[:3]) or "None"
        if not mx:
            risk += 20
            signals.append(("warning", "No mail servers. This domain can't receive email."))
    _, txt = dns_query(domain, "TXT")
    _, dmarc = dns_query(f"_dmarc.{domain}", "TXT")
    has_spf = any(r.lower().startswith("v=spf1") for r in (txt or []))
    has_dmarc = any(r.lower().startswith("v=dmarc1") for r in (dmarc or []))
    details["SPF"] = "Yes" if has_spf else "No"
    details["DMARC"] = "Yes" if has_dmarc else "No"
    if txt is not None and not has_spf and not has_dmarc:
        risk += 10
        signals.append(("warning", "No SPF or DMARC, so email from this domain is easy to spoof."))
    if not any(level in ("danger", "warning") for level, _ in signals):
        signals.append(("ok", "No phishing, disposable, or lookalike signals found."))
    return result(risk, signals, details)


# =============================================================================
# Email addresses
# =============================================================================
def check_email(email, disposable=None, phishing=None, phishing_domains=None, breaches=None, victims=None):
    email = email.strip().lower()
    local, domain = email.rsplit("@", 1)
    report = check_domain(domain, disposable, phishing, phishing_domains, breaches, victims)
    details = {"Email": email, **report["details"]}
    signals, risk = list(report["signals"]), report["risk"]

    if domain in FREE_EMAIL_PROVIDERS:
        details["Provider"] = "Free webmail"
        # Free webmail is normal for people, but a red flag for "official" messages
        if any(word in local for word in ("support", "security", "billing", "admin", "helpdesk", "service")):
            risk += 30
            signals.append(("warning", "Free webmail address posing as a support or security team."))
        signals = [s for s in signals if "SPF" not in s[1]]  # big providers are fine
    raw = {}
    ipqs = ipqs_email(email)
    if ipqs:
        raw["ipqualityscore"] = ipqs
        risk = max(risk, ipqs.get("fraud_score", 0))
        details["IPQS fraud score"] = ipqs.get("fraud_score")
        details["Deliverable"] = ipqs.get("deliverability", "—")
        if ipqs.get("recent_abuse"):
            signals.append(("danger", "IPQualityScore: recent abuse reported for this address."))
        if ipqs.get("honeypot"):
            signals.append(("warning", "IPQualityScore: this looks like a spam trap."))
        if ipqs.get("leaked"):
            signals.append(("warning", "IPQualityScore: this address appears in known data leaks."))
    if any(level in ("danger", "warning") for level, _ in signals):
        signals = [s for s in signals if s[0] != "ok"]
    return result(risk, signals, details, raw)


def ipqs_email(email):
    key = get_key("IPQS_API_KEY")
    if not key or not KEY_FORMAT.match(key):
        return None
    return _ipqs_email(email, key_id(key), key)


@st.cache_data(ttl=600, show_spinner=False, max_entries=500)
def _ipqs_email(email, key_fingerprint, _key):
    key = _key
    try:
        url = IPQS_EMAIL_URL.format(key=key, email=requests.utils.quote(email, safe="@"))
        data = requests.get(url, timeout=TIMEOUT).json()
        return data if data.get("success") else None
    except Exception:
        return None


# =============================================================================
# IP addresses and CVEs
# =============================================================================
def check_ip(ip, ipsum=None, feodo=None, honeypot=None, intel=None, drop=None, subnets=None):
    from feeds import lookup_abuseipdb, lookup_geo, lookup_internetdb
    signals, risk, details = [], 0, {"IP": ip}

    score = 0
    if ipsum is not None:
        match = ipsum[ipsum["ip"] == ip]
        score = int(match["score"].iloc[0]) if not match.empty else 0
    details["Blocklist score"] = f"{score} lists"
    if score >= 3:
        risk += 40 + score * 5
        signals.append(("danger", f"On {score} public blocklists (IPsum)."))
    elif score > 0:
        risk += 20
        signals.append(("warning", f"On {score} public blocklist(s) (IPsum)."))

    if feodo is not None and not feodo.empty and ip in set(feodo["ip_address"]):
        row = feodo[feodo["ip_address"] == ip].iloc[0]
        risk += 90
        signals.append(("danger", f"Botnet command server for {row.get('malware', 'unknown')} malware (Feodo Tracker)."))
        details["Botnet malware"] = row.get("malware")

    if intel is not None and not intel.empty:
        row = intel[intel["ip"] == ip]
        if not row.empty and "country" in row and row["country"].iat[0]:
            details["Registered country"] = row["country"].iat[0]
        if not row.empty:
            tags = [t for t in row["tags"].iat[0].split("; ") if t not in ("Blocklisted", "Botnet C2")]
            details["Seen in"] = row["tags"].iat[0]
            attacks = [t for t in tags if t not in ("Scanner (CINS)", "Tor exit")]
            if attacks:
                risk += 20 + 10 * len(attacks)
                signals.append(("danger", f"Caught attacking servers (blocklist.de): {', '.join(attacks)}."))
            if "Scanner (CINS)" in tags:
                risk += 25
                signals.append(("warning", "On the CINS Army list: very poor reputation, usually a scanner."))
            if "Tor exit" in tags:
                risk += 10
                signals.append(("info", "Tor exit node. Traffic from it could be anyone using Tor."))

    address = ipaddress.ip_address(ip)
    if drop is not None and not drop.empty:
        for network, sbl in zip(drop["network"], drop["sbl_id"]):
            if address in ipaddress.ip_network(network, strict=False):
                risk += 80
                signals.append(("danger", f"Inside a hijacked or criminal-run network on Spamhaus DROP ({network}, {sbl})."))
                details["Spamhaus DROP"] = f"{network} ({sbl})"
                break
    if subnets is not None and not subnets.empty:
        for r in subnets.itertuples():
            if address in ipaddress.ip_network(r.network, strict=False):
                risk += 40
                signals.append(("danger", f"In one of today's top 20 attacking networks (DShield): {r.network}, "
                                          f"{r.targets:,} targets attacked."))
                break

    if honeypot is not None and not honeypot.empty:
        hits = int((honeypot["ip"] == ip).sum())
        details["Hit our honeypot"] = f"{hits:,} times"
        if hits:
            risk += 30
            signals.append(("danger", f"Attacked our honeypot {hits:,} time(s)."))

    abuse = lookup_abuseipdb(ip)
    if abuse:
        details["AbuseIPDB score"] = f"{abuse.get('abuseConfidenceScore')}%"
        details["AbuseIPDB reports"] = abuse.get("totalReports")
        risk = max(risk, abuse.get("abuseConfidenceScore") or 0)
        if (abuse.get("abuseConfidenceScore") or 0) >= 25:
            signals.append(("danger", f"AbuseIPDB confidence {abuse['abuseConfidenceScore']}% "
                                      f"from {abuse.get('totalReports', 0)} reports."))

    geo = lookup_geo(ip)
    if geo:
        details["Location"] = ", ".join(x for x in (geo.get("city"), geo.get("country")) if x)
        details["Network"] = f"{geo.get('isp', '')} ({geo.get('as', '')})"
    shodan = lookup_internetdb(ip)
    if shodan:
        details["Open ports"] = ", ".join(map(str, shodan.get("ports", []))) or "None seen"
        if shodan.get("tags"):
            details["Tags"] = ", ".join(shodan["tags"])
        if shodan.get("vulns"):
            details["Known vulns"] = ", ".join(shodan["vulns"][:10])
            risk += 10
            signals.append(("warning", f"Shodan sees {len(shodan['vulns'])} known vulnerabilities on this host."))
    if not signals:
        signals.append(("ok", "Not on any blocklist, botnet list, or honeypot log."))
    return result(risk, signals, details, {"abuseipdb": abuse, "shodan": shodan, "geo": geo})


def check_cve(cve, kev=None):
    cve = cve.upper()
    details = {"CVE": cve, "NVD": f"https://nvd.nist.gov/vuln/detail/{cve}"}
    match = kev[kev["cveID"] == cve] if kev is not None else pd.DataFrame()
    from feeds import lookup_epss
    epss = None
    if not match.empty and "epss" in match and pd.notna(match["epss"].iat[0]):
        epss = {"epss": match["epss"].iat[0], "percentile": match["epss_percentile"].iat[0]}
    else:
        epss = lookup_epss(cve)
    if epss:
        details["EPSS"] = f"{epss['epss']:.1%} chance of exploitation in the next 30 days (higher than {epss['percentile']:.0%} of CVEs)"
    if match.empty:
        signals = [("info", "Not on CISA's Known Exploited list, so there's no confirmed exploitation in the wild.")]
        risk = 10
        if epss and epss["epss"] >= 0.5:
            signals.append(("warning", f"But EPSS rates it {epss['epss']:.0%} likely to be exploited soon. Patch it."))
            risk = 55
        return result(risk, signals, details)
    row = match.iloc[0]
    ransomware = row["knownRansomwareCampaignUse"] == "Known"
    details.update({
        "Name": row["vulnerabilityName"],
        "Affects": f"{row['vendorProject']} {row['product']}",
        "Added to KEV": f"{row['dateAdded']:%Y-%m-%d}",
        "Fix deadline (federal)": row.get("dueDate", "—"),
        "Description": row["shortDescription"],
        "Required action": row["requiredAction"],
    })
    signals = [("danger", "Actively exploited in the wild (CISA KEV).")]
    if ransomware:
        signals.append(("danger", "Used in ransomware campaigns."))
    if epss and epss["epss"] >= 0.5:
        signals.append(("danger", f"EPSS: {epss['epss']:.0%} chance of exploitation in the next 30 days."))
    return result(95 if ransomware else 85, signals, details)
