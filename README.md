# Mothlight

*They always come to the light.*

**Mothlight** is an OSINT threat intelligence SIEM with a live SSH honeypot, built with Python and Streamlit. It pulls free open-source intelligence (OSINT) feeds into one place, raises alerts from detection rules, and lets you hunt through everything with **KQL, SPL, or SQL**. You can also investigate any IP, CVE, email address, phone number, or domain.

**Live demo:** https://mothlight.streamlit.app

**Built by** Zephaniah Johnson, Zakari Gilmer, and Bofelo Gaeonale.

## Features

| Page | What it does |
|---|---|
| **Overview** | KPIs, a 3D night-side threat globe (countries glowing by how many malicious IPs they host, sample IPs by attack type, US scam calls, alerts as pulsing rings, honeypot attack arcs, each a toggleable layer), alert queue, live feed tables |
| **Alerts** | Detections from 24 rules across 4 severities (Critical, High, Medium, Low), filterable by severity and source |
| **Search** | Query console for KQL (Microsoft Sentinel), SPL (Splunk), or SQL, with an event timeline, schema browser, example queries, and CSV export |
| **Investigate** | One box for any indicator. Auto-detects IPs, CVEs, emails, phone numbers, and domains, then returns a verdict, risk score, and evidence |
| **Honeypot** | Live SSH attacks on our Cowrie honeypot, updated every 5 minutes: attackers on a map, attacks per hour, and the usernames, passwords, and commands they tried |
| **Connectors** | Health, record counts, and refresh status for every data source |

### Query engine

KQL and SPL queries are translated into SQL and run against an in-memory SQLite database, so you can see the translated SQL for every search. The console is sandboxed: every query runs on a private read-only copy, only `SELECT` is allowed, and queries are cancelled after 10 seconds.

### Detection rules

| Severity | Rule |
|---|---|
| Critical | Ransomware-linked CVE added to CISA KEV in the last 7 days |
| Critical | Botnet command-and-control server attacked the honeypot |
| High | Ransomware-linked CVE added in the last 30 days |
| High | Exploited CVE in a widely used product (Fortinet, Ivanti, Cisco, Microsoft...) in the last 14 days |
| High | Botnet C2 server is online |
| High | IP on 8+ public blocklists |
| High | Phishing site impersonating a bank, crypto exchange, PayPal, or the IRS |
| High | Scam number with a large spike in FTC reports |
| High | IP on 5+ blocklists attacked the honeypot |
| Medium | Any other CVE added in the last 14 days |
| Medium | Attacker seen doing 3+ kinds of attacks |
| Medium | Phishing site impersonating any other major brand (lookalike detection) |
| Medium | Mass-reported scam number |
| Medium | 100+ attempts from one IP against the honeypot |
| Low | CVE added 15 to 30 days ago |
| Low | Tor exit node with abuse reports, or attacking the honeypot |
| Low | Phishing page hosted on a free platform (Vercel, GitHub Pages, Netlify...) |

### Phone and email checks

These are **reputation checks**. They show whether a number, address, or domain is linked to scams, spam, or phishing, not who owns it.

- **Phone:** FTC scam and robocall reports, validity, line type (VoIP, toll-free, premium rate), region, optional IPQualityScore fraud score
- **Email / domain:** live phishing hosting (OpenPhish), disposable providers, brand-impersonation lookalikes, domain age (RDAP), MX/SPF/DMARC records, optional IPQualityScore fraud score

## Data sources

| Source | Table | What it provides | Key |
|---|---|---|---|
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | `kev` | Vulnerabilities exploited in the wild | No |
| [IPsum](https://github.com/stamparm/ipsum) | `malicious_ips` | IPs on 30+ public blocklists, with a score | No |
| [abuse.ch Feodo Tracker](https://feodotracker.abuse.ch/) | `botnet_c2` | Botnet command-and-control servers | No |
| [blocklist.de](https://www.blocklist.de/en/export.html) | `attack_reports` | IPs caught attacking servers, by type (SSH, web, mail, FTP, SIP...) | No |
| [CINS Army](https://cinsarmy.com/) | `cins_army` | IPs with very poor reputation, mostly scanners | No |
| [Tor Project](https://check.torproject.org/torbulkexitlist) | `tor_exits` | Current Tor exit nodes | No |
| [GreenSnow](https://greensnow.co/) | `greensnow` | IPs caught brute-forcing and scanning | No |
| [Binary Defense](https://www.binarydefense.com/banlist.txt) | `binary_defense` | IPs hitting their honeypots (non-commercial use) | No |
| [SANS ISC DShield](https://isc.sans.edu/) | `top_attacking_subnets` | Top 20 attacking networks of the last 3 days (CC BY-NC-SA) | No |
| [Spamhaus DROP](https://www.spamhaus.org/blocklists/do-not-route-or-peer/) | `hijacked_netblocks` | Hijacked or criminal-run networks | No |
| [Ransomware.live](https://www.ransomware.live/) | `ransomware_victims` | Latest victims posted on ransomware leak sites | Free key (ransomware.live/my) |
| [Have I Been Pwned](https://haveibeenpwned.com/PwnedWebsites) | `data_breaches` | Public data breach catalog | No |
| [FIRST EPSS](https://www.first.org/epss/) | `epss` (also on `kev`) | Chance each exploited CVE gets used in the next 30 days | No |
| [Phishing Army](https://phishing.army/) + [CERT Polska](https://cert.pl/en/warning-list/) | `phishing_domains` | Phishing and scam domains (personal use) | No |
| [SANS ISC DShield API](https://isc.sans.edu/api/) | `dshield_top_ips` | Top 1,000 attacking IPs worldwide | No |
| [IPtoASN via ip-location-db](https://github.com/sapics/ip-location-db) | — | Registered country for every IP, offline (public domain) | No |
| All IP feeds combined | `ip_intel` | One row per IP: attack type, every feed it's in, blocklist score, risk score | — |
| [OpenPhish Community](https://github.com/openphish/public_feed) | `phishing_urls` | Live phishing URLs (non-commercial use) | No |
| [FTC Do Not Call data](https://www.ftc.gov/policy-notices/open-government/data-sets/do-not-call-data) | `scam_calls` | Phone numbers reported for unwanted calls (daily CSVs, or the official FTC API as a fallback) | Optional (api.data.gov) |
| [disposable-email-domains](https://github.com/disposable-email-domains/disposable-email-domains) | `disposable_domains` | Throwaway email providers | No |
| [Our Cowrie honeypot](https://github.com/realzephaniahjohnson/mothlight-honeypot-data) | `honeypot` | Live SSH attacks: login attempts, commands, and malware downloads (updated every 5 minutes) | No |
| ip-api.com, Shodan InternetDB, Google DNS, RDAP | — | Enrichment in Investigate | No |
| [AbuseIPDB](https://www.abuseipdb.com/), [IPQualityScore](https://www.ipqualityscore.com/) | — | Extra scores in Investigate | Optional, free |

## Skills demonstrated

- Collecting and normalizing threat intelligence from multiple OSINT sources
- Writing detection rules and triaging alerts by severity
- Threat hunting with KQL and SPL, and translating both into SQL
- IOC enrichment for IPs, domains, emails, and phone numbers
- Phishing analysis: lookalike domains, domain age, email authentication (SPF/DMARC)
- Running a live SSH honeypot (Cowrie on Oracle Cloud) and shipping its logs into the SIEM through a least-privilege pipeline
- Correlating honeypot telemetry with external threat feeds
- Secure design: sandboxed read-only query engine, API keys kept out of the repo

## Honeypot data

Mothlight shows live attacks from our own [Cowrie](https://github.com/cowrie/cowrie) SSH honeypot running on an
Oracle Cloud VM in Montreal. The pipeline:

```
attackers ──► Cowrie (fake SSH on port 22) ──► cowrie.json
                                                  │  every 5 min (cron, unprivileged user)
                                                  ▼
                       honeypot/export_cowrie.py: keep login attempts, commands, downloads;
                       drop private IPs and our own addresses; cap field length and row count
                                                  │  deploy key that can only write to one repo
                                                  ▼
                       github.com/realzephaniahjohnson/mothlight-honeypot-data (honeypot.csv)
                                                  │  Mothlight re-reads it every 5 minutes
                                                  ▼
                       Honeypot page, globe arcs, honeypot alert rules, `honeypot` search table
```

The real SSH port is only reachable over Tailscale, so nothing on the VM accepts admin logins from the internet.
Everything in the data was typed by attackers, so Mothlight treats it as untrusted: it's size-capped, validated,
and only shown in escaped tables. CSV exports neutralize spreadsheet formulas.

## Project structure

```
app.py            # Pages, alerts, charts, and layout
feeds.py          # Downloads, caches, and cleans each data feed
query_engine.py   # KQL/SPL-to-SQL translator and sandboxed query runner
checks.py         # Reputation checks for IPs, CVEs, emails, phone numbers, and domains
globe3d.py        # 3D night-lights threat globe (globe.gl / WebGL)
honeypot/         # Export job that runs on the honeypot VM
.streamlit/       # Theme and server settings
```

## Team

Mothlight was designed and built by:

- **Zephaniah Johnson**
- **Zakari Gilmer**
- **Bofelo Gaeonale**
