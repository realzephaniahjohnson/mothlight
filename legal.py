"""Privacy Policy and Terms of Use shown on the Privacy & Terms page."""

EFFECTIVE = "November 9, 2026"
TEAM = "Zephaniah Johnson, Zakari Gilmer, and Bofelo Gaeonale"
CONTACT = "[github.com/realzephaniahjohnson](https://github.com/realzephaniahjohnson)"

PRIVACY = f"""
**Effective {EFFECTIVE}**

Mothlight is a free, non-commercial threat intelligence and security learning project built and run by
Zephaniah Johnson, Zakari Gilmer, and Bofelo Gaeonale ("we", "us"). This policy explains what happens to information when you use Mothlight.
The short version: **we don't have accounts, ads, analytics, or trackers, and we don't keep what you search.**

#### 1. What we collect
- **Nothing that identifies you, on purpose.** There are no accounts, sign-ups, ads, analytics, tracking
  pixels, or fingerprinting. Streamlit's built-in usage statistics are turned off.
- **We don't record keystrokes.** Text boxes are only sent to the server when you press Enter or click a button,
  and what you type is not logged or saved.
- **Rate-limit counters.** To stop abuse, we keep the *times* of recent searches and lookups (not their contents)
  in memory for up to 15 minutes.
- **Attack data from our honeypot, not from visitors.** Our honeypot is a fake SSH server that exists only to be
  attacked. It records the IP address, login attempts, and commands of systems that connect to it and try to break
  in, and we publish the last 7 days of that data for security research and network defense (a legitimate interest
  recognized in GDPR Recital 49). It never includes people who visit this website. If you believe an entry is about
  you and was recorded in error, contact us and we'll remove it.

#### 2. What you submit
- **Searches and indicators** (IP addresses, domains, emails, phone numbers, CVE IDs) are processed only to show you
  results. They are held in server memory while your session is open and, for some lookups, in a short-lived
  cache (10 minutes for emails and phone numbers, up to 1 hour for IPs and domains) so the same lookup isn't sent
  to an outside service twice. Caches are not linked to you and clear automatically. Nothing is written to a
  database, sold, or shared beyond the services in section 4.
- **Your own API keys** (optional) stay in your browser session only. They are never written to disk, logged,
  displayed back, or shared. They're used only to call that provider for you, and they're gone when you close
  the tab. The site never sends a key back to your browser, and the site's own keys never leave the server.
- **Uploaded files** (honeypot logs, max 20 MB) are read in memory for your session only and are not saved.

Please only look up people's emails or phone numbers when you have a legitimate security reason (for example,
checking a suspicious message you received).

#### 3. Cookies
Mothlight doesn't set its own cookies. The hosting platform (Streamlit) uses strictly necessary cookies to keep
your session working and to protect against cross-site request forgery. No advertising or tracking cookies are used.

#### 4. Third parties that may receive data
- **Hosting:** Streamlit Community Cloud (operated by Snowflake Inc.) hosts the site and, like any web host, may
  process technical data such as your IP address and browser type under its own privacy policy. Streamlit's
  app analytics show the site owner view counts and, only if you're signed in to Streamlit, your Streamlit username.
- **Globe graphics:** the 3D globe loads code and images from jsDelivr and GitHub. Like any website, they can see
  your IP address. We tell your browser not to send them the page address (no-referrer).
- **Lookups you run on the Investigate page:** depending on what you check, the indicator is sent to Google Public
  DNS, RDAP (rdap.org), Shodan InternetDB, and ip-api.com, and, only if a key is present, AbuseIPDB and
  IPQualityScore. Each service handles data under its own policy.
- **Threat feeds** are downloaded by our server, not your browser, so the feed providers don't see you.

#### 5. Retention
We don't keep personal data after your session ends, apart from the short-lived caches and counters above.
Public threat feed data is cached for up to 24 hours.

#### 6. Security
Measures include: server-side only API keys, keys redacted from every error message, a read-only and
resource-limited search engine, escaped output, upload limits, and rate limiting. No system is perfectly secure,
so please don't submit information you're not comfortable sending over the internet.

#### 7. Children
Mothlight is not directed to children under 13 (or under 16 where local law sets a higher age), and we don't
knowingly collect their personal information.

#### 8. Your privacy rights
Depending on where you live (for example under the GDPR, UK GDPR, or US state laws like the CCPA/CPRA), you may
have rights to access, correct, delete, or object to processing of your personal data. Because we don't keep
personal data tied to you, there is usually nothing to return or delete, but you can still contact us.
We **do not sell or share** personal information for advertising, and we don't use it to make automated decisions
about you. Where the GDPR applies, our legal basis for processing what you submit is our legitimate interest in
providing a security research tool you've chosen to use. You also have the right to complain to your local data
protection authority.

#### 9. International users
The site is hosted in the United States. By using it, you understand your requests are processed there.

#### 10. Changes
We may update this policy. The effective date above shows when it last changed. Continued use after a change
means you accept the updated policy.

#### 11. Contact
Mothlight is run by {TEAM}. Questions, privacy requests, or security reports: {CONTACT}.
"""

TERMS = f"""
**Effective {EFFECTIVE}**

By using Mothlight you agree to these terms. If you don't agree, please don't use the site.

#### 1. What Mothlight is
A free, non-commercial tool for defensive security research, threat hunting, and education. It combines public
threat intelligence feeds and lets you search and check indicators.
Mothlight is built and run by Zephaniah Johnson, Zakari Gilmer, and Bofelo Gaeonale (together, "the operators").

#### 2. Acceptable use
You may use Mothlight for lawful defensive security, research, and learning. You must **not**:
- break any law, or use the site to plan, support, or carry out an attack on any system;
- harass, stalk, dox, threaten, or try to identify or locate a person;
- use results to make decisions about a person's eligibility for credit, insurance, employment, housing, or any
  other purpose covered by the U.S. Fair Credit Reporting Act or similar laws;
- overload, scrape, or abuse the site or the services behind it, or try to get around rate limits or security
  controls;
- try to access, extract, or misuse API keys, server data, or other users' sessions;
- upload malware, illegal content, or data you don't have the right to share.

We may block access or limit use at any time to protect the site, its users, or third parties.

#### 3. Not a consumer report
Mothlight is **not a consumer reporting agency** and its results are **not consumer reports**. Email and phone
checks show reputation signals only (for example scam or spam reports). They never identify who owns a number or
address.

#### 4. Accuracy of data
Results come from third-party and public sources that can be incomplete, out of date, or wrong. An IP, domain,
email, or phone number appearing in a feed does **not** prove that any person or organization did anything wrong.
Verify findings independently before acting on them, and don't block, report, or accuse anyone based only on
Mothlight.

#### 5. Third-party data and licenses
Each data source keeps its own license and terms, and you're responsible for following them if you reuse data.
Several sources are free for **personal or non-commercial use only**, including Phishing Army, Binary Defense,
SANS ISC DShield, Ransomware.live, and the OpenPhish community feed. Breach data comes from Have I Been Pwned
(CC BY 4.0). Scam call data comes from the U.S. Federal Trade Commission. Mothlight is not affiliated with or
endorsed by any data provider. All trademarks belong to their owners.

#### 6. Your content
You're responsible for what you submit or upload, and you confirm you have the right to do so.

#### 7. No warranty
Mothlight is provided **"as is" and "as available"**, without warranties of any kind, express or implied,
including merchantability, fitness for a particular purpose, accuracy, availability, and non-infringement.

#### 8. Limitation of liability
To the fullest extent allowed by law, the operators will not be liable for any indirect, incidental, special,
consequential, or punitive damages, or any loss of data, profits, or business, arising from your use of (or
inability to use) Mothlight or any data from it. The operators' total liability for any claim is limited to the
amount you paid to use the site, which is zero. Some places don't allow certain limitations, so some of these may
not apply to you.

#### 9. Indemnity
You agree to defend and hold harmless the operators from claims, losses, and costs (including reasonable legal
fees) arising from your misuse of Mothlight or your violation of these terms or of any law or third-party right.

#### 10. Availability and changes
Features, data sources, and limits may change, pause, or end at any time without notice. We may update these terms;
the effective date shows the latest version, and continued use means you accept it.

#### 11. Security research
Found a vulnerability in Mothlight itself? Please report it privately through {CONTACT} and give a reasonable time
to fix it before sharing. Don't access other people's data or disrupt the service while testing.

#### 12. Who runs Mothlight
Mothlight is built and run by {TEAM}. Contact: {CONTACT}.

#### 13. General
These terms are governed by the laws of the State of New York, USA, without regard to conflict-of-law rules, and
disputes will be handled in the state or federal courts located in New York, except where your local law gives
you the right to bring claims elsewhere. If any part of these terms is found unenforceable, the rest stays in
effect. Not enforcing a term is not a waiver. These terms and the Privacy Policy are the full agreement between
you and the operators about Mothlight.
"""
