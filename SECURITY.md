# Security Policy

## Reporting a vulnerability
Please report security issues privately by contacting the owner through their GitHub profile
(github.com/realzephaniahjohnson). Don't open a public issue, and don't access other people's data or
disrupt the live site while testing. You'll get a reply as soon as possible, and fixes will be credited
if you'd like.

## How Mothlight protects secrets
- API keys live only in `.env` (local) or Streamlit Secrets (hosted). Both are git-ignored and never committed.
- Keys are used server-side only and are never sent to the browser. They're redacted from every error message.
- Visitors can use their own keys for the current session only. Those keys are never saved or logged.
- The search console runs on a read-only, size- and time-limited copy of the data.
- Searches, lookups, and data refreshes are rate limited per visitor and site-wide.
