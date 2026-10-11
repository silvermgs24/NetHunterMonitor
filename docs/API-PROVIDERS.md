# Reputation providers (API configuration)

Reputation is **optional**. Without any API key NetHunter still monitors, attributes processes, hashes executables,
checks your local IOC lists and analyses behaviour. When the Internet is unavailable the UI shows
*Threat intelligence unavailable*, monitoring continues, and queued lookups resume automatically.

## AbuseIPDB (IP addresses)

1. Create a free account at <https://www.abuseipdb.com/register> and create an API key under *Account → API*.
2. In NetHunter: **Settings → Threat intelligence providers → Enable AbuseIPDB**, paste the key, **Save settings**.
3. Default limits: 30 requests/minute, 1 000/day (free plan). Adjust if your plan differs.

Request: `GET https://api.abuseipdb.com/api/v2/check?ipAddress=<ip>&maxAgeInDays=90` with header `Key: <api key>`.
Shown: abuse confidence, total reports, distinct reporters, country, ISP, usage type, domain, last reported,
whitelist flag. AbuseIPDB data is one signal: ≥ 75 % confidence adds 0.5, 25–74 % adds 0.25.

## VirusTotal (IP addresses, domains, file hashes)

1. Create an account at <https://www.virustotal.com/> and copy your API key from your profile → *API key*.
2. **Settings → Enable VirusTotal**, paste the key, **Save settings**.
3. Default limits: 4 requests/minute, 500/day (public API). Premium keys can raise them.

Requests: `GET https://www.virustotal.com/api/v3/ip_addresses/<ip>`, `/domains/<domain>`, `/files/<sha256>` with
header `x-apikey`. Shown: malicious / suspicious / total engines, community reputation, country / AS owner, file name.

**Files are never uploaded automatically.** Only the SHA-256 is looked up. *Upload file to VirusTotal…* in a
connection's detail panel is a separate action that asks for confirmation and warns that uploaded files become
available to VirusTotal and its partners. Uploads > 32 MB are refused.

## What is sent, and when

| Indicator | Sent to | Conditions |
|---|---|---|
| Public destination IP | AbuseIPDB, VirusTotal | Provider enabled, key set, threat intel allowed, not cached |
| Domain name | VirusTotal | As above + *Look up domain names* enabled |
| Executable SHA-256 | VirusTotal | As above + *Look up executable hashes* enabled |

Never sent: private / loopback / link-local / multicast / documentation addresses, process names or paths, packet
contents, files (unless you explicitly upload), your local IOC lists. Synthetic test data is never sent anywhere.
Every outbound query is listed under **Settings → Threat-intelligence activity** and written to the log.

## Rate limits, queueing and caching

* Each provider has its own worker, **priority queue** (suspicious, unsigned and non-browser activity first, max 5 000
  pending, lowest priority dropped first) and **sliding-window limiter** (per minute and per day).
* HTTP 429 / quota errors block that provider until `Retry-After` (default 1 minute).
* Results are cached (`IOC → reputation → expiry`) for `ReputationCacheHours` (default 24 h) in memory **and** in
  SQLite, so restarts do not spend quota again. Provider errors are cached for 15 minutes; rate-limit and offline
  outcomes are not cached.
* Network failures mark threat intelligence offline; the item is re-queued and retried after 60 s.

## Security

* HTTPS only (enforced in code), default certificate validation, 20 s timeout, 4 MB response limit.
* Responses are validated field by field (types, ranges, the IP in the answer must match the query); malformed
  responses become *Error* results, never exceptions.
* Keys are DPAPI-encrypted at rest, never logged and never displayed after saving.

## Adding a provider

Implement `IRemoteReputationProvider` (or derive from `HttpReputationProvider`, which already handles TLS, timeouts,
status codes, size limits and rate-limit headers), map the response to `ReputationResult`, add a scoring rule in
`RiskScorer.FromReputation`, and register it in `AppHost.Create`. Add parsing tests like those in `IntelTests.cs`.
