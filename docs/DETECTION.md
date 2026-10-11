# Detection engine

NetHunter never turns a single fact into a verdict. Every signal becomes an **evidence item** with a plain-language
reason and a strength between 0 and 1. The engine combines them into:

* **Risk score (0–100)** — noisy-OR combination: `score = 100 × (1 − Π(1 − strength))`, then scaled down by mitigating
  evidence (negative strength, e.g. an analyst *Trusted* mark or an AbuseIPDB whitelist). One weak signal stays weak;
  several independent signals reinforce each other with diminishing returns.
* **Confidence (0–99 %)** — grows with the number of *independent evidence categories*, whether the process could be
  attributed, and whether threat intelligence was consulted. A single signal never yields high confidence.
* **Classification** — kept distinct on purpose:

| Class | Meaning |
|---|---|
| *Suspicious behavior* | Behavioural anomalies only (score ≥ 35) |
| *IOC reputation match* | A reputation provider reports the indicator, score ≥ 35 |
| *Possible C2 communication* | Beaconing with score ≥ 50, or bad reputation + other categories with score ≥ 60 |
| *Known malicious indicator* | On the analyst's **own** local IOC list, or a file hash detected by ≥ 10 VirusTotal engines |

"Possible C2" is a hypothesis for an analyst; the UI, reports and alerts say so explicitly.

## Severity levels

| Score | Level | Colour + label |
|---|---|---|
| — (not yet assessed) | Unknown | grey `? UNKNOWN` |
| 0–34 | Low | green `✓ LOW` |
| 35–59 | Medium | yellow `⚠ SUSPICIOUS` |
| 60–84 | High | orange `▲ HIGH` |
| 85–100, or *Known malicious* | Critical | red `✖ CRITICAL` |

Alerts are created at or above the configured level (default *Medium*; set *Low* to also alert on first-seen and
unknown destinations). An alert always shows its strongest assessment; weaker re-assessments never overwrite its
evidence. Alerts re-open when severity escalates.

## Signals

### Reputation
| Signal | Strength |
|---|---|
| Local IOC list match (IP, CIDR, domain or parent domain, SHA-256) | 0.95 → *Known malicious* |
| VirusTotal file hash ≥ 10 / 3–9 / 1–2 engines | 0.90 / 0.60 / 0.20 |
| VirusTotal IP/domain ≥ 5 / 2–4 / 1 engines | 0.60 / 0.35 / 0.12 |
| AbuseIPDB confidence ≥ 75 % / 25–74 % / reports with < 25 % | 0.50 / 0.25 / 0.06 |
| AbuseIPDB whitelisted | −0.20 |
| Hash unknown to VirusTotal | 0.05 (explicitly "not proof of anything") |

### Network behaviour
| Signal | Strength |
|---|---|
| Possible beacon (see below) | 0.25 + 0.35 × beacon confidence |
| Port associated with RATs/IRC/Tor/mining (4444, 1337, 6667, 9050…) | 0.25 |
| Unusual destination port / ephemeral-range port | 0.08 / 0.10 |
| ≥ 5 (≥ 20) failed connection attempts | 0.10 (0.20) |
| Direct-to-IP (no DNS answer observed for the IP, while DNS visibility is on) | 0.06 |
| Long-lived outbound connection (> 1 h) | 0.05 |
| Inbound from an external address | 0.05 (common port) / 0.12 |

Port 443, a cloud provider, a public IP, missing PTR, or "unknown to VirusTotal" are **never** enough on their own.

### Process behaviour
| Signal | Strength |
|---|---|
| System binary name from the wrong path (masquerading) | 0.60 |
| Invalid Authenticode signature | 0.45 |
| Runs from the Recycle Bin / Temp / `C:\Users\Public` | 0.45 / 0.30 / 0.30 |
| Runs from Downloads / ProgramData root / AppData\Roaming / AppData\Local | 0.15 / 0.15 / 0.12 / 0.05 |
| Unsigned executable talking externally | 0.15 |
| Living-off-the-land binary talking externally (mshta, regsvr32, rundll32, certutil, powershell…) | 0.15–0.45 |
| Office application spawned a script host; svchost not started by services.exe | 0.40 / 0.35 |
| Connection within 30 s of process start | 0.04 |

### Domain and DNS behaviour
| Signal | Strength |
|---|---|
| DGA-like registrable domain (entropy, digit mix, consonant runs) | 0.25 (0.03 under a known CDN) |
| Random-looking subdomain | 0.12 |
| Dynamic-DNS / tunnelling service (duckdns, no-ip, ngrok, trycloudflare…) | 0.22 |
| Frequently abused TLD (configurable) | 0.12 |
| Very long hostname / deep nesting / punycode | 0.10 / 0.08 / 0.06 |
| ≥ 30 unique long subdomains of one domain in 10 min (tunnelling) | 0.45 |
| ≥ 50 unique subdomains of one domain in 10 min (churn) | 0.20 |
| ≥ 300 queries for one domain in 10 min (volume) | 0.10 |
| ≥ 10 TXT queries for one domain in 10 min | 0.30 |
| ≥ 25 distinct NXDOMAIN names in 10 min (DGA) | 0.30 |
| ≥ 10 distinct IPs for a name in 1 h (fast-flux), low TTL | 0.10–0.20 (0.02 for CDNs) |

Known CDN/cloud suffixes (configurable) reduce randomness and churn weights; they are never whitelisted.

### Baseline
After the learning period (default 24 h) the engine notes when a process contacts a destination group (registrable
domain, or /24 IPv4 / /48 IPv6 network) it never used before (0.05), a destination the machine has never contacted
(0.10), or when a process that never made external connections suddenly does (0.15). During learning only a 0.03 note
is added. Nothing is whitelisted automatically; analysts mark items **Trusted / Ignored / Suspicious** manually
(Suspicious adds 0.4; Trusted subtracts 0.6 and suppresses alerts, except for local IOC matches).

## Beacon detection

Input: start times of new connections for one *(process, destination IP or hostname, port)*.

1. Collapse bursts (contacts < 2 s apart count once — browsers open parallel sockets).
2. Need ≥ 4 contacts. Gaps between contacts are computed; the period is the median gap, corrected downward when the
   median is a multiple of the typical gap (missed beats).
3. Each gap is matched to *k × period* (k = 1…4, residual ≤ 25 %). `fitRatio` = fraction of gaps that fit.
4. Jitter = coefficient of variation of the normalised gaps, after removing the variance explained by the collector's
   sampling resolution (poll interval).
5. `regularity = clamp(1 − jitter / 0.35)`, `confidence = regularity × fitRatio × min(1, 0.55 + 0.05 × gaps)`.
6. A possible beacon is reported when confidence ≥ 0.5 and the period is between 5 s and 6 h.

Example from the specification — contacts at 12:00:01, 12:01:02, 12:02:01, 12:03:03 — gives
*Possible periodic beacon, interval ≈ 60 s*. Jittered beacons (±20 %) are still detected; random human browsing is not
(both are unit-tested).

## Process attribution rules

* PID comes only from the kernel tables / ETW records. PID 0 (TIME_WAIT sockets) is shown as **Process: Unknown**.
* PID reuse is guarded by comparing process creation times; a "parent" that started after its child is discarded.
* When the path cannot be read the reason is shown (e.g. *Access denied: run as administrator*), never a guess.
* PCAP flows are always *Process: Unknown*.
