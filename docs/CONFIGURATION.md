# Configuration

## Folder layout (portable)

Everything lives next to the executable. Delete the folder to remove the application completely.

```
NetHunterMonitor\
├── NetHunterMonitor.exe        desktop application (self-contained, no .NET install needed)
├── nethunter.exe               command-line companion (optional)
├── config\
│   ├── settings.json           all settings (API keys DPAPI-encrypted)
│   └── ioc\                    your IOC lists (*.txt), loaded at start-up and on import
├── database\
│   ├── nethunter.db            live monitoring history (SQLite)
│   ├── synthetic-test.db       synthetic test mode only
│   └── pcap\                   one database per PCAP investigation
├── logs\nethunter-YYYYMMDD.log operational and security-relevant log (no API keys)
└── exports\                    (suggested location for reports)
```

If the executable's folder is not writable (for example under `C:\Program Files`), data goes to
`%LOCALAPPDATA%\NetHunterMonitor` instead and the path is shown at the bottom of the navigation bar.

## Settings (Settings page or `config\settings.json`)

| Key | Default | Meaning |
|---|---|---|
| `PollIntervalMs` | 1000 | TCP table polling interval (250–10000 ms) |
| `DnsCachePollSeconds` | 5 | DNS cache polling interval (2–300 s) |
| `UseEtwWhenElevated` | true | Use real-time ETW kernel/DNS tracing when running as administrator |
| `IncludeLoopback` | false | Track 127.0.0.1 / ::1 traffic |
| `IncludeLanTraffic` | true | Track private/LAN destinations (never sent to reputation services) |
| `ResolvePtr` | true | Reverse-DNS lookups for external IPs |
| `HashExecutables` | true | Compute SHA-256 of executables that use the network |
| `VerifySignatures` | true | Authenticode verification (embedded + Windows catalogs) |
| `RetentionHours` | 168 | 1, 6, 24, 168 (7 d), 720 (30 d) or 0 = unlimited |
| `NotificationsEnabled` | true | Tray balloon notifications |
| `MinimumNotificationLevel` | High | Medium / High / Critical |
| `MinimumAlertLevel` | Medium | Low / Medium / High / Critical (Low also alerts on first-seen destinations) |
| `ThreatIntelEnabled` | true | Master switch for all external lookups (local IOC lists always work) |
| `ReputationCacheHours` | 24 | How long provider answers are reused |
| `LookupFileHashes` | true | Send SHA-256 hashes to VirusTotal (hash only) |
| `LookupDomains` | true | Send domain names to VirusTotal |
| `AbuseIpDb` / `VirusTotal` | disabled | `Enabled`, `ProtectedApiKey` (DPAPI), `RequestsPerMinute`, `RequestsPerDay` |
| `BaselineLearningHours` | 24 | Learning period before "new destination" signals get full weight |
| `SuspiciousTlds` | list | TLDs that add a small domain signal |
| `CdnSuffixes` | list | CDN/cloud suffixes whose random-looking names are discounted (never whitelisted) |

Invalid values are clamped on load. A corrupt `settings.json` is preserved as `settings.json.corrupt` and defaults
are used, so monitoring still starts.

API keys must be entered through the Settings page (they are encrypted with DPAPI for the current Windows user).
A copied `settings.json` will not decrypt on another account or machine: re-enter the keys there.

## Local IOC lists

Put text files in `config\ioc\` or use **IOC → Import IOC list…** (the file is copied into that folder).

```text
# comment
185.220.101.1                   # IPv4 or IPv6
10.66.0.0/16, internal C2 range # CIDR (comment after comma, tab, space or " #")
evil.example.com                # domain: also matches every subdomain
hxxp://bad[.]example/payload    # URL (defanged input accepted)
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

Names such as `malicious_ips.txt`, `malicious_domains.txt` and `hashes.txt` are fine; the type of each line is detected
automatically. Lists are checked locally **before** any external service and work offline. A match always produces a
*Known malicious indicator* (Critical) alert that an analyst *Trusted* mark cannot suppress: remove the entry from the
list instead.

## Analyst marks

From any detail panel you can mark an IP, domain, process or hash as **Trusted**, **Ignored** or **Suspicious**
(stored in the `marks` table). Nothing is ever marked automatically.

## Command-line options

| Program | Option | Effect |
|---|---|---|
| `NetHunterMonitor.exe` | `--synthetic` | Start in synthetic test mode |
| `nethunter.exe` | `status`, `snapshot`, `listeners`, `dns-cache`, `watch [s]`, `synthetic`, `pcap <file>`, `check <ioc>`, `hash <file>`, `make-sample-pcap <file>` | See `nethunter help` |
