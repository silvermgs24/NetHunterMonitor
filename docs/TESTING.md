# Testing

## Automated tests

```powershell
dotnet test NetHunterMonitor.sln
```

| Suite | Tests | Runs on | Covers |
|---|---|---|---|
| `NetHunter.Core.Tests` | 105 | any OS | AbuseIPDB & VirusTotal parsing (valid, error, malformed, out-of-range, mismatched answers), provider HTTP behaviour (HTTPS, headers, 401, 429 + Retry-After, network failure, disabled/keyless), API caching (TTL, persistence across restarts, error/offline handling), rate limiting, offline mode (service status and engine continuing with local IOC detection), local IOC matching (IP, CIDR, IPv4-mapped IPv6, domain parents, URL, hash, defanged input, import), DNS wire parsing (compression, NXDOMAIN, loop protection), Windows DNS-Client result parsing, TLS SNI and HTTP Host extraction, pcap and pcapng reading incl. truncated/garbage input, SHA-256 known vectors, IP scope classification, registrable-domain logic, beacon detection (spec example, jitter, missed beats, random traffic, bursts), risk scoring (weak signals, reinforcement, classification, trusted marks, VT/AbuseIPDB grading, explanation), domain/DNS behaviour (DGA, CDN discount, tunnelling, NXDOMAIN bursts), process heuristics (masquerading, LOLBins, Office parent, unknown process), baseline, engine end-to-end (beacon → Possible C2 alert with reasons, unknown attribution, DNS → hostname, trusted suppression, alert not downgraded after restart, synthetic scenario), database storage & SQL-injection-safe search, retention, exports (CSV injection, HTML encoding, JSON), settings (encrypted keys, sanitising, corrupt file) |
| `NetHunter.Windows.Tests` | 14 | Windows | **Real** process-to-connection attribution: opens TCP connections in the test process and checks the IP Helper table reports this PID, path and SHA-256; polling source open/close events with direction; TCP+UDP listeners; exited-process handling; PID 0/4; Authenticode (Microsoft-signed, catalog-signed, unsigned, tampered → invalid); DPAPI round-trip and tamper rejection; PTR reverse-name construction; DNS cache read & grouping; ETW sources refusing cleanly without admin |

All 119 tests pass on the development machine (Windows 11 Enterprise 22H2, build 22621, non-elevated).

## Controlled synthetic test mode (no malware required)

* **Desktop**: *Settings → Restart in synthetic test mode* (or `NetHunterMonitor.exe --synthetic`). A purple banner marks
  the mode. A generator replays clearly-labelled events through the real engine for 10 minutes:
  * `SYNTHETIC-beacon.exe` (unsigned, in a Temp folder) contacting `203.0.113.50:443` every ~10 s ± 8 % → **Possible C2 beacon**
  * `powershell.exe` started by `winword.exe` polling `198.51.100.23:8080` every ~15 s → **Possible C2 beacon**
  * `SYNTHETIC-updater.exe` contacting `203.0.113.66:4444` / `evil-c2.example` (on the synthetic IOC list) → **Known malicious indicator**
  * `SYNTHETIC-dnstunnel.exe` sending long random TXT queries → **Possible DNS tunnelling**
  * `SYNTHETIC-browser.exe` irregular browsing → stays **LOW**
* **CLI**: `nethunter synthetic` runs the same scenario instantly and prints alerts with reasons.
* **PCAP**: `samples\synthetic-beacon-sample.pcap` (see `samples\README.md`).

Synthetic data uses RFC 5737 addresses and `.example` names only, is stored in `database\synthetic-test.db`, and is
never sent to reputation providers.

## Manual verification checklist (Windows 10 and Windows 11)

1. Extract the release zip to a writable folder, run `NetHunterMonitor.exe` (no install, no .NET runtime needed).
2. The yellow banner explains what works without administrator rights; monitoring starts automatically.
3. Browse a few websites: rows appear in *Live traffic* within ~1 s; hostnames appear within the DNS-cache poll interval.
4. *Connections* → select a row: process, PID, path, SHA-256, signature, destination, DNS hostname / PTR, reputation and
   reasons are shown.
5. `nethunter snapshot` lists the same connections with paths, hashes and signatures.
6. Click *Restart as administrator*, accept UAC: the banner disappears and the dashboard lists the ETW collectors.
   Short-lived connections (e.g. `curl https://example.com`) now appear with their process, and the *DNS* page shows
   the requesting process.
7. Disconnect the network: the *Threat intelligence unavailable* banner appears once a lookup fails; live monitoring
   continues.
8. Run synthetic test mode and confirm the four detections above.
9. *PCAP → Open capture…* → `samples\synthetic-beacon-sample.pcap`: the beacon, DNS tunnelling and failed connections
   are reported.
10. *Stop monitoring*, close the app, delete the folder: nothing was installed (no services, drivers, scheduled tasks or autostart entries).

## Verification status

| Item | Status |
|---|---|
| Unit + Windows integration tests (119) | ✅ pass |
| Non-elevated live monitoring: TCP attribution, path/hash/signature, DNS cache hostnames, listeners | ✅ verified on Windows 11 22H2 |
| Synthetic test mode end-to-end in the desktop UI | ✅ verified |
| PCAP import end-to-end (CLI and UI) with the synthetic sample | ✅ verified |
| Portable self-contained single-file publish, first run from an empty folder | ✅ verified |
| **Elevated mode (ETW kernel TCP/IP and DNS-Client real-time tracing)** | ⚠ implemented with the official TraceEvent library, but **not executed** on the development VM (no interactive UAC approval available during the build). If ETW cannot start, the app logs the reason and continues with polling. |
| **Windows 10** | ⚠ not tested on a Windows 10 machine; only APIs available since Windows 8 are used (`MSFT_DNSClientCache` WMI class, `CryptCATAdminAcquireContext2`, IP Helper, ETW). |
| Live AbuseIPDB / VirusTotal queries | ⚠ parsing and HTTP behaviour are tested against recorded-format responses; no API keys were available, so no live query was made. |
