# Architecture

## 1. Technology choice

**C# / .NET 8 + WPF, published self-contained single-file for win-x64.**

| Requirement | Why this stack |
|---|---|
| Native Windows APIs (IP Helper, ETW, WinTrust, DPAPI, Toolhelp, WMI) | Direct P/Invoke with no wrapper layer; the official ETW library (TraceEvent) is .NET |
| Portable, no installer, no runtime to install | `PublishSingleFile` + `--self-contained`: one `NetHunterMonitor.exe` (≈70 MB) that carries the .NET runtime, WPF and native SQLite |
| Responsive UI with thousands of rows | WPF `DataGrid` with row/column virtualization and recycling; all collection work is batched once per second |
| Security engineering | Memory-safe managed code, parameterised SQLite, TLS with default certificate validation from `HttpClient` |
| Testability | Engine is a platform-neutral `net8.0` library tested on any machine; Windows collectors have their own tests that run against the real APIs |

Rejected alternatives: Electron/Node (large, extra runtime surface, weaker access to ETW/WinTrust), Python (needs an
interpreter, packaging is fragile), C++/Win32 (slower to build a rich, safe UI and parsers), kernel driver/WFP callout
(not needed: user-mode APIs give reliable process attribution; drivers need signing and add risk).

## 2. Components

```
                 ┌────────────────────────── NetHunter.Windows ──────────────────────────┐
 Windows ──────► │ IpHelperConnectionSource   EtwNetworkSource (admin)                   │
                 │ DnsCacheSource (WMI)       EtwDnsSource (admin)                       │
                 │ WindowsProcessInfoProvider AuthenticodeVerifier  SystemHostnameResolver│
                 │ DpapiProtector             AppHost (composition root, portable paths) │
                 └──────────────┬───────────────────────────────────────────────────────┘
                                │ ConnectionObservation / DnsObservation (facts only, PID nullable)
                 ┌──────────────▼──────────────── NetHunter.Core ─────────────────────────┐
                 │ MonitoringEngine (single consumer over a bounded channel)              │
                 │   1 process attribution ─► 2 hostname (DNS map, PTR, SNI)              │
                 │   3 SHA-256 + signature (background) ─► 4 local IOC lists              │
                 │   5 ReputationService ─► IReputationProvider: LocalIoc, AbuseIPDB, VT │
                 │   6 behaviour: BeaconTracker, Baseline, DomainAnalyzer, DnsBehavior    │
                 │   7 RiskScorer (evidence → score, confidence, class) ─► 8 alerts       │
                 │   9 Database (SQLite, WAL, batched writes, retention)                 │
                 │ PcapReader/PacketDecoder/PcapAnalyzer  Exporter  SyntheticScenario     │
                 └──────────────┬───────────────────────────────────────────────────────┘
                                │ EngineBatch (≈1/s)
                 ┌──────────────▼─────────── NetHunter.App (WPF) / NetHunter.Cli ─────────┐
                 │ LiveStore → pages: Dashboard, Connections, Processes, IOC, Alerts, DNS,│
                 │ Listening Ports, Timeline, PCAP, Settings, Search; tray notifications  │
                 └────────────────────────────────────────────────────────────────────────┘
```

Projects:

| Project | Target | Role |
|---|---|---|
| `NetHunter.Core` | net8.0 | Models, engine, detection, scoring, intel providers, cache, rate limiting, storage, PCAP, export, synthetic generator |
| `NetHunter.Windows` | net8.0-windows | Collectors and OS integration (P/Invoke, ETW, WMI, DPAPI), `AppHost` composition root |
| `NetHunter.App` | net8.0-windows (WPF) | Desktop UI → `NetHunterMonitor.exe` |
| `NetHunter.Cli` | net8.0-windows | Headless companion → `nethunter.exe` |
| `NetHunter.Core.Tests` / `NetHunter.Windows.Tests` | xUnit | See [TESTING.md](TESTING.md) |

### Interfaces between components

| Interface | Implementations |
|---|---|
| `IConnectionSource` | `IpHelperConnectionSource`, `EtwNetworkSource`, `SyntheticSource` |
| `IDnsSource` | `DnsCacheSource`, `EtwDnsSource`, `SyntheticSource` |
| `IProcessInfoProvider` | `WindowsProcessInfoProvider`, `SyntheticProcessProvider` |
| `ISignatureVerifier` | `AuthenticodeVerifier` |
| `IHostnameResolver` | `SystemHostnameResolver` (pure PTR query) |
| `IReputationProvider` / `IRemoteReputationProvider` | `LocalIocProvider`, `AbuseIpDbProvider`, `VirusTotalProvider` (add more by implementing the interface and registering in `AppHost`) |
| `IReputationStore`, `IBaselineStore` | `Database` |
| `ISecretProtector` | `DpapiProtector` |

## 3. Windows APIs used

| Purpose | API | Admin? |
|---|---|---|
| TCP connections + owning PID, listening ports | `GetExtendedTcpTable(TCP_TABLE_OWNER_PID_ALL)` (IPv4+IPv6) | No |
| UDP endpoints + owning PID | `GetExtendedUdpTable(UDP_TABLE_OWNER_PID)` | No |
| Real-time TCP connect/accept/disconnect, UDP send/recv with PID | ETW kernel provider `NetworkTCPIP` via TraceEvent | **Yes** |
| Real-time DNS queries/answers with requesting PID | ETW `Microsoft-Windows-DNS-Client` (events 3006/3008) | **Yes** |
| DNS cache contents (hostname ↔ IP) | WMI `root\StandardCimv2\MSFT_DNSClientCache` | No |
| Reverse DNS | `DnsQuery_W(…, DNS_TYPE_PTR)` | No |
| Process name and parent | `CreateToolhelp32Snapshot` / `Process32FirstW/NextW` | No |
| Process image path, start time | `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)`, `QueryFullProcessImageNameW`, `GetProcessTimes` | No for own-user processes; SYSTEM/other users need admin |
| Authenticode (embedded) | `WinVerifyTrust(WINTRUST_ACTION_GENERIC_VERIFY_V2)` | No |
| Authenticode (catalog-signed Windows binaries) | `CryptCATAdminAcquireContext2`, `CryptCATAdminCalcHashFromFileHandle2`, `CryptCATAdminEnumCatalogFromHash`, `WinVerifyTrust(WTD_CHOICE_CATALOG)` | No |
| API key protection | `CryptProtectData` / `CryptUnprotectData` (DPAPI, current user) | No |
| Elevation detection | `WindowsPrincipal.IsInRole(Administrator)` (false for UAC-filtered tokens) | — |

Signature checks run with revocation disabled and cache-only URL retrieval so verification never generates network
traffic. The manifest requests `asInvoker`; elevation is only obtained through a normal UAC prompt when the user clicks
**Restart as administrator**.

## 4. What requires administrator rights

| Capability | Standard user | Administrator |
|---|---|---|
| TCP connections with process attribution | ✓ (polled, default 1 s) | ✓ real-time ETW + polling |
| Connections shorter than the poll interval | Partly: TIME_WAIT remnants shown as *Process: Unknown* | ✓ |
| UDP peers (remote address) with PID | ✗ (only local UDP endpoints) | ✓ |
| DNS hostnames | ✓ from DNS cache (no PID) | ✓ every query with requesting PID |
| Path / hash / signature of own processes | ✓ | ✓ |
| Path / hash / signature of SYSTEM / other users' processes | ✗ (name and PID still shown) | ✓ (except protected processes) |
| Listening ports, IOC lists, reputation, beaconing, baseline, alerts, PCAP, exports | ✓ | ✓ |

The UI shows this as a banner when not elevated, and the CLI prints it with `nethunter status`.

## 5. Pipeline details

* **Collectors never block.** They post facts into a bounded channel (100 000 items, drop-oldest with a visible
  counter). A single consumer task owns all mutable engine state, so the logic needs no fine-grained locking.
* **Connection identity.** The tuple `(protocol, local ip:port, remote ip:port)` de-duplicates the same connection
  reported by ETW and by polling. PID 0 (TIME_WAIT) is never attributed.
* **Flows.** Connections aggregate into flows keyed by `process path (or name) | remote ip | remote port | protocol |
  direction`. Flows are what get scored and alerted.
* **Expensive work is asynchronous**: SHA-256 (2 concurrent, cached by path+size+mtime, files opened with full sharing),
  Authenticode (cached), PTR (4 concurrent, 5 s timeout, cached per IP), reputation (one worker per provider with its
  own priority queue, rate limiter and cache). Results come back as messages and trigger re-scoring of affected flows.
* **Hostnames** are tracked per IP from observed DNS answers (most recent first), kept separate from PTR and from
  TLS SNI / HTTP Host (PCAP only). The UI labels each source; PTR is shown as informational only.
* **Batching.** Every second the engine flushes new events, changed flows and DNS rows to SQLite in one transaction and
  raises one `EngineBatch` for the UI. The UI keeps at most 3 000 live rows; history is queried from the database.
* **Retention** runs every 10 minutes (1 h / 6 h / 24 h / 7 d / 30 d / unlimited).

## 6. Storage

SQLite (WAL mode) at `database\nethunter.db`; synthetic test mode uses `database\synthetic-test.db`, PCAP
investigations `database\pcap\<capture>-<timestamp>.db`.

| Table | Content |
|---|---|
| `connection_events` | Every observed connection (time, direction, endpoints, PID, process, path, hash, hostname, PTR, risk) |
| `flows` | Aggregated process→destination flows with score, confidence, classification and evidence (JSON) |
| `dns_events` | DNS observations with notes on suspicious behaviour |
| `alerts` | Alerts with evidence, first/last seen, acknowledgement |
| `reputation_cache` | Provider results with expiry (survives restarts, saves API quota) |
| `baseline` | Learned process → destination groups (registrable domain or /24 / /48 network) |
| `marks` | Analyst marks: Trusted / Ignored / Suspicious for IPs, domains, processes, hashes |

All SQL uses bound parameters; `LIKE` searches escape wildcards.

## 7. Security engineering

* No shell execution; Explorer is launched with `ArgumentList` (no string concatenation).
* All provider responses are size-limited (4 MB), parsed defensively (type checks, clamping, control-character
  stripping) and validated (e.g. AbuseIPDB must answer for the IP that was asked).
* HTTPS only, default certificate validation, 20 s timeouts, `Retry-After` honoured on HTTP 429.
* API keys: DPAPI-encrypted at rest, never logged, never shown after entry.
* Private, loopback, link-local, multicast and documentation addresses are never sent to reputation services.
* PCAP parsing is bounds-checked (packet ≤ 256 KB, block ≤ 16 MB, DNS compression-loop protection).
* UI shows untrusted strings only as plain text; HTML reports encode everything and carry a restrictive CSP; CSV
  export neutralises spreadsheet formula injection.
* Least privilege: runs as the invoking user; ETW sessions are stopped on exit.
