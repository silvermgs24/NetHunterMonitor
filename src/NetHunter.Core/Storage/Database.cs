using System.Text.Json;
using Microsoft.Data.Sqlite;
using NetHunter.Core.Detection;
using NetHunter.Core.Intel;
using NetHunter.Core.Models;

namespace NetHunter.Core.Storage;

public sealed class EventFilter
{
    public string? Text { get; set; }
    public string? Process { get; set; }
    public string? Ip { get; set; }
    public string? Domain { get; set; }
    public int? Port { get; set; }
    public TransportProtocol? Protocol { get; set; }
    public RiskLevel? MinLevel { get; set; }
    public Direction? Direction { get; set; }
    public DateTimeOffset? From { get; set; }
    public DateTimeOffset? To { get; set; }
    public int Limit { get; set; } = 2000;
}

public sealed class ProcessSummary
{
    public string ProcessKey { get; set; } = "";
    public string ProcessName { get; set; } = "";
    public string? ProcessPath { get; set; }
    public string? Sha256 { get; set; }
    public int? LastPid { get; set; }
    public long Connections { get; set; }
    public int Destinations { get; set; }
    public int MaxScore { get; set; }
    public RiskLevel Level { get; set; }
    public DateTimeOffset LastSeen { get; set; }
}

/// <summary>
/// Local SQLite store (WAL mode). One serialized writer connection; readers open pooled connections.
/// All values are bound as parameters: no SQL is ever built from observed data.
/// </summary>
public sealed class Database : IReputationStore, IBaselineStore, IDisposable
{
    private readonly string _connString;
    private readonly SqliteConnection _writer;
    private readonly object _writeLock = new();
    private static readonly JsonSerializerOptions Json = new();

    public Database(string path)
    {
        Path = path;
        Directory.CreateDirectory(System.IO.Path.GetDirectoryName(System.IO.Path.GetFullPath(path))!);
        _connString = new SqliteConnectionStringBuilder { DataSource = path, Mode = SqliteOpenMode.ReadWriteCreate, Pooling = true }.ToString();
        _writer = new SqliteConnection(_connString);
        _writer.Open();
        Exec("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;");
        Migrate();
    }

    public string Path { get; }

    private void Migrate()
    {
        Exec("""
        CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT);
        CREATE TABLE IF NOT EXISTS connection_events(
            id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL, direction INTEGER, proto INTEGER,
            local_ip TEXT, local_port INTEGER, remote_ip TEXT, remote_port INTEGER, state TEXT, pid INTEGER,
            process_name TEXT, process_path TEXT, sha256 TEXT, hostname TEXT, ptr TEXT, flow_key TEXT,
            score INTEGER, level INTEGER, source TEXT, synthetic INTEGER);
        CREATE INDEX IF NOT EXISTS ix_ce_ts ON connection_events(ts);
        CREATE INDEX IF NOT EXISTS ix_ce_remote ON connection_events(remote_ip);
        CREATE INDEX IF NOT EXISTS ix_ce_flow ON connection_events(flow_key);
        CREATE TABLE IF NOT EXISTS flows(
            flow_key TEXT PRIMARY KEY, process_key TEXT, process_name TEXT, process_path TEXT, last_pid INTEGER, sha256 TEXT,
            remote_ip TEXT, remote_port INTEGER, proto INTEGER, direction INTEGER, hostname TEXT, ptr TEXT, sni TEXT,
            first_seen INTEGER, last_seen INTEGER, count INTEGER, failed INTEGER, last_state TEXT,
            score INTEGER, level INTEGER, confidence INTEGER, classification INTEGER, title TEXT, evidence TEXT, synthetic INTEGER);
        CREATE INDEX IF NOT EXISTS ix_flows_last ON flows(last_seen);
        CREATE INDEX IF NOT EXISTS ix_flows_proc ON flows(process_key);
        CREATE TABLE IF NOT EXISTS dns_events(
            id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL, pid INTEGER, process_name TEXT, query TEXT, qtype TEXT,
            status INTEGER, answers TEXT, source TEXT, level INTEGER, notes TEXT, synthetic INTEGER);
        CREATE INDEX IF NOT EXISTS ix_dns_ts ON dns_events(ts);
        CREATE INDEX IF NOT EXISTS ix_dns_query ON dns_events(query);
        CREATE TABLE IF NOT EXISTS alerts(
            id INTEGER PRIMARY KEY AUTOINCREMENT, created INTEGER, updated INTEGER, severity INTEGER, classification INTEGER,
            title TEXT, subject_key TEXT, process_name TEXT, pid INTEGER, process_path TEXT, sha256 TEXT, remote_ip TEXT,
            remote_port INTEGER, hostname TEXT, score INTEGER, confidence INTEGER, evidence TEXT, first_seen INTEGER,
            last_seen INTEGER, acknowledged INTEGER, synthetic INTEGER);
        CREATE INDEX IF NOT EXISTS ix_alerts_subject ON alerts(subject_key);
        CREATE TABLE IF NOT EXISTS reputation_cache(
            provider TEXT, ioc_type INTEGER, value TEXT, json TEXT, expires INTEGER, PRIMARY KEY(provider, ioc_type, value));
        CREATE TABLE IF NOT EXISTS baseline(
            process_key TEXT, dest_key TEXT, first_seen INTEGER, last_seen INTEGER, count INTEGER, PRIMARY KEY(process_key, dest_key));
        CREATE TABLE IF NOT EXISTS marks(kind TEXT, value TEXT, mark INTEGER, note TEXT, created INTEGER, PRIMARY KEY(kind, value));
        INSERT OR IGNORE INTO meta(key, value) VALUES('schema', '1');
        """);
    }

    private void Exec(string sql)
    {
        lock (_writeLock)
        {
            using var cmd = _writer.CreateCommand();
            cmd.CommandText = sql;
            cmd.ExecuteNonQuery();
        }
    }

    private SqliteConnection OpenReader()
    {
        var c = new SqliteConnection(_connString);
        c.Open();
        using var cmd = c.CreateCommand();
        cmd.CommandText = "PRAGMA busy_timeout=5000;";
        cmd.ExecuteNonQuery();
        return c;
    }

    private static long Ms(DateTimeOffset t) => t.ToUnixTimeMilliseconds();
    private static DateTimeOffset FromMs(long ms) => DateTimeOffset.FromUnixTimeMilliseconds(ms);
    private static object Db(object? v) => v ?? DBNull.Value;
    private static string? S(SqliteDataReader r, int i) => r.IsDBNull(i) ? null : r.GetString(i);
    private static int? I(SqliteDataReader r, int i) => r.IsDBNull(i) ? null : r.GetInt32(i);

    // ───────────── batched writes ─────────────

    public void WriteBatch(IReadOnlyList<ConnectionEvent> events, IReadOnlyList<FlowRecord> flows, IReadOnlyList<DnsEventRecord> dns)
    {
        if (events.Count == 0 && flows.Count == 0 && dns.Count == 0) return;
        lock (_writeLock)
        {
            using var tx = _writer.BeginTransaction();
            if (events.Count > 0)
            {
                using var cmd = _writer.CreateCommand();
                cmd.Transaction = tx;
                cmd.CommandText = """
                    INSERT INTO connection_events(ts,direction,proto,local_ip,local_port,remote_ip,remote_port,state,pid,process_name,process_path,sha256,hostname,ptr,flow_key,score,level,source,synthetic)
                    VALUES($ts,$dir,$proto,$lip,$lport,$rip,$rport,$state,$pid,$pname,$ppath,$sha,$host,$ptr,$flow,$score,$level,$src,$syn)
                    """;
                var p = new[] { "$ts", "$dir", "$proto", "$lip", "$lport", "$rip", "$rport", "$state", "$pid", "$pname", "$ppath", "$sha", "$host", "$ptr", "$flow", "$score", "$level", "$src", "$syn" }
                    .Select(n => cmd.Parameters.Add(new SqliteParameter { ParameterName = n })).ToArray();
                foreach (var e in events)
                {
                    object?[] v = { Ms(e.Timestamp), (int)e.Direction, (int)e.Protocol, e.LocalIp, e.LocalPort, e.RemoteIp, e.RemotePort, e.State, e.Pid,
                        e.ProcessName, e.ProcessPath, e.Sha256, e.Hostname, e.Ptr, e.FlowKey, e.Score, (int)e.Level, e.Source, e.IsSynthetic ? 1 : 0 };
                    for (int i = 0; i < p.Length; i++) p[i].Value = Db(v[i]);
                    cmd.ExecuteNonQuery();
                    e.Id = 0;
                }
            }
            if (flows.Count > 0)
            {
                using var cmd = _writer.CreateCommand();
                cmd.Transaction = tx;
                cmd.CommandText = """
                    INSERT INTO flows(flow_key,process_key,process_name,process_path,last_pid,sha256,remote_ip,remote_port,proto,direction,hostname,ptr,sni,first_seen,last_seen,count,failed,last_state,score,level,confidence,classification,title,evidence,synthetic)
                    VALUES($k,$pk,$pn,$pp,$pid,$sha,$rip,$rport,$proto,$dir,$host,$ptr,$sni,$fs,$ls,$cnt,$fail,$state,$score,$level,$conf,$cls,$title,$ev,$syn)
                    ON CONFLICT(flow_key) DO UPDATE SET process_name=excluded.process_name, process_path=excluded.process_path, last_pid=excluded.last_pid,
                      sha256=COALESCE(excluded.sha256, flows.sha256), hostname=COALESCE(excluded.hostname, flows.hostname), ptr=COALESCE(excluded.ptr, flows.ptr),
                      sni=COALESCE(excluded.sni, flows.sni), last_seen=excluded.last_seen, count=excluded.count, failed=excluded.failed, last_state=excluded.last_state,
                      score=excluded.score, level=excluded.level, confidence=excluded.confidence, classification=excluded.classification, title=excluded.title, evidence=excluded.evidence
                    """;
                var p = new[] { "$k", "$pk", "$pn", "$pp", "$pid", "$sha", "$rip", "$rport", "$proto", "$dir", "$host", "$ptr", "$sni", "$fs", "$ls", "$cnt", "$fail", "$state", "$score", "$level", "$conf", "$cls", "$title", "$ev", "$syn" }
                    .Select(n => cmd.Parameters.Add(new SqliteParameter { ParameterName = n })).ToArray();
                foreach (var f in flows)
                {
                    var a = f.Assessment;
                    object?[] v = { f.Key, f.ProcessKey, f.ProcessName, f.ProcessPath, f.LastPid, f.Sha256, f.RemoteIp, f.RemotePort, (int)f.Protocol, (int)f.Direction,
                        f.Hostname, f.Ptr, f.Sni, Ms(f.FirstSeen), Ms(f.LastSeen), f.Count, f.FailedCount, f.LastState, a.Score, (int)a.Level, a.Confidence,
                        (int)a.Classification, a.Title, JsonSerializer.Serialize(a.Evidence, Json), f.IsSynthetic ? 1 : 0 };
                    for (int i = 0; i < p.Length; i++) p[i].Value = Db(v[i]);
                    cmd.ExecuteNonQuery();
                }
            }
            if (dns.Count > 0)
            {
                using var cmd = _writer.CreateCommand();
                cmd.Transaction = tx;
                cmd.CommandText = "INSERT INTO dns_events(ts,pid,process_name,query,qtype,status,answers,source,level,notes,synthetic) VALUES($ts,$pid,$pn,$q,$t,$st,$a,$src,$lvl,$notes,$syn)";
                var p = new[] { "$ts", "$pid", "$pn", "$q", "$t", "$st", "$a", "$src", "$lvl", "$notes", "$syn" }
                    .Select(n => cmd.Parameters.Add(new SqliteParameter { ParameterName = n })).ToArray();
                foreach (var d in dns)
                {
                    object?[] v = { Ms(d.Timestamp), d.Pid, d.ProcessName, d.Query, d.RecordType, d.Status, d.Answers, d.Source, (int)d.Level, d.Notes, d.IsSynthetic ? 1 : 0 };
                    for (int i = 0; i < p.Length; i++) p[i].Value = Db(v[i]);
                    cmd.ExecuteNonQuery();
                }
            }
            tx.Commit();
        }
    }

    // ───────────── alerts ─────────────

    public long UpsertAlert(AlertRecord a)
    {
        lock (_writeLock)
        {
            using var cmd = _writer.CreateCommand();
            if (a.Id == 0)
            {
                cmd.CommandText = """
                    INSERT INTO alerts(created,updated,severity,classification,title,subject_key,process_name,pid,process_path,sha256,remote_ip,remote_port,hostname,score,confidence,evidence,first_seen,last_seen,acknowledged,synthetic)
                    VALUES($c,$u,$sev,$cls,$t,$k,$pn,$pid,$pp,$sha,$rip,$rport,$h,$s,$conf,$ev,$fs,$ls,$ack,$syn); SELECT last_insert_rowid();
                    """;
            }
            else
            {
                cmd.CommandText = """
                    UPDATE alerts SET updated=$u, severity=$sev, classification=$cls, title=$t, process_name=$pn, pid=$pid, process_path=$pp, sha256=$sha,
                      hostname=$h, score=$s, confidence=$conf, evidence=$ev, last_seen=$ls, acknowledged=$ack WHERE id=$id; SELECT $id;
                    """;
                cmd.Parameters.AddWithValue("$id", a.Id);
            }
            cmd.Parameters.AddWithValue("$c", Ms(a.Created));
            cmd.Parameters.AddWithValue("$u", Ms(a.Updated));
            cmd.Parameters.AddWithValue("$sev", (int)a.Severity);
            cmd.Parameters.AddWithValue("$cls", (int)a.Classification);
            cmd.Parameters.AddWithValue("$t", a.Title);
            cmd.Parameters.AddWithValue("$k", a.SubjectKey);
            cmd.Parameters.AddWithValue("$pn", a.ProcessName);
            cmd.Parameters.AddWithValue("$pid", Db(a.Pid));
            cmd.Parameters.AddWithValue("$pp", Db(a.ProcessPath));
            cmd.Parameters.AddWithValue("$sha", Db(a.Sha256));
            cmd.Parameters.AddWithValue("$rip", Db(a.RemoteIp));
            cmd.Parameters.AddWithValue("$rport", Db(a.RemotePort));
            cmd.Parameters.AddWithValue("$h", Db(a.Hostname));
            cmd.Parameters.AddWithValue("$s", a.Score);
            cmd.Parameters.AddWithValue("$conf", a.Confidence);
            cmd.Parameters.AddWithValue("$ev", JsonSerializer.Serialize(a.Evidence, Json));
            cmd.Parameters.AddWithValue("$fs", Db(a.FirstSeen is { } fs ? Ms(fs) : null));
            cmd.Parameters.AddWithValue("$ls", Db(a.LastSeen is { } ls ? Ms(ls) : null));
            cmd.Parameters.AddWithValue("$ack", a.Acknowledged ? 1 : 0);
            cmd.Parameters.AddWithValue("$syn", a.IsSynthetic ? 1 : 0);
            a.Id = Convert.ToInt64(cmd.ExecuteScalar());
            return a.Id;
        }
    }

    public List<AlertRecord> GetAlerts(int limit = 1000, bool includeAcknowledged = true)
    {
        using var c = OpenReader();
        using var cmd = c.CreateCommand();
        cmd.CommandText = $"SELECT id,created,updated,severity,classification,title,subject_key,process_name,pid,process_path,sha256,remote_ip,remote_port,hostname,score,confidence,evidence,first_seen,last_seen,acknowledged,synthetic FROM alerts {(includeAcknowledged ? "" : "WHERE acknowledged=0")} ORDER BY updated DESC LIMIT $l";
        cmd.Parameters.AddWithValue("$l", limit);
        using var r = cmd.ExecuteReader();
        var list = new List<AlertRecord>();
        while (r.Read())
        {
            list.Add(new AlertRecord
            {
                Id = r.GetInt64(0), Created = FromMs(r.GetInt64(1)), Updated = FromMs(r.GetInt64(2)), Severity = (RiskLevel)r.GetInt32(3),
                Classification = (DetectionClass)r.GetInt32(4), Title = r.GetString(5), SubjectKey = r.GetString(6), ProcessName = S(r, 7) ?? "Unknown",
                Pid = I(r, 8), ProcessPath = S(r, 9), Sha256 = S(r, 10), RemoteIp = S(r, 11), RemotePort = I(r, 12), Hostname = S(r, 13),
                Score = r.GetInt32(14), Confidence = r.GetInt32(15), Evidence = DeserializeEvidence(S(r, 16)),
                FirstSeen = r.IsDBNull(17) ? null : FromMs(r.GetInt64(17)), LastSeen = r.IsDBNull(18) ? null : FromMs(r.GetInt64(18)),
                Acknowledged = r.GetInt32(19) != 0, IsSynthetic = r.GetInt32(20) != 0,
            });
        }
        return list;
    }

    private static IReadOnlyList<Evidence> DeserializeEvidence(string? json)
    {
        if (string.IsNullOrEmpty(json)) return Array.Empty<Evidence>();
        try { return JsonSerializer.Deserialize<List<Evidence>>(json, Json) ?? new List<Evidence>(); }
        catch (JsonException) { return Array.Empty<Evidence>(); }
    }

    public void AcknowledgeAlert(long id, bool ack)
    {
        lock (_writeLock)
        {
            using var cmd = _writer.CreateCommand();
            cmd.CommandText = "UPDATE alerts SET acknowledged=$a WHERE id=$id";
            cmd.Parameters.AddWithValue("$a", ack ? 1 : 0);
            cmd.Parameters.AddWithValue("$id", id);
            cmd.ExecuteNonQuery();
        }
    }

    // ───────────── queries ─────────────

    public List<ConnectionEvent> QueryEvents(EventFilter f)
    {
        using var c = OpenReader();
        using var cmd = c.CreateCommand();
        var where = new List<string>();
        if (!string.IsNullOrWhiteSpace(f.Text))
        {
            where.Add("(process_name LIKE $t ESCAPE '\\' OR process_path LIKE $t ESCAPE '\\' OR remote_ip LIKE $t ESCAPE '\\' OR hostname LIKE $t ESCAPE '\\' OR ptr LIKE $t ESCAPE '\\' OR sha256 LIKE $t ESCAPE '\\' OR CAST(remote_port AS TEXT) = $exact OR CAST(local_port AS TEXT) = $exact)");
            cmd.Parameters.AddWithValue("$t", "%" + EscapeLike(f.Text.Trim()) + "%");
            cmd.Parameters.AddWithValue("$exact", f.Text.Trim());
        }
        if (!string.IsNullOrWhiteSpace(f.Process)) { where.Add("process_name LIKE $p ESCAPE '\\'"); cmd.Parameters.AddWithValue("$p", "%" + EscapeLike(f.Process.Trim()) + "%"); }
        if (!string.IsNullOrWhiteSpace(f.Ip)) { where.Add("remote_ip LIKE $ip ESCAPE '\\'"); cmd.Parameters.AddWithValue("$ip", EscapeLike(f.Ip.Trim()) + "%"); }
        if (!string.IsNullOrWhiteSpace(f.Domain)) { where.Add("(hostname LIKE $d ESCAPE '\\' OR ptr LIKE $d ESCAPE '\\')"); cmd.Parameters.AddWithValue("$d", "%" + EscapeLike(f.Domain.Trim()) + "%"); }
        if (f.Port is { } port) { where.Add("(remote_port=$port OR local_port=$port)"); cmd.Parameters.AddWithValue("$port", port); }
        if (f.Protocol is { } proto) { where.Add("proto=$proto"); cmd.Parameters.AddWithValue("$proto", (int)proto); }
        if (f.MinLevel is { } lvl) { where.Add("level>=$lvl"); cmd.Parameters.AddWithValue("$lvl", (int)lvl); }
        if (f.Direction is { } dir) { where.Add("direction=$dir"); cmd.Parameters.AddWithValue("$dir", (int)dir); }
        if (f.From is { } from) { where.Add("ts>=$from"); cmd.Parameters.AddWithValue("$from", Ms(from)); }
        if (f.To is { } to) { where.Add("ts<=$to"); cmd.Parameters.AddWithValue("$to", Ms(to)); }
        cmd.CommandText = "SELECT id,ts,direction,proto,local_ip,local_port,remote_ip,remote_port,state,pid,process_name,process_path,sha256,hostname,ptr,flow_key,score,level,source,synthetic FROM connection_events"
            + (where.Count > 0 ? " WHERE " + string.Join(" AND ", where) : "") + " ORDER BY ts DESC LIMIT $limit";
        cmd.Parameters.AddWithValue("$limit", Math.Clamp(f.Limit, 1, 100_000));
        using var r = cmd.ExecuteReader();
        var list = new List<ConnectionEvent>();
        while (r.Read())
        {
            list.Add(new ConnectionEvent
            {
                Id = r.GetInt64(0), Timestamp = FromMs(r.GetInt64(1)), Direction = (Direction)r.GetInt32(2), Protocol = (TransportProtocol)r.GetInt32(3),
                LocalIp = S(r, 4) ?? "", LocalPort = r.GetInt32(5), RemoteIp = S(r, 6) ?? "", RemotePort = r.GetInt32(7), State = S(r, 8) ?? "",
                Pid = I(r, 9), ProcessName = S(r, 10) ?? "Unknown", ProcessPath = S(r, 11), Sha256 = S(r, 12), Hostname = S(r, 13), Ptr = S(r, 14),
                FlowKey = S(r, 15) ?? "", Score = r.GetInt32(16), Level = (RiskLevel)r.GetInt32(17), Source = S(r, 18) ?? "", IsSynthetic = r.GetInt32(19) != 0,
            });
        }
        return list;
    }

    public List<DnsEventRecord> QueryDns(string? text, int limit = 2000)
    {
        using var c = OpenReader();
        using var cmd = c.CreateCommand();
        cmd.CommandText = "SELECT id,ts,pid,process_name,query,qtype,status,answers,source,level,notes,synthetic FROM dns_events"
            + (string.IsNullOrWhiteSpace(text) ? "" : " WHERE query LIKE $t ESCAPE '\\' OR answers LIKE $t ESCAPE '\\' OR process_name LIKE $t ESCAPE '\\'")
            + " ORDER BY ts DESC LIMIT $l";
        if (!string.IsNullOrWhiteSpace(text)) cmd.Parameters.AddWithValue("$t", "%" + EscapeLike(text.Trim()) + "%");
        cmd.Parameters.AddWithValue("$l", limit);
        using var r = cmd.ExecuteReader();
        var list = new List<DnsEventRecord>();
        while (r.Read())
            list.Add(new DnsEventRecord
            {
                Id = r.GetInt64(0), Timestamp = FromMs(r.GetInt64(1)), Pid = I(r, 2), ProcessName = S(r, 3), Query = S(r, 4) ?? "", RecordType = S(r, 5) ?? "",
                Status = r.GetInt32(6), Answers = S(r, 7) ?? "", Source = S(r, 8) ?? "", Level = (RiskLevel)r.GetInt32(9), Notes = S(r, 10) ?? "", IsSynthetic = r.GetInt32(11) != 0,
            });
        return list;
    }

    public List<FlowRecord> QueryFlows(string? text = null, int limit = 5000, DateTimeOffset? since = null)
    {
        using var c = OpenReader();
        using var cmd = c.CreateCommand();
        var where = new List<string>();
        if (!string.IsNullOrWhiteSpace(text))
        {
            where.Add("(process_name LIKE $t ESCAPE '\\' OR process_path LIKE $t ESCAPE '\\' OR remote_ip LIKE $t ESCAPE '\\' OR hostname LIKE $t ESCAPE '\\' OR sha256 LIKE $t ESCAPE '\\' OR CAST(remote_port AS TEXT)=$exact)");
            cmd.Parameters.AddWithValue("$t", "%" + EscapeLike(text.Trim()) + "%");
            cmd.Parameters.AddWithValue("$exact", text.Trim());
        }
        if (since is { } s) { where.Add("last_seen>=$since"); cmd.Parameters.AddWithValue("$since", Ms(s)); }
        cmd.CommandText = "SELECT flow_key,process_key,process_name,process_path,last_pid,sha256,remote_ip,remote_port,proto,direction,hostname,ptr,sni,first_seen,last_seen,count,failed,last_state,score,level,confidence,classification,title,evidence,synthetic FROM flows"
            + (where.Count > 0 ? " WHERE " + string.Join(" AND ", where) : "") + " ORDER BY last_seen DESC LIMIT $l";
        cmd.Parameters.AddWithValue("$l", limit);
        using var r = cmd.ExecuteReader();
        var list = new List<FlowRecord>();
        while (r.Read())
        {
            list.Add(new FlowRecord
            {
                Key = r.GetString(0), ProcessKey = S(r, 1) ?? "", ProcessName = S(r, 2) ?? "Unknown", ProcessPath = S(r, 3), LastPid = I(r, 4), Sha256 = S(r, 5),
                RemoteIp = S(r, 6) ?? "", RemotePort = r.GetInt32(7), Protocol = (TransportProtocol)r.GetInt32(8), Direction = (Direction)r.GetInt32(9),
                Hostname = S(r, 10), Ptr = S(r, 11), Sni = S(r, 12), FirstSeen = FromMs(r.GetInt64(13)), LastSeen = FromMs(r.GetInt64(14)), Count = r.GetInt64(15),
                FailedCount = r.GetInt32(16), LastState = S(r, 17) ?? "",
                Assessment = new RiskAssessment
                {
                    Score = r.GetInt32(18), Level = (RiskLevel)r.GetInt32(19), Confidence = r.GetInt32(20), Classification = (DetectionClass)r.GetInt32(21),
                    Title = S(r, 22) ?? "", Evidence = DeserializeEvidence(S(r, 23)),
                },
                IsSynthetic = r.GetInt32(24) != 0,
            });
        }
        return list;
    }

    public List<ProcessSummary> QueryProcesses(DateTimeOffset? since = null)
    {
        using var c = OpenReader();
        using var cmd = c.CreateCommand();
        cmd.CommandText = """
            SELECT process_key, MAX(process_name), MAX(process_path), MAX(sha256), MAX(last_pid), SUM(count), COUNT(DISTINCT remote_ip), MAX(score), MAX(level), MAX(last_seen)
            FROM flows WHERE last_seen >= $since GROUP BY process_key ORDER BY MAX(score) DESC, SUM(count) DESC
            """;
        cmd.Parameters.AddWithValue("$since", since is { } s ? Ms(s) : 0);
        using var r = cmd.ExecuteReader();
        var list = new List<ProcessSummary>();
        while (r.Read())
            list.Add(new ProcessSummary
            {
                ProcessKey = r.GetString(0), ProcessName = S(r, 1) ?? "Unknown", ProcessPath = S(r, 2), Sha256 = S(r, 3), LastPid = I(r, 4),
                Connections = r.GetInt64(5), Destinations = r.GetInt32(6), MaxScore = r.GetInt32(7), Level = (RiskLevel)r.GetInt32(8), LastSeen = FromMs(r.GetInt64(9)),
            });
        return list;
    }

    /// <summary>Destination IPs, hostnames and executable hashes observed in flows, aggregated for the IOC view.</summary>
    public List<IocSummary> QueryIocs()
    {
        using var c = OpenReader();
        var list = new List<IocSummary>();
        void Run(string sql, IocType type)
        {
            using var cmd = c.CreateCommand();
            cmd.CommandText = sql;
            using var r = cmd.ExecuteReader();
            while (r.Read())
                list.Add(new IocSummary
                {
                    Type = type, Value = r.GetString(0), FirstSeen = FromMs(r.GetInt64(1)), LastSeen = FromMs(r.GetInt64(2)),
                    Processes = S(r, 3) ?? "", Score = r.GetInt32(4), Level = (RiskLevel)r.GetInt32(5), Connections = r.GetInt64(6),
                });
        }
        Run("SELECT remote_ip, MIN(first_seen), MAX(last_seen), GROUP_CONCAT(DISTINCT process_name), MAX(score), MAX(level), SUM(count) FROM flows WHERE remote_ip<>'' GROUP BY remote_ip", IocType.Ip);
        Run("SELECT hostname, MIN(first_seen), MAX(last_seen), GROUP_CONCAT(DISTINCT process_name), MAX(score), MAX(level), SUM(count) FROM flows WHERE hostname IS NOT NULL AND hostname<>'' GROUP BY hostname", IocType.Domain);
        Run("SELECT sha256, MIN(first_seen), MAX(last_seen), GROUP_CONCAT(DISTINCT process_name), MAX(score), MAX(level), SUM(count) FROM flows WHERE sha256 IS NOT NULL GROUP BY sha256", IocType.Sha256);
        return list;
    }

    private static string EscapeLike(string s) => s.Replace("\\", "\\\\").Replace("%", "\\%").Replace("_", "\\_");

    // ───────────── marks ─────────────

    public void SetMark(string kind, string value, UserMarkKind mark, string? note)
    {
        lock (_writeLock)
        {
            using var cmd = _writer.CreateCommand();
            if (mark == UserMarkKind.None)
            {
                cmd.CommandText = "DELETE FROM marks WHERE kind=$k AND value=$v";
            }
            else
            {
                cmd.CommandText = "INSERT INTO marks(kind,value,mark,note,created) VALUES($k,$v,$m,$n,$c) ON CONFLICT(kind,value) DO UPDATE SET mark=excluded.mark, note=excluded.note";
                cmd.Parameters.AddWithValue("$m", (int)mark);
                cmd.Parameters.AddWithValue("$n", Db(note));
                cmd.Parameters.AddWithValue("$c", Ms(DateTimeOffset.UtcNow));
            }
            cmd.Parameters.AddWithValue("$k", kind);
            cmd.Parameters.AddWithValue("$v", value.ToLowerInvariant());
            cmd.ExecuteNonQuery();
        }
    }

    public List<UserMark> GetMarks()
    {
        using var c = OpenReader();
        using var cmd = c.CreateCommand();
        cmd.CommandText = "SELECT kind,value,mark,note,created FROM marks ORDER BY created DESC";
        using var r = cmd.ExecuteReader();
        var list = new List<UserMark>();
        while (r.Read()) list.Add(new UserMark(r.GetString(0), r.GetString(1), (UserMarkKind)r.GetInt32(2), S(r, 3), FromMs(r.GetInt64(4))));
        return list;
    }

    // ───────────── retention ─────────────

    public int ApplyRetention(TimeSpan? keep, DateTimeOffset now)
    {
        int removed = 0;
        lock (_writeLock)
        {
            using var cmd = _writer.CreateCommand();
            cmd.Parameters.AddWithValue("$now", Ms(now));
            if (keep is { } k)
            {
                cmd.Parameters.AddWithValue("$cut", Ms(now - k));
                cmd.CommandText = "DELETE FROM connection_events WHERE ts<$cut; DELETE FROM dns_events WHERE ts<$cut; DELETE FROM flows WHERE last_seen<$cut; DELETE FROM alerts WHERE updated<$cut;";
                removed += cmd.ExecuteNonQuery();
            }
            cmd.CommandText = "DELETE FROM reputation_cache WHERE expires<$now;";
            removed += cmd.ExecuteNonQuery();
        }
        return removed;
    }

    public (long Events, long Flows, long Dns, long Alerts) Counts()
    {
        using var c = OpenReader();
        using var cmd = c.CreateCommand();
        cmd.CommandText = "SELECT (SELECT COUNT(*) FROM connection_events),(SELECT COUNT(*) FROM flows),(SELECT COUNT(*) FROM dns_events),(SELECT COUNT(*) FROM alerts)";
        using var r = cmd.ExecuteReader();
        r.Read();
        return (r.GetInt64(0), r.GetInt64(1), r.GetInt64(2), r.GetInt64(3));
    }

    // ───────────── IReputationStore ─────────────

    public IEnumerable<(ReputationResult Result, DateTimeOffset Expires)> LoadReputation(DateTimeOffset now)
    {
        using var c = OpenReader();
        using var cmd = c.CreateCommand();
        cmd.CommandText = "SELECT json, expires FROM reputation_cache WHERE expires>$now";
        cmd.Parameters.AddWithValue("$now", Ms(now));
        using var r = cmd.ExecuteReader();
        var list = new List<(ReputationResult, DateTimeOffset)>();
        while (r.Read())
        {
            try
            {
                var res = JsonSerializer.Deserialize<ReputationResult>(r.GetString(0), Json);
                if (res is not null) list.Add((res, FromMs(r.GetInt64(1))));
            }
            catch (JsonException) { /* skip corrupt rows */ }
        }
        return list;
    }

    public void SaveReputation(ReputationResult result, DateTimeOffset expires)
    {
        lock (_writeLock)
        {
            using var cmd = _writer.CreateCommand();
            cmd.CommandText = "INSERT INTO reputation_cache(provider,ioc_type,value,json,expires) VALUES($p,$t,$v,$j,$e) ON CONFLICT(provider,ioc_type,value) DO UPDATE SET json=excluded.json, expires=excluded.expires";
            cmd.Parameters.AddWithValue("$p", result.Provider);
            cmd.Parameters.AddWithValue("$t", (int)result.Type);
            cmd.Parameters.AddWithValue("$v", result.Value);
            cmd.Parameters.AddWithValue("$j", JsonSerializer.Serialize(result, Json));
            cmd.Parameters.AddWithValue("$e", Ms(expires));
            cmd.ExecuteNonQuery();
        }
    }

    // ───────────── IBaselineStore ─────────────

    public IEnumerable<(string ProcessKey, string DestKey, DateTimeOffset FirstSeen, long Count)> LoadBaseline()
    {
        using var c = OpenReader();
        using var cmd = c.CreateCommand();
        cmd.CommandText = "SELECT process_key, dest_key, first_seen, count FROM baseline";
        using var r = cmd.ExecuteReader();
        var list = new List<(string, string, DateTimeOffset, long)>();
        while (r.Read()) list.Add((r.GetString(0), r.GetString(1), FromMs(r.GetInt64(2)), r.GetInt64(3)));
        return list;
    }

    public void UpsertBaseline(string processKey, string destKey, DateTimeOffset seen)
    {
        lock (_writeLock)
        {
            using var cmd = _writer.CreateCommand();
            cmd.CommandText = "INSERT INTO baseline(process_key,dest_key,first_seen,last_seen,count) VALUES($p,$d,$t,$t,1) ON CONFLICT(process_key,dest_key) DO UPDATE SET last_seen=$t, count=count+1";
            cmd.Parameters.AddWithValue("$p", processKey);
            cmd.Parameters.AddWithValue("$d", destKey);
            cmd.Parameters.AddWithValue("$t", Ms(seen));
            cmd.ExecuteNonQuery();
        }
    }

    public DateTimeOffset? GetBaselineStart()
    {
        using var c = OpenReader();
        using var cmd = c.CreateCommand();
        cmd.CommandText = "SELECT value FROM meta WHERE key='baseline_start'";
        var v = cmd.ExecuteScalar() as string;
        return long.TryParse(v, out var ms) ? FromMs(ms) : null;
    }

    public void SetBaselineStart(DateTimeOffset start)
    {
        lock (_writeLock)
        {
            using var cmd = _writer.CreateCommand();
            cmd.CommandText = "INSERT INTO meta(key,value) VALUES('baseline_start',$v) ON CONFLICT(key) DO UPDATE SET value=excluded.value";
            cmd.Parameters.AddWithValue("$v", Ms(start).ToString());
            cmd.ExecuteNonQuery();
        }
    }

    public void ResetBaseline()
    {
        Exec("DELETE FROM baseline;");
        SetBaselineStart(DateTimeOffset.UtcNow);
    }

    public void Dispose()
    {
        lock (_writeLock)
        {
            _writer.Dispose();
        }
        SqliteConnection.ClearAllPools();
    }
}
