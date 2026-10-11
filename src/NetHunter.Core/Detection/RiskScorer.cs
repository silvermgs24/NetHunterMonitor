using NetHunter.Core.Models;

namespace NetHunter.Core.Detection;

/// <summary>All signals gathered for one subject (usually a process→destination flow).</summary>
public sealed class AssessmentInput
{
    public List<Evidence> Evidence { get; } = new();
    public BeaconResult? Beacon { get; set; }
    public bool ProcessAttributed { get; set; }
    public bool IntelConsulted { get; set; }
    public UserMarkKind Mark { get; set; }
    public string? MarkSubject { get; set; }
    public bool ExternalDestination { get; set; }

    public void Add(Evidence? e) { if (e is not null) Evidence.Add(e); }
    public void AddRange(IEnumerable<Evidence> e) => Evidence.AddRange(e);
}

/// <summary>
/// Combines independent signals with a noisy-OR: score = 1 − Π(1 − strength). One weak signal stays weak;
/// several independent signals reinforce each other with diminishing returns. Mitigating evidence
/// (negative strength) scales the result down. The output always carries the evidence that produced it.
/// </summary>
public static class RiskScorer
{
    public static RiskAssessment Assess(AssessmentInput input)
    {
        var evidence = new List<Evidence>(input.Evidence);

        if (input.Beacon is { IsBeacon: true } b)
            evidence.Add(new Evidence(EvidenceCategory.Beacon, "Possible C2 beacon: " + b.Describe(), 0.25 + 0.35 * b.Confidence));

        switch (input.Mark)
        {
            case UserMarkKind.Suspicious:
                evidence.Add(new Evidence(EvidenceCategory.UserMark, $"Analyst marked {input.MarkSubject ?? "this item"} as suspicious", 0.4));
                break;
            case UserMarkKind.Trusted:
                evidence.Add(new Evidence(EvidenceCategory.UserMark, $"Analyst marked {input.MarkSubject ?? "this item"} as trusted", -0.6));
                break;
        }

        // Keep the strongest piece of evidence per distinct text to avoid double counting the same fact.
        evidence = evidence.GroupBy(e => e.Text).Select(g => g.OrderByDescending(e => Math.Abs(e.Strength)).First()).ToList();

        double keep = 1.0, mitigate = 1.0;
        foreach (var e in evidence)
        {
            if (e.Strength > 0) keep *= 1 - Math.Clamp(e.Strength, 0, 0.99);
            else if (e.Strength < 0) mitigate *= 1 + Math.Clamp(e.Strength, -0.95, 0);
        }
        bool localIoc = evidence.Any(e => e.Category == EvidenceCategory.LocalIoc && e.Strength > 0);
        bool knownBadHash = evidence.Any(e => e.Category == EvidenceCategory.Reputation && e.Strength >= 0.85);
        // An analyst-supplied IOC match is not diluted by "trusted" marks: the analyst must remove the IOC instead.
        if (localIoc) mitigate = 1.0;

        int score = (int)Math.Round(100 * (1 - keep) * mitigate);
        score = Math.Clamp(score, 0, 100);

        var positive = evidence.Where(e => e.Strength >= 0.1).ToList();
        int categories = positive.Select(e => e.Category).Distinct().Count();
        bool hasReputation = positive.Any(e => e.Category == EvidenceCategory.Reputation);
        bool beacon = input.Beacon is { IsBeacon: true };

        DetectionClass cls;
        if (localIoc || knownBadHash) cls = DetectionClass.KnownMalicious;
        else if (beacon && score >= 50) cls = DetectionClass.PossibleC2;
        else if (hasReputation && score >= 60 && categories >= 2) cls = DetectionClass.PossibleC2;
        else if (hasReputation && score >= 35) cls = DetectionClass.IocMatch;
        else if (score >= 35) cls = DetectionClass.SuspiciousBehavior;
        else cls = DetectionClass.None;

        var level = RiskLevelExtensions.FromScore(score);
        if (cls == DetectionClass.KnownMalicious) { level = RiskLevel.Critical; score = Math.Max(score, 90); }

        // Confidence: independent corroboration + data quality. A single signal never gets high confidence.
        double maxStrength = positive.Count == 0 ? 0 : positive.Max(e => e.Strength);
        int confidence = (int)Math.Round(10 + 17 * Math.Min(categories, 4) + (input.ProcessAttributed ? 8 : 0) + (input.IntelConsulted ? 8 : 0) + 10 * maxStrength);
        if (localIoc) confidence = Math.Max(confidence, 90);
        if (score < 35 && categories == 0) confidence = input.ProcessAttributed ? 60 : 40; // confidence that it looks normal
        confidence = Math.Clamp(confidence, 0, 99);

        string title = cls switch
        {
            DetectionClass.KnownMalicious => localIoc ? "Known malicious indicator (local IOC list)" : "Known malicious file (multi-engine detection)",
            DetectionClass.PossibleC2 when beacon => "Possible C2 beacon",
            DetectionClass.PossibleC2 => "Possible C2 communication",
            DetectionClass.IocMatch => "Destination has bad reputation",
            DetectionClass.SuspiciousBehavior => "Suspicious network behavior",
            _ => evidence.Count == 0 ? "No suspicious signals" : "Low-risk observations",
        };

        return new RiskAssessment
        {
            Score = score,
            Level = level,
            Confidence = confidence,
            Classification = cls,
            Title = title,
            Evidence = evidence.OrderByDescending(e => e.Strength).ToList(),
            Mark = input.Mark,
            Suppressed = input.Mark is UserMarkKind.Trusted or UserMarkKind.Ignored && !localIoc,
        };
    }

    /// <summary>Turns provider results into graded evidence. Reputation is one signal, never a verdict on its own.</summary>
    public static IEnumerable<Evidence> FromReputation(IEnumerable<ReputationResult> results, string subjectLabel)
    {
        foreach (var r in results)
        {
            if (r.Status != ReputationStatus.Ok)
            {
                if (r.Status == ReputationStatus.NotFound && r.Type == IocType.Sha256 && r.Provider == "VirusTotal")
                    yield return new Evidence(EvidenceCategory.Reputation, $"File hash is unknown to VirusTotal (not proof of anything; rare or new file)", 0.05);
                continue;
            }

            if (r.ListName is not null)
            {
                yield return new Evidence(EvidenceCategory.LocalIoc, $"{subjectLabel} matches local IOC list '{r.ListName}' ({r.Detail})", 0.95);
                continue;
            }

            if (r.AbuseConfidence is { } conf)
            {
                if (r.IsWhitelisted == true)
                    yield return new Evidence(EvidenceCategory.Reputation, $"AbuseIPDB lists {subjectLabel} as whitelisted", -0.2);
                else if (conf >= 75)
                    yield return new Evidence(EvidenceCategory.Reputation, $"AbuseIPDB abuse confidence {conf}% ({r.TotalReports ?? 0} reports)", 0.5);
                else if (conf >= 25)
                    yield return new Evidence(EvidenceCategory.Reputation, $"AbuseIPDB abuse confidence {conf}% ({r.TotalReports ?? 0} reports)", 0.25);
                else if ((r.TotalReports ?? 0) > 0)
                    yield return new Evidence(EvidenceCategory.Reputation, $"AbuseIPDB: {r.TotalReports} historical reports, low confidence ({conf}%)", 0.06);
                continue;
            }

            if (r.Malicious is { } mal)
            {
                int total = r.TotalEngines ?? 0;
                int sus = r.Suspicious ?? 0;
                if (r.Type == IocType.Sha256)
                {
                    if (mal >= 10) yield return new Evidence(EvidenceCategory.Reputation, $"VirusTotal: file detected by {mal}/{total} engines", 0.9);
                    else if (mal >= 3) yield return new Evidence(EvidenceCategory.Reputation, $"VirusTotal: file detected by {mal}/{total} engines", 0.6);
                    else if (mal >= 1) yield return new Evidence(EvidenceCategory.Reputation, $"VirusTotal: file detected by {mal}/{total} engines (low; possible false positive)", 0.2);
                }
                else
                {
                    string what = r.Type == IocType.Ip ? "IP" : "domain";
                    if (mal >= 5) yield return new Evidence(EvidenceCategory.Reputation, $"VirusTotal: {what} flagged malicious by {mal}/{total} engines", 0.6);
                    else if (mal >= 2) yield return new Evidence(EvidenceCategory.Reputation, $"VirusTotal: {what} flagged malicious by {mal}/{total} engines", 0.35);
                    else if (mal == 1 || sus >= 2) yield return new Evidence(EvidenceCategory.Reputation, $"VirusTotal: {what} flagged by {mal} malicious / {sus} suspicious engines (weak)", 0.12);
                }
            }
        }
    }
}
