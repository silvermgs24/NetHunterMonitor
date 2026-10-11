namespace NetHunter.Core.Models;

/// <summary>One explainable reason contributing to a risk score.</summary>
/// <param name="Strength">0..1: how strongly this signal alone indicates malicious activity. Negative values reduce risk.</param>
public sealed record Evidence(EvidenceCategory Category, string Text, double Strength)
{
    public int Points => (int)Math.Round(Strength * 100);
    public bool IsMitigating => Strength < 0;
}

public sealed record RiskAssessment
{
    public static readonly RiskAssessment Pending = new() { Score = 0, Level = RiskLevel.Unknown, Confidence = 0 };

    public int Score { get; init; }
    public RiskLevel Level { get; init; }
    /// <summary>0..100: how much corroborating, independent evidence supports the score.</summary>
    public int Confidence { get; init; }
    public DetectionClass Classification { get; init; }
    public string Title { get; init; } = "";
    public IReadOnlyList<Evidence> Evidence { get; init; } = Array.Empty<Evidence>();
    /// <summary>True when the analyst marked the subject Trusted/Ignored: still scored, but no alert.</summary>
    public bool Suppressed { get; init; }
    public UserMarkKind Mark { get; init; }
}
