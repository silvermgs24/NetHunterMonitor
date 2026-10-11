using System.Globalization;
using System.Text.Json;

namespace NetHunter.Core.Intel;

/// <summary>Defensive accessors: API responses are untrusted input, so every field is type-checked and bounded.</summary>
internal static class JsonHelpers
{
    public static JsonElement? Prop(this JsonElement e, string name) =>
        e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v) ? v : null;

    public static JsonElement? Prop(this JsonElement? e, string name) => e is { } x ? x.Prop(name) : null;

    public static int? Int(this JsonElement? e, int min = 0, int max = int.MaxValue)
    {
        if (e is not { } x) return null;
        long v;
        if (x.ValueKind == JsonValueKind.Number && x.TryGetInt64(out v)) { }
        else if (x.ValueKind == JsonValueKind.String && long.TryParse(x.GetString(), NumberStyles.Integer, CultureInfo.InvariantCulture, out v)) { }
        else return null;
        return (int)Math.Clamp(v, min, max);
    }

    public static long? Long(this JsonElement? e)
    {
        if (e is not { } x) return null;
        return x.ValueKind == JsonValueKind.Number && x.TryGetInt64(out var v) ? v : null;
    }

    public static string? Str(this JsonElement? e, int maxLen = 256)
    {
        if (e is not { ValueKind: JsonValueKind.String } x) return null;
        var s = x.GetString();
        if (s is null) return null;
        // Strip control characters so hostile content cannot corrupt logs or the UI.
        var clean = new string(s.Where(c => !char.IsControl(c)).Take(maxLen).ToArray());
        return clean.Length == 0 ? null : clean;
    }

    public static bool? Bool(this JsonElement? e) =>
        e is { } x && (x.ValueKind == JsonValueKind.True || x.ValueKind == JsonValueKind.False) ? x.GetBoolean() : null;

    public static DateTimeOffset? Date(this JsonElement? e)
    {
        var s = e.Str(64);
        return s is not null && DateTimeOffset.TryParse(s, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var d) ? d : null;
    }
}
