using System.Globalization;
using System.Windows;
using System.Windows.Data;
using System.Windows.Media;
using NetHunter.Core.Models;

namespace NetHunter.App.Ui;

public static class RiskColors
{
    public static readonly SolidColorBrush Low = Freeze(new SolidColorBrush(Color.FromRgb(0x1A, 0x3D, 0x26)));
    public static readonly SolidColorBrush Medium = Freeze(new SolidColorBrush(Color.FromRgb(0x4A, 0x3A, 0x0E)));
    public static readonly SolidColorBrush High = Freeze(new SolidColorBrush(Color.FromRgb(0x55, 0x2D, 0x10)));
    public static readonly SolidColorBrush Critical = Freeze(new SolidColorBrush(Color.FromRgb(0x5E, 0x17, 0x1B)));
    public static readonly SolidColorBrush Unknown = Freeze(new SolidColorBrush(Color.FromRgb(0x2A, 0x31, 0x3B)));

    public static readonly SolidColorBrush LowFg = Freeze(new SolidColorBrush(Color.FromRgb(0x56, 0xD3, 0x64)));
    public static readonly SolidColorBrush MediumFg = Freeze(new SolidColorBrush(Color.FromRgb(0xE3, 0xB3, 0x41)));
    public static readonly SolidColorBrush HighFg = Freeze(new SolidColorBrush(Color.FromRgb(0xFF, 0xA6, 0x57)));
    public static readonly SolidColorBrush CriticalFg = Freeze(new SolidColorBrush(Color.FromRgb(0xFF, 0x7B, 0x72)));
    public static readonly SolidColorBrush UnknownFg = Freeze(new SolidColorBrush(Color.FromRgb(0xA0, 0xAB, 0xB8)));

    private static SolidColorBrush Freeze(SolidColorBrush b) { b.Freeze(); return b; }

    public static RiskLevel Level(object? v) => v switch
    {
        RiskLevel l => l,
        int i => (RiskLevel)i,
        _ => RiskLevel.Unknown,
    };

    public static Brush Background(RiskLevel l) => l switch
    {
        RiskLevel.Low => Low, RiskLevel.Medium => Medium, RiskLevel.High => High, RiskLevel.Critical => Critical, _ => Unknown,
    };

    public static Brush Foreground(RiskLevel l) => l switch
    {
        RiskLevel.Low => LowFg, RiskLevel.Medium => MediumFg, RiskLevel.High => HighFg, RiskLevel.Critical => CriticalFg, _ => UnknownFg,
    };
}

public sealed class RiskBrushConverter : IValueConverter
{
    public object Convert(object value, Type t, object p, CultureInfo c) => RiskColors.Background(RiskColors.Level(value));
    public object ConvertBack(object value, Type t, object p, CultureInfo c) => Binding.DoNothing;
}

public sealed class RiskForegroundConverter : IValueConverter
{
    public object Convert(object value, Type t, object p, CultureInfo c) => RiskColors.Foreground(RiskColors.Level(value));
    public object ConvertBack(object value, Type t, object p, CultureInfo c) => Binding.DoNothing;
}

public sealed class RiskTextConverter : IValueConverter
{
    public object Convert(object value, Type t, object p, CultureInfo c)
    {
        var l = RiskColors.Level(value);
        return $"{l.Glyph()} {l.Label()}";
    }
    public object ConvertBack(object value, Type t, object p, CultureInfo c) => Binding.DoNothing;
}

public sealed class LocalTimeConverter : IValueConverter
{
    public object Convert(object value, Type t, object p, CultureInfo c) => value is DateTimeOffset d ? d.ToLocalTime().ToString("HH:mm:ss") : "";
    public object ConvertBack(object value, Type t, object p, CultureInfo c) => Binding.DoNothing;
}

public sealed class LocalDateTimeConverter : IValueConverter
{
    public object Convert(object value, Type t, object p, CultureInfo c) => value is DateTimeOffset d ? d.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss") : "";
    public object ConvertBack(object value, Type t, object p, CultureInfo c) => Binding.DoNothing;
}

public sealed class UpperConverter : IValueConverter
{
    public object Convert(object value, Type t, object p, CultureInfo c) => value?.ToString()?.ToUpperInvariant() ?? "";
    public object ConvertBack(object value, Type t, object p, CultureInfo c) => Binding.DoNothing;
}

public sealed class DirectionConverter : IValueConverter
{
    public object Convert(object value, Type t, object p, CultureInfo c) => value switch
    {
        Direction.Inbound => "⬇ IN",
        Direction.Outbound => "⬆ OUT",
        _ => "?",
    };
    public object ConvertBack(object value, Type t, object p, CultureInfo c) => Binding.DoNothing;
}

public sealed class UnknownConverter : IValueConverter
{
    public object Convert(object value, Type t, object p, CultureInfo c) => value is null || value is string { Length: 0 } ? (p as string ?? "Unknown") : value;
    public object ConvertBack(object value, Type t, object p, CultureInfo c) => Binding.DoNothing;
}

public sealed class DetectionConverter : IValueConverter
{
    public object Convert(object value, Type t, object p, CultureInfo c) => value is DetectionClass d ? (d == DetectionClass.None ? "" : d.Describe()) : "";
    public object ConvertBack(object value, Type t, object p, CultureInfo c) => Binding.DoNothing;
}

public sealed class BoolToVisibilityConverter : IValueConverter
{
    public object Convert(object value, Type t, object p, CultureInfo c) => (value is true) != (p as string == "invert") ? Visibility.Visible : Visibility.Collapsed;
    public object ConvertBack(object value, Type t, object p, CultureInfo c) => Binding.DoNothing;
}
