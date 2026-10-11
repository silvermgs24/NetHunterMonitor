using System.Collections.Concurrent;
using System.Security.Cryptography;

namespace NetHunter.Core.Util;

/// <summary>
/// SHA-256 of executables with a cache keyed by (path, size, last-write). Files that are in use
/// are opened with full sharing so we never block the process we are inspecting.
/// </summary>
public sealed class FileHasher
{
    private readonly ConcurrentDictionary<string, (long Size, DateTime Write, string Hash)> _cache = new(StringComparer.OrdinalIgnoreCase);
    private readonly SemaphoreSlim _gate = new(2);

    public long MaxBytes { get; set; } = 512L * 1024 * 1024;

    public static string ComputeSha256(Stream stream)
    {
        using var sha = SHA256.Create();
        return Convert.ToHexString(sha.ComputeHash(stream)).ToLowerInvariant();
    }

    public static string ComputeSha256(ReadOnlySpan<byte> data) => Convert.ToHexString(SHA256.HashData(data)).ToLowerInvariant();

    /// <summary>Returns the lowercase hex SHA-256, or null if the file cannot be read (reason in <paramref name="error"/>).</summary>
    public string? TryHash(string path, out string? error)
    {
        error = null;
        try
        {
            var fi = new FileInfo(path);
            if (!fi.Exists) { error = "file not found"; return null; }
            if (fi.Length > MaxBytes) { error = $"file larger than {MaxBytes / (1024 * 1024)} MB; not hashed"; return null; }
            if (_cache.TryGetValue(path, out var c) && c.Size == fi.Length && c.Write == fi.LastWriteTimeUtc) return c.Hash;

            _gate.Wait();
            try
            {
                using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 1 << 16, FileOptions.SequentialScan);
                var hash = ComputeSha256(fs);
                _cache[path] = (fi.Length, fi.LastWriteTimeUtc, hash);
                return hash;
            }
            finally { _gate.Release(); }
        }
        catch (UnauthorizedAccessException) { error = "access denied"; }
        catch (IOException ex) { error = ex.Message; }
        return null;
    }
}
