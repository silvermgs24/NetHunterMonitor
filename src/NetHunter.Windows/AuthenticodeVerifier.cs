using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Win32.SafeHandles;
using NetHunter.Core.Engine;
using NetHunter.Core.Models;

namespace NetHunter.Windows;

/// <summary>
/// Authenticode verification via WinVerifyTrust: first the embedded signature, then the Windows security
/// catalogs (most in-box Windows binaries are catalog-signed, not embedded-signed). Revocation checks are
/// disabled and URL retrieval is cache-only so verification never triggers network traffic.
/// </summary>
public sealed class AuthenticodeVerifier : ISignatureVerifier
{
    private const int TRUST_E_NOSIGNATURE = unchecked((int)0x800B0100);
    private const int TRUST_E_SUBJECT_FORM_UNKNOWN = unchecked((int)0x800B0003);
    private const int TRUST_E_PROVIDER_UNKNOWN = unchecked((int)0x800B0001);
    private const int CRYPT_E_FILE_ERROR = unchecked((int)0x80092003);

    private readonly ConcurrentDictionary<string, (DateTime Write, SignatureInfo Info)> _cache = new(StringComparer.OrdinalIgnoreCase);

    public SignatureInfo Verify(string path)
    {
        DateTime write;
        try { write = File.GetLastWriteTimeUtc(path); }
        catch (Exception) { return SignatureInfo.Unknown; }
        if (_cache.TryGetValue(path, out var c) && c.Write == write) return c.Info;
        var info = VerifyUncached(path);
        _cache[path] = (write, info);
        return info;
    }

    private static SignatureInfo VerifyUncached(string path)
    {
        if (!File.Exists(path)) return SignatureInfo.Unknown;
        int rc = VerifyEmbedded(path);
        if (rc == 0) return new SignatureInfo(SignatureStatus.Signed, EmbeddedSigner(path));
        if (rc is TRUST_E_NOSIGNATURE or TRUST_E_SUBJECT_FORM_UNKNOWN or TRUST_E_PROVIDER_UNKNOWN)
        {
            var cat = VerifyCatalog(path);
            if (cat is not null) return cat;
            return new SignatureInfo(SignatureStatus.Unsigned, null);
        }
        if (rc == CRYPT_E_FILE_ERROR) return SignatureInfo.Unknown;
        return new SignatureInfo(SignatureStatus.Invalid, $"WinVerifyTrust 0x{rc:X8}");
    }

    private static int VerifyEmbedded(string path)
    {
        var pPath = Marshal.StringToHGlobalUni(path);
        var fileInfo = new Native.WINTRUST_FILE_INFO { cbStruct = (uint)Marshal.SizeOf<Native.WINTRUST_FILE_INFO>(), pcwszFilePath = pPath };
        var pFile = Marshal.AllocHGlobal(Marshal.SizeOf(fileInfo));
        try
        {
            Marshal.StructureToPtr(fileInfo, pFile, false);
            return Run(Native.WTD_CHOICE_FILE, pFile);
        }
        finally
        {
            Marshal.FreeHGlobal(pFile);
            Marshal.FreeHGlobal(pPath);
        }
    }

    private static int Run(uint choice, IntPtr union)
    {
        var data = new Native.WINTRUST_DATA
        {
            cbStruct = (uint)Marshal.SizeOf<Native.WINTRUST_DATA>(),
            dwUIChoice = Native.WTD_UI_NONE,
            fdwRevocationChecks = Native.WTD_REVOKE_NONE,
            dwUnionChoice = choice,
            pUnion = union,
            dwStateAction = Native.WTD_STATEACTION_VERIFY,
            dwProvFlags = Native.WTD_REVOCATION_CHECK_NONE | Native.WTD_CACHE_ONLY_URL_RETRIEVAL | Native.WTD_DISABLE_MD2_MD4,
        };
        var action = Native.WINTRUST_ACTION_GENERIC_VERIFY_V2;
        int rc = Native.WinVerifyTrust(new IntPtr(-1), ref action, ref data); // INVALID_HANDLE_VALUE: no UI
        data.dwStateAction = Native.WTD_STATEACTION_CLOSE;
        Native.WinVerifyTrust(new IntPtr(-1), ref action, ref data);
        return rc;
    }

    private static SignatureInfo? VerifyCatalog(string path)
    {
        foreach (var alg in new[] { "SHA256", "SHA1" })
        {
            var guid = Native.DRIVER_ACTION_VERIFY;
            if (!Native.CryptCATAdminAcquireContext2(out var hCatAdmin, ref guid, alg, IntPtr.Zero, 0)) continue;
            try
            {
                byte[] hash;
                using (var fh = File.OpenHandle(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                {
                    uint cb = 0;
                    Native.CryptCATAdminCalcHashFromFileHandle2(hCatAdmin, fh, ref cb, null, 0);
                    if (cb == 0 || cb > 64) continue;
                    hash = new byte[cb];
                    if (!Native.CryptCATAdminCalcHashFromFileHandle2(hCatAdmin, fh, ref cb, hash, 0)) continue;
                }

                var hCatInfo = Native.CryptCATAdminEnumCatalogFromHash(hCatAdmin, hash, (uint)hash.Length, 0, IntPtr.Zero);
                if (hCatInfo == IntPtr.Zero) continue;
                try
                {
                    var ci = new Native.CATALOG_INFO { cbStruct = (uint)Marshal.SizeOf<Native.CATALOG_INFO>() };
                    if (!Native.CryptCATCatalogInfoFromContext(hCatInfo, ref ci, 0)) continue;

                    var tag = Convert.ToHexString(hash);
                    var pCat = Marshal.StringToHGlobalUni(ci.wszCatalogFile);
                    var pTag = Marshal.StringToHGlobalUni(tag);
                    var pMember = Marshal.StringToHGlobalUni(path);
                    var pHash = Marshal.AllocHGlobal(hash.Length);
                    Marshal.Copy(hash, 0, pHash, hash.Length);
                    var cat = new Native.WINTRUST_CATALOG_INFO
                    {
                        cbStruct = (uint)Marshal.SizeOf<Native.WINTRUST_CATALOG_INFO>(),
                        pcwszCatalogFilePath = pCat, pcwszMemberTag = pTag, pcwszMemberFilePath = pMember,
                        pbCalculatedFileHash = pHash, cbCalculatedFileHash = (uint)hash.Length, hCatAdmin = hCatAdmin,
                    };
                    var pUnion = Marshal.AllocHGlobal(Marshal.SizeOf(cat));
                    try
                    {
                        Marshal.StructureToPtr(cat, pUnion, false);
                        int rc = Run(Native.WTD_CHOICE_CATALOG, pUnion);
                        if (rc == 0) return new SignatureInfo(SignatureStatus.CatalogSigned, CatalogSigner(ci.wszCatalogFile));
                        return new SignatureInfo(SignatureStatus.Invalid, $"catalog verification 0x{rc:X8}");
                    }
                    finally
                    {
                        Marshal.FreeHGlobal(pUnion); Marshal.FreeHGlobal(pCat); Marshal.FreeHGlobal(pTag); Marshal.FreeHGlobal(pMember); Marshal.FreeHGlobal(pHash);
                    }
                }
                finally { Native.CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0); }
            }
            catch (IOException) { return null; }
            catch (UnauthorizedAccessException) { return null; }
            finally { Native.CryptCATAdminReleaseContext(hCatAdmin, 0); }
        }
        return null;
    }

    private static string? EmbeddedSigner(string path)
    {
        try
        {
#pragma warning disable SYSLIB0057
            using var cert = new X509Certificate2(X509Certificate.CreateFromSignedFile(path));
#pragma warning restore SYSLIB0057
            return cert.GetNameInfo(X509NameType.SimpleName, false);
        }
        catch (Exception) { return null; }
    }

    private static string? CatalogSigner(string catalogPath)
    {
        try
        {
#pragma warning disable SYSLIB0057
            using var cert = new X509Certificate2(X509Certificate.CreateFromSignedFile(catalogPath));
#pragma warning restore SYSLIB0057
            return cert.GetNameInfo(X509NameType.SimpleName, false);
        }
        catch (Exception) { return "Windows catalog"; }
    }
}
