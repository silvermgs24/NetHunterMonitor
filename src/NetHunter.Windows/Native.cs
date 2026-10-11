using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace NetHunter.Windows;

/// <summary>P/Invoke declarations. Only documented Win32 APIs, plus DnsGetCacheDataTable (used by ipconfig /displaydns).</summary>
internal static class Native
{
    // ───── IP Helper ─────
    public const int AF_INET = 2, AF_INET6 = 23;
    public const int TCP_TABLE_OWNER_PID_ALL = 5;
    public const int UDP_TABLE_OWNER_PID = 1;
    public const int ERROR_INSUFFICIENT_BUFFER = 122;

    [DllImport("iphlpapi.dll", SetLastError = false)]
    public static extern uint GetExtendedTcpTable(IntPtr pTcpTable, ref int pdwSize, bool bOrder, int ulAf, int tableClass, uint reserved);

    [DllImport("iphlpapi.dll", SetLastError = false)]
    public static extern uint GetExtendedUdpTable(IntPtr pUdpTable, ref int pdwSize, bool bOrder, int ulAf, int tableClass, uint reserved);

    [StructLayout(LayoutKind.Sequential)]
    public struct MIB_TCPROW_OWNER_PID
    {
        public uint State, LocalAddr, LocalPort, RemoteAddr, RemotePort, OwningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    public unsafe struct MIB_TCP6ROW_OWNER_PID
    {
        public fixed byte LocalAddr[16];
        public uint LocalScopeId, LocalPort;
        public fixed byte RemoteAddr[16];
        public uint RemoteScopeId, RemotePort, State, OwningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct MIB_UDPROW_OWNER_PID
    {
        public uint LocalAddr, LocalPort, OwningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    public unsafe struct MIB_UDP6ROW_OWNER_PID
    {
        public fixed byte LocalAddr[16];
        public uint LocalScopeId, LocalPort, OwningPid;
    }

    // ───── processes ─────
    public const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
    public const uint TH32CS_SNAPPROCESS = 0x2;

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern SafeProcessHandle OpenProcess(uint access, bool inherit, int pid);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "QueryFullProcessImageNameW")]
    public static extern bool QueryFullProcessImageName(SafeProcessHandle h, uint flags, StringBuilder name, ref int size);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool GetProcessTimes(SafeProcessHandle h, out long creation, out long exit, out long kernel, out long user);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern SafeFileHandle CreateToolhelp32Snapshot(uint flags, uint pid);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "Process32FirstW")]
    public static extern bool Process32First(SafeFileHandle snap, ref PROCESSENTRY32W entry);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "Process32NextW")]
    public static extern bool Process32Next(SafeFileHandle snap, ref PROCESSENTRY32W entry);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct PROCESSENTRY32W
    {
        public uint dwSize;
        public uint cntUsage;
        public uint th32ProcessID;
        public IntPtr th32DefaultHeapID;
        public uint th32ModuleID;
        public uint cntThreads;
        public uint th32ParentProcessID;
        public int pcPriClassBase;
        public uint dwFlags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string szExeFile;
    }

    // ───── WinTrust (Authenticode) ─────
    public static readonly Guid WINTRUST_ACTION_GENERIC_VERIFY_V2 = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");
    public static readonly Guid DRIVER_ACTION_VERIFY = new("F750E6C3-38EE-11d1-85E5-00C04FC295EE");
    public const uint WTD_UI_NONE = 2, WTD_REVOKE_NONE = 0, WTD_CHOICE_FILE = 1, WTD_CHOICE_CATALOG = 2;
    public const uint WTD_STATEACTION_VERIFY = 1, WTD_STATEACTION_CLOSE = 2;
    public const uint WTD_REVOCATION_CHECK_NONE = 0x10, WTD_CACHE_ONLY_URL_RETRIEVAL = 0x1000, WTD_DISABLE_MD2_MD4 = 0x2000;

    [StructLayout(LayoutKind.Sequential)]
    public struct WINTRUST_FILE_INFO
    {
        public uint cbStruct;
        public IntPtr pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct WINTRUST_CATALOG_INFO
    {
        public uint cbStruct;
        public uint dwCatalogVersion;
        public IntPtr pcwszCatalogFilePath;
        public IntPtr pcwszMemberTag;
        public IntPtr pcwszMemberFilePath;
        public IntPtr hMemberFile;
        public IntPtr pbCalculatedFileHash;
        public uint cbCalculatedFileHash;
        public IntPtr pcCatalogContext;
        public IntPtr hCatAdmin;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct WINTRUST_DATA
    {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pUnion;
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
        public IntPtr pSignatureSettings;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct CATALOG_INFO
    {
        public uint cbStruct;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string wszCatalogFile;
    }

    [DllImport("wintrust.dll", ExactSpelling = true)]
    public static extern int WinVerifyTrust(IntPtr hwnd, ref Guid action, ref WINTRUST_DATA data);

    [DllImport("wintrust.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool CryptCATAdminAcquireContext2(out IntPtr hCatAdmin, ref Guid subsystem, string hashAlgorithm, IntPtr strongHashPolicy, uint flags);

    [DllImport("wintrust.dll", SetLastError = true)]
    public static extern bool CryptCATAdminCalcHashFromFileHandle2(IntPtr hCatAdmin, SafeFileHandle hFile, ref uint cbHash, byte[]? pbHash, uint flags);

    [DllImport("wintrust.dll", SetLastError = true)]
    public static extern IntPtr CryptCATAdminEnumCatalogFromHash(IntPtr hCatAdmin, byte[] pbHash, uint cbHash, uint flags, IntPtr phPrevCatInfo);

    [DllImport("wintrust.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool CryptCATCatalogInfoFromContext(IntPtr hCatInfo, ref CATALOG_INFO info, uint flags);

    [DllImport("wintrust.dll")]
    public static extern bool CryptCATAdminReleaseCatalogContext(IntPtr hCatAdmin, IntPtr hCatInfo, uint flags);

    [DllImport("wintrust.dll")]
    public static extern bool CryptCATAdminReleaseContext(IntPtr hCatAdmin, uint flags);

    // ───── DNS (PTR lookups) ─────
    public const int DnsFreeRecordList = 1;

    [StructLayout(LayoutKind.Sequential)]
    public struct DNS_RECORD_HEADER
    {
        public IntPtr pNext;
        public IntPtr pName;
        public ushort wType;
        public ushort wDataLength;
        public uint Flags;
        public uint dwTtl;
        public uint dwReserved;
    }

    [DllImport("dnsapi.dll", EntryPoint = "DnsQuery_W", CharSet = CharSet.Unicode, ExactSpelling = true)]
    public static extern int DnsQuery(string name, ushort type, uint options, IntPtr extra, out IntPtr results, IntPtr reserved);

    [DllImport("dnsapi.dll")]
    public static extern void DnsFree(IntPtr data, int freeType);

    // ───── DPAPI ─────
    [StructLayout(LayoutKind.Sequential)]
    public struct DATA_BLOB
    {
        public int cbData;
        public IntPtr pbData;
    }

    public const int CRYPTPROTECT_UI_FORBIDDEN = 0x1;

    [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool CryptProtectData(ref DATA_BLOB dataIn, string? description, IntPtr entropy, IntPtr reserved, IntPtr prompt, int flags, out DATA_BLOB dataOut);

    [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool CryptUnprotectData(ref DATA_BLOB dataIn, IntPtr description, IntPtr entropy, IntPtr reserved, IntPtr prompt, int flags, out DATA_BLOB dataOut);

    [DllImport("kernel32.dll")]
    public static extern IntPtr LocalFree(IntPtr mem);
}
