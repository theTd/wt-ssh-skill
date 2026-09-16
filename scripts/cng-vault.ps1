param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateSet("init", "wrap", "unwrap", "unwrap-many", "status", "remove")]
    [string]$Action,

    [string]$Provider = "Microsoft Platform Crypto Provider",
    [string]$KeyName = "wtssh-vault",
    # Shown in the CNG PIN dialog (NCRYPT_USE_CONTEXT_PROPERTY). Not a secret:
    # host/key names only. unwrap without it still gets a generic fallback.
    [string]$UseContext = ""
)
# CNG key vault host for wtssh. One TPM-resident RSA key ("wtssh-vault" by
# name) with UI Policy PROTECT|FORCE_HIGH: same-user silent decrypt is
# refused with NTE_SILENT_CONTEXT (verified on this machine), every use
# requires the CNG consent dialog (PIN).
#
#   init    create vault key (dialog: set PIN), self-test wrap+unwrap
#           (dialog: consent). stdout: {"ok": true}
#   wrap    silent RSA-OAEP(SHA256) encrypt. stdin: hex DEK; stdout: hex CT
#   unwrap  interactive decrypt (dialog). stdin: hex CT; stdout: hex DEK
#           -UseContext is relayed into the PIN UI (not a secret; argv is fine)
#   unwrap-many  interactive batch decrypt under ONE consent (dialog once):
#           stdin: hex CTs, one per line; stdout: hex DEKs, one per line.
#           PCP does not re-prompt within the same key handle, so a
#           whole jump chain unwraps with a single PIN gesture.
#   status  silent. stdout: {"exists": true|false}
#   remove  silent. deletes the vault key.
#
# Payloads travel via stdin, never argv (same-user processes can read
# command lines of other processes).
#
# Exit codes: 0 ok; 2 vault key missing (run init); 3 user cancelled /
#   consent refused; 4 provider unavailable; 1 other error.
#
# Marshal notes (verified by probe): NCRYPT_OAEP_PADDING_INFO has NO
# cbSize; NCRYPT_PAD_OAEP_FLAG=0x4; NCryptOpenKey takes (hProv, &hKey,
# name, spec, flags) -- no algorithm parameter. Keys are NEVER deleted
# except by the remove action.

$ErrorActionPreference = "Stop"

$src = @'
using System;
using System.Runtime.InteropServices;
using System.Text;

namespace WtSshVault {
    public static class Vault {
        [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
        static extern int NCryptOpenStorageProvider(out IntPtr h, string p, int f);
        [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
        static extern int NCryptCreatePersistedKey(IntPtr h, out IntPtr k, string alg, string name, int spec, int f);
        [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
        static extern int NCryptSetProperty(IntPtr k, string prop, byte[] buf, int cb, int f);
        [DllImport("ncrypt.dll")]
        static extern int NCryptFinalizeKey(IntPtr k, int f);
        [DllImport("ncrypt.dll")]
        static extern int NCryptEncrypt(IntPtr k, byte[] ib, int ci, ref NCOAEP p, byte[] ob, int cb, out int r, int f);
        [DllImport("ncrypt.dll")]
        static extern int NCryptDecrypt(IntPtr k, byte[] ib, int ci, ref NCOAEP p, byte[] ob, int cb, out int r, int f);
        [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
        static extern int NCryptOpenKey(IntPtr h, out IntPtr k, string name, int spec, int f);
        [DllImport("ncrypt.dll")]
        static extern int NCryptDeleteKey(IntPtr k, int f);
        [DllImport("ncrypt.dll")]
        static extern int NCryptFreeObject(IntPtr h);
        [DllImport("kernel32.dll")]
        static extern IntPtr GetConsoleWindow();
        [DllImport("user32.dll")]
        static extern IntPtr GetForegroundWindow();

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct NCOAEP {
            [MarshalAs(UnmanagedType.LPWStr)] public string alg;
            public IntPtr label;
            public int cbLabel;
        }
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct UIPOL {
            public int dwVersion;
            public int dwFlags;
            [MarshalAs(UnmanagedType.LPWStr)] public string pszCreationTitle;
            [MarshalAs(UnmanagedType.LPWStr)] public string pszFriendlyName;
            [MarshalAs(UnmanagedType.LPWStr)] public string pszDescription;
        }

        const int PAD_OAEP = 0x4;
        const int SILENT = 0x40;
        const int OVERWRITE = 0x80;
        const int NTE_NOT_FOUND = unchecked((int)0x80090016);

        static string H(int r) { return string.Format("0x{0:X8}", r & 0xFFFFFFFF); }
        static void Err(string what, int rc) { Console.Error.WriteLine(what + ": " + H(rc)); }

        public static int Init(string prov, string kname) {
            IntPtr hp; int rc = NCryptOpenStorageProvider(out hp, prov, 0);
            if (rc != 0) { Err("open provider", rc); return 4; }
            // refuse to clobber an existing vault key: blobs sealed under
            // it would become permanently undecryptable. wtssh.py checks
            // too, but this script is directly invokable -- the guard must
            // live here (defense against a bypassed CLI).
            IntPtr existing;
            rc = NCryptOpenKey(hp, out existing, kname, 0, 0);
            if (rc == 0) {
                NCryptFreeObject(existing);
                Err("vault key already exists (refusing to overwrite)", 0);
                return 5;
            }
            if (rc != NTE_NOT_FOUND) { Err("open key", rc); return 1; }
            IntPtr hk;
            rc = NCryptCreatePersistedKey(hp, out hk, "RSA", kname, 0, 0);
            if (rc != 0) { Err("create", rc); return 1; }
            byte[] usage = BitConverter.GetBytes(1);  // NCRYPT_ALLOW_DECRYPT_FLAG only
            NCryptSetProperty(hk, "Key Usage", usage, 4, 0);
            var pol = new UIPOL {
                dwVersion = 1,
                dwFlags = 0x3,
                pszCreationTitle = "wtssh key vault",
                pszFriendlyName = "wtssh vault key",
                pszDescription = "Protects wtssh imported private keys (TPM-backed)"
            };
            int sz = Marshal.SizeOf(pol);
            IntPtr p = Marshal.AllocHGlobal(sz);
            Marshal.StructureToPtr(pol, p, false);
            byte[] buf = new byte[sz];
            Marshal.Copy(p, buf, 0, sz);
            Marshal.FreeHGlobal(p);
            rc = NCryptSetProperty(hk, "UI Policy", buf, sz, 0);
            if (rc != 0) { NCryptDeleteKey(hk, 0); Err("UI Policy", rc); return 1; }
            rc = NCryptFinalizeKey(hk, 0); // dialog: set PIN
            if (rc != 0) { NCryptDeleteKey(hk, 0); Err("finalize", rc); return 3; }
            // key intentionally SURVIVES: handles close with the process
            return 0;
        }

        public static int Wrap(string prov, string kname, string dekHex, out string ctHex) {
            ctHex = null;
            IntPtr hp; int rc = NCryptOpenStorageProvider(out hp, prov, 0);
            if (rc != 0) { Err("open provider", rc); return 4; }
            IntPtr hk; rc = NCryptOpenKey(hp, out hk, kname, 0, 0);
            if (rc == NTE_NOT_FOUND) return 2;
            if (rc != 0) { Err("open key", rc); return 1; }
            var oaep = new NCOAEP { alg = "SHA256", label = IntPtr.Zero, cbLabel = 0 };
            byte[] dek = HexToBytes(dekHex);
            byte[] ob = new byte[512]; int on;
            rc = NCryptEncrypt(hk, dek, dek.Length, ref oaep, ob, 512, out on, PAD_OAEP | SILENT);
            if (rc != 0) { Err("encrypt", rc); return 1; }
            ctHex = BitConverter.ToString(ob, 0, on).Replace("-", "");
            return 0;
        }

        static void SetPinUi(IntPtr hk, string useContext) {
            // HWND Handle: pointer-sized HWND value, so the PIN dialog is
            // parented (NULL parent is explicitly discouraged by the docs).
            IntPtr hwnd = GetConsoleWindow();
            if (hwnd == IntPtr.Zero) hwnd = GetForegroundWindow();
            if (hwnd != IntPtr.Zero) {
                byte[] hwndBuf = IntPtr.Size == 8
                    ? BitConverter.GetBytes(hwnd.ToInt64())
                    : BitConverter.GetBytes(hwnd.ToInt32());
                int hr = NCryptSetProperty(hk, "HWND Handle", hwndBuf, hwndBuf.Length, 0);
                if (hr != 0) Err("HWND Handle", hr);  // non-fatal: PIN still works
            }
            // Use Context is handle-local and not persisted. PCP relays it
            // into the PIN UI ("this application needs to use this key to …").
            string ctx = string.IsNullOrEmpty(useContext) ? "wtssh vault unwrap" : useContext;
            byte[] buf = Encoding.Unicode.GetBytes(ctx + "\0");
            int rc = NCryptSetProperty(hk, "Use Context", buf, buf.Length, 0);
            if (rc != 0) Err("Use Context", rc);  // non-fatal: Python also prints it
        }

        public static int Unwrap(string prov, string kname, string ctHex,
                                 string useContext, out string dekHex) {
            dekHex = null;
            IntPtr hp; int rc = NCryptOpenStorageProvider(out hp, prov, 0);
            if (rc != 0) { Err("open provider", rc); return 4; }
            IntPtr hk; rc = NCryptOpenKey(hp, out hk, kname, 0, 0);
            if (rc == NTE_NOT_FOUND) return 2;
            if (rc != 0) { Err("open key", rc); return 1; }
            SetPinUi(hk, useContext);
            var oaep = new NCOAEP { alg = "SHA256", label = IntPtr.Zero, cbLabel = 0 };
            byte[] ct = HexToBytes(ctHex);
            byte[] ob = new byte[512]; int on;
            rc = NCryptDecrypt(hk, ct, ct.Length, ref oaep, ob, 512, out on, PAD_OAEP);
            if (rc != 0) { Err("decrypt", rc); return 3; }
            dekHex = BitConverter.ToString(ob, 0, on).Replace("-", "");
            return 0;
        }

        public static int UnwrapMany(string prov, string kname, string[] cts,
                                     string useContext, out string dekHexes) {
            dekHexes = null;
            IntPtr hp; int rc = NCryptOpenStorageProvider(out hp, prov, 0);
            if (rc != 0) { Err("open provider", rc); return 4; }
            IntPtr hk; rc = NCryptOpenKey(hp, out hk, kname, 0, 0);
            if (rc == NTE_NOT_FOUND) return 2;
            if (rc != 0) { Err("open key", rc); return 1; }
            SetPinUi(hk, useContext);
            var oaep = new NCOAEP { alg = "SHA256", label = IntPtr.Zero, cbLabel = 0 };
            // Collect EVERYTHING before emitting anything: a mid-batch failure
            // must not leak partial DEKs to stdout (wtssh dies on nonzero rc
            // and would ignore them anyway, but fail-closed costs nothing).
            var sb = new StringBuilder();
            for (int i = 0; i < cts.Length; i++) {
                byte[] ct = HexToBytes(cts[i]);
                byte[] ob = new byte[512]; int on;
                rc = NCryptDecrypt(hk, ct, ct.Length, ref oaep, ob, 512, out on, PAD_OAEP);
                if (rc != 0) { Err("decrypt[" + i + "]", rc); return 3; }
                if (i > 0) sb.Append('\n');
                sb.Append(BitConverter.ToString(ob, 0, on).Replace("-", ""));
            }
            dekHexes = sb.ToString();
            return 0;
        }

        public static int Status(string prov, string kname, out bool exists) {
            exists = false;
            IntPtr hp; int rc = NCryptOpenStorageProvider(out hp, prov, 0);
            if (rc != 0) { Err("open provider", rc); return 4; }
            IntPtr hk; rc = NCryptOpenKey(hp, out hk, kname, 0, 0);
            exists = rc == 0;
            return 0;
        }

        public static int Remove(string prov, string kname) {
            IntPtr hp; int rc = NCryptOpenStorageProvider(out hp, prov, 0);
            if (rc != 0) { Err("open provider", rc); return 4; }
            IntPtr hk; rc = NCryptOpenKey(hp, out hk, kname, 0, 0);
            if (rc == NTE_NOT_FOUND) return 2;
            if (rc != 0) { Err("open key", rc); return 1; }
            rc = NCryptDeleteKey(hk, 0);
            if (rc != 0) { Err("delete", rc); return 1; }
            return 0;
        }

        static byte[] HexToBytes(string h) {
            byte[] b = new byte[h.Length / 2];
            for (int i = 0; i < b.Length; i++) b[i] = Convert.ToByte(h.Substring(i * 2, 2), 16);
            return b;
        }
    }
}
'@
Add-Type -TypeDefinition $src -ErrorAction Stop

function Read-StdinHex {
    $in_ = [Console]::In.ReadToEnd().Trim()
    if (-not $in_ -or $in_ -notmatch '^[0-9a-fA-F]+$') {
        [Console]::Error.WriteLine("expected hex payload on stdin")
        exit 1
    }
    return $in_
}

switch ($Action) {
    "init" {
        $rc = [WtSshVault.Vault]::Init($Provider, $KeyName)
        if ($rc -ne 0) { exit $rc }
        # self-test: wrap + unwrap a throwaway DEK (one more consent dialog)
        $dek = New-Object byte[] 32
        (New-Object System.Security.Cryptography.RNGCryptoServiceProvider).GetBytes($dek)
        $dekHex = [BitConverter]::ToString($dek).Replace("-", "")
        $ctHex = $null
        $rc = [WtSshVault.Vault]::Wrap($Provider, $KeyName, $dekHex, [ref]$ctHex)
        if ($rc -ne 0) { exit $rc }
        $outHex = $null
        $initCtx = if ($env:WTSSH_UI_LANG -eq "en") { "wtssh vault init self-test" } else { "初始化 wtssh vault（自测）" }
        $rc = [WtSshVault.Vault]::Unwrap($Provider, $KeyName, $ctHex, $initCtx, [ref]$outHex)
        if ($rc -ne 0) { exit $rc }
        if ($outHex -ne $dekHex) {
            [Console]::Error.WriteLine("self-test roundtrip mismatch")
            exit 1
        }
        [Console]::Out.WriteLine('{"ok": true}')
        exit 0
    }
    "wrap" {
        $ctHex = $null
        $rc = [WtSshVault.Vault]::Wrap($Provider, $KeyName, (Read-StdinHex), [ref]$ctHex)
        if ($rc -ne 0) { exit $rc }
        [Console]::Out.WriteLine($ctHex)
        exit 0
    }
    "unwrap" {
        $outHex = $null
        $rc = [WtSshVault.Vault]::Unwrap($Provider, $KeyName, (Read-StdinHex), $UseContext, [ref]$outHex)
        if ($rc -ne 0) { exit $rc }
        [Console]::Out.WriteLine($outHex)
        exit 0
    }
    "unwrap-many" {
        $lines = @([Console]::In.ReadToEnd() -split "`r?`n" |
                   Where-Object { $_.Trim() } | ForEach-Object { $_.Trim() })
        if ($lines.Count -eq 0) {
            [Console]::Error.WriteLine("expected hex payloads on stdin, one per line")
            exit 1
        }
        foreach ($ln in $lines) {
            if ($ln -notmatch '^[0-9a-fA-F]+$') {
                [Console]::Error.WriteLine("expected hex payloads on stdin, one per line")
                exit 1
            }
        }
        $outHexes = $null
        $rc = [WtSshVault.Vault]::UnwrapMany($Provider, $KeyName,
                                             [string[]]$lines, $UseContext,
                                             [ref]$outHexes)
        if ($rc -ne 0) { exit $rc }
        [Console]::Out.WriteLine($outHexes)
        exit 0
    }
    "status" {
        $exists = $false
        $rc = [WtSshVault.Vault]::Status($Provider, $KeyName, [ref]$exists)
        if ($rc -ne 0) { exit $rc }
        [Console]::Out.WriteLine('{"exists": ' + ($(if ($exists) { 'true' } else { 'false' })) + '}')
        exit 0
    }
    "remove" {
        # Drill-mode refusal, mirroring wtssh.py: WTSSH_KEYS/WTSSH_SECRETS
        # point the blob checks below at sandbox dirs, so a drill caller
        # would pass them while the real blobs stay sealed elsewhere --
        # deleting the real TPM key would orphan those permanently.
        if ($env:WTSSH_KEYS -or $env:WTSSH_SECRETS) {
            [Console]::Error.WriteLine("refusing remove: WTSSH_KEYS/WTSSH_SECRETS are set (drill mode); clear them first")
            exit 5
        }
        # Guard: deleting the vault key orphans every sealed blob. wtssh.py
        # enforces this too, but this script is directly invokable -- the
        # check must live here. Default dirs mirror wtssh.py (%LOCALAPPDATA%
        # \wtssh); WTSSH_KEYS/WTSSH_SECRETS override for sandboxes.
        $keysDir    = if ($env:WTSSH_KEYS)    { $env:WTSSH_KEYS }    else { Join-Path $env:LOCALAPPDATA "wtssh\keys" }
        $secretsDir = if ($env:WTSSH_SECRETS) { $env:WTSSH_SECRETS } else { Join-Path $env:LOCALAPPDATA "wtssh\secrets" }
        $blobs = @()
        if (Test-Path $keysDir)    { $blobs += Get-ChildItem $keysDir -Filter *.wtv -ErrorAction SilentlyContinue }
        if (Test-Path $secretsDir) { $blobs += Get-ChildItem $secretsDir -Filter *.bin -ErrorAction SilentlyContinue }
        if ($blobs.Count -gt 0) {
            [Console]::Error.WriteLine("refusing remove: $($blobs.Count) sealed blob(s) still exist; clear them via wtssh first")
            exit 5
        }
        exit [WtSshVault.Vault]::Remove($Provider, $KeyName)
    }
}
