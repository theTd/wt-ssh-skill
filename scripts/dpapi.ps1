param([Parameter(Mandatory=$true)][ValidateSet("Protect","Unprotect")][string]$Action)
$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.Security

# UTF-8 on both redirected pipes so non-ASCII passphrases round-trip exactly.
try { [Console]::InputEncoding = [Text.Encoding]::UTF8 } catch {}
try { [Console]::OutputEncoding = [Text.Encoding]::UTF8 } catch {}

$payload = [Console]::In.ReadToEnd()
if ($Action -eq "Protect") {
    $bytes = [Text.Encoding]::UTF8.GetBytes($payload)
    $enc = [Security.Cryptography.ProtectedData]::Protect($bytes, $null,
        [Security.Cryptography.DataProtectionScope]::CurrentUser)
    [Console]::Out.Write([Convert]::ToBase64String($enc))
} else {
    $dec = [Security.Cryptography.ProtectedData]::Unprotect([Convert]::FromBase64String($payload.Trim()),
        $null, [Security.Cryptography.DataProtectionScope]::CurrentUser)
    [Console]::Out.Write([Text.Encoding]::UTF8.GetString($dec))
}
