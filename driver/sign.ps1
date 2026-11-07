# sign.ps1 -- self-sign the driver for local testing
#
# For production you need an EV code-signing certificate + Microsoft
# attestation signing, or WHQL/HLK submission.
# Self-signed certs ONLY work with "bcdedit /set testsigning on".
param(
    [string]$Driver = "memkit_drv.sys"
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path $Driver)) {
    Write-Host "[ERR] $Driver not found"
    exit 1
}

$kits = "C:/Program Files (x86)/Windows Kits/10"
$signtool = @(
    "$kits/bin/10.0.26100.0/x64/signtool.exe",
    "$kits/bin/10.0.22621.0/x64/signtool.exe"
) | Where-Object { Test-Path $_ } | Select-Object -First 1

if (-not $signtool) {
    Write-Host "[ERR] signtool.exe not found under Windows Kits"
    exit 1
}

Write-Host "[1/3] create/reuse self-signed cert"
$cert = Get-ChildItem Cert:\CurrentUser\My |
        Where-Object { $_.Subject -eq 'CN=WvmTestDriver' } |
        Select-Object -First 1
if (-not $cert) {
    $cert = New-SelfSignedCertificate `
        -Type CodeSigningCert `
        -Subject 'CN=WvmTestDriver' `
        -KeyUsage DigitalSignature `
        -FriendlyName 'wvm test driver' `
        -CertStoreLocation Cert:\CurrentUser\My
}
Write-Host "      thumbprint = $($cert.Thumbprint)"

# Trust the cert locally, otherwise signtool verify /pa fails with
# "certificate chain terminated in a root not trusted".
# Root store = 让内核加载器接受；TrustedPublisher = 让 UAC/安装时不弹窗。
Write-Host "[1.5/3] install cert into Root + TrustedPublisher (needs admin)"
$rootStore = New-Object System.Security.Cryptography.X509Certificates.X509Store('Root','LocalMachine')
$pubStore  = New-Object System.Security.Cryptography.X509Certificates.X509Store('TrustedPublisher','LocalMachine')
try {
    $rootStore.Open('ReadWrite'); $rootStore.Add($cert); $rootStore.Close()
    $pubStore.Open('ReadWrite');  $pubStore.Add($cert);  $pubStore.Close()
    Write-Host "      added to LocalMachine\Root and LocalMachine\TrustedPublisher"
} catch {
    Write-Host "      [WARN] could not write to machine stores (needs admin): $($_.Exception.Message)"
}

Write-Host "[2/3] sign"
& $signtool sign /fd sha256 /sha1 $cert.Thumbprint /sm /v $Driver
if ($LASTEXITCODE -ne 0) {
    & $signtool sign /fd sha256 /sha1 $cert.Thumbprint /v $Driver
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[ERR] signing failed"
        exit 1
    }
}

Write-Host "[3/3] verify"
& $signtool verify /pa /v $Driver
if ($LASTEXITCODE -ne 0) {
    Write-Host "[ERR] verification failed"
    exit 1
}

Write-Host ""
Write-Host "[OK] signed. Remember: bcdedit /set testsigning on + reboot"
exit 0
