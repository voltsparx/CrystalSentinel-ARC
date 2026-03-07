$ErrorActionPreference = "Stop"

$serviceName = "CrystalSentinel"
$binaryPath = if ($env:CRYSTALSENTINEL_BINARY) {
    $env:CRYSTALSENTINEL_BINARY
} else {
    Join-Path $env:ProgramFiles "CrystalSentinel-CRA\bin\sentineld.exe"
}

sc.exe create $serviceName binPath= "`"$binaryPath`"" start= auto | Out-Null
sc.exe description $serviceName "CrystalSentinel-CRA runtime service" | Out-Null

Write-Host "Created Windows service $serviceName"
Write-Host "Binary path: $binaryPath"
