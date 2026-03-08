$ErrorActionPreference = "Stop"

$serviceName = "CrystalSentinelARC"
$binaryPath = if ($env:CRYSTALSENTINEL_ARC_BINARY) {
    $env:CRYSTALSENTINEL_ARC_BINARY
} else {
    Join-Path $env:ProgramFiles "CrystalSentinel-ARC\bin\sentineld.exe"
}

sc.exe create $serviceName binPath= "`"$binaryPath`"" start= auto | Out-Null
sc.exe description $serviceName "CrystalSentinel-ARC runtime service" | Out-Null

Write-Host "Created Windows service $serviceName"
Write-Host "Binary path: $binaryPath"
