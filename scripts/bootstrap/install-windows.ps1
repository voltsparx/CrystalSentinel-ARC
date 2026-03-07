$ErrorActionPreference = "Stop"

$root = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$programFilesRoot = if ($env:CRYSTALSENTINEL_PROGRAMFILES) {
    $env:CRYSTALSENTINEL_PROGRAMFILES
} else {
    Join-Path $env:ProgramFiles "CrystalSentinel-CRA"
}
$programDataRoot = if ($env:CRYSTALSENTINEL_PROGRAMDATA) {
    $env:CRYSTALSENTINEL_PROGRAMDATA
} else {
    Join-Path $env:ProgramData "CrystalSentinel-CRA"
}

$binRoot = Join-Path $programFilesRoot "bin"
$libRoot = Join-Path $programFilesRoot "lib"
$configRoot = Join-Path $programDataRoot "etc"
$rulesRoot = Join-Path $configRoot "rules"
$logRoot = Join-Path $programDataRoot "logs"
$stateRoot = Join-Path $programDataRoot "state"
$runRoot = Join-Path $programDataRoot "run"

Write-Host "Installing CrystalSentinel-CRA layout for Windows"
Write-Host "  program files: $programFilesRoot"
Write-Host "  program data:  $programDataRoot"
Write-Host "  rules root:    $rulesRoot"

$dirs = @(
    $binRoot,
    $libRoot,
    $configRoot,
    $rulesRoot,
    (Join-Path $rulesRoot "signatures"),
    (Join-Path $rulesRoot "heuristics"),
    (Join-Path $rulesRoot "anomaly"),
    (Join-Path $rulesRoot "baselines"),
    (Join-Path $rulesRoot "response-policies"),
    (Join-Path $rulesRoot "allowlists"),
    (Join-Path $rulesRoot "states"),
    (Join-Path $rulesRoot "compiled"),
    $logRoot,
    $stateRoot,
    $runRoot
)

foreach ($dir in $dirs) {
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
}

Copy-Item (Join-Path $root "configs\base\runtime.toml") (Join-Path $configRoot "runtime.toml") -Force
Copy-Item (Join-Path $root "configs\base\install-layout.toml") (Join-Path $configRoot "install-layout.toml") -Force
Copy-Item (Join-Path $root "configs\base\defense-modules.toml") (Join-Path $configRoot "defense-modules.toml") -Force
Copy-Item (Join-Path $root "rules\*") $rulesRoot -Recurse -Force

$sentineld = Join-Path $root "target\release\sentineld.exe"
$sentinelctl = Join-Path $root "target\release\sentinelctl.exe"

if (Test-Path $sentineld) {
    Copy-Item $sentineld (Join-Path $binRoot "sentineld.exe") -Force
}

if (Test-Path $sentinelctl) {
    Copy-Item $sentinelctl (Join-Path $binRoot "sentinelctl.exe") -Force
}

Write-Host "Installation layout complete."
Write-Host "Build release binaries first with: cargo build --release --bins"
