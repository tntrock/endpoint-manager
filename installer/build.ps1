# 建置通用範本 MSI（不含任何組織資訊）。
# 需要 .NET SDK 與 WiX v5：dotnet tool install --global wix --version 5.0.2
# 要簽章 endpoint-agent.exe：先 cargo build、簽章，再以 -NoCargo 執行本腳本。
param(
    [string]$Version = "",
    [string]$Out = "",
    [switch]$NoCargo
)
$ErrorActionPreference = "Stop"
$repo = Split-Path $PSScriptRoot -Parent
if (-not $Version) {
    $Version = (Select-String -Path "$repo\Cargo.toml" -Pattern '^version = "(.+)"').Matches[0].Groups[1].Value
}
if (-not $Out) { $Out = "$repo\target\endpoint-agent-$Version.msi" }
if (-not $NoCargo) {
    cargo build --release -p endpoint-agent --manifest-path "$repo\Cargo.toml"
    if ($LASTEXITCODE) { throw "cargo build failed" }
}
wix build "$PSScriptRoot\agent.wxs" -arch x64 `
    -d "Version=$Version" -d "AgentExe=$repo\target\release\endpoint-agent.exe" -o $Out
if ($LASTEXITCODE) { throw "wix build failed" }
Write-Host "MSI: $Out"
