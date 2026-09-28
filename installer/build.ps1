# 建置通用範本 MSI（不含任何組織資訊）。
# 需要 .NET SDK 與 WiX v5：dotnet tool install --global wix --version 5.0.2
# 要簽章 endpoint-agent.exe 的話，在 cargo build 之後、wix build 之前簽。
param(
    [string]$Version = "",
    [string]$Out = ""
)
$ErrorActionPreference = "Stop"
$repo = Split-Path $PSScriptRoot -Parent
if (-not $Version) {
    $Version = (Select-String -Path "$repo\Cargo.toml" -Pattern '^version = "(.+)"').Matches[0].Groups[1].Value
}
if (-not $Out) { $Out = "$repo\target\endpoint-agent-$Version.msi" }
cargo build --release -p endpoint-agent --manifest-path "$repo\Cargo.toml"
if ($LASTEXITCODE) { throw "cargo build failed" }
wix build "$PSScriptRoot\agent.wxs" -arch x64 `
    -d "Version=$Version" -d "AgentExe=$repo\target\release\endpoint-agent.exe" -o $Out
if ($LASTEXITCODE) { throw "wix build failed" }
Write-Host "MSI: $Out"
