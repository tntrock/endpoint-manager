# MSI 安裝／升級／解除安裝測試。需要系統管理員權限（CI 的 windows runner）。
# $Msi：以 agent-msi 產生、已包好設定的安裝檔；$UpgradeMsi：較新版本的通用範本（不帶任何屬性）。
param(
    [Parameter(Mandatory)][string]$Msi,
    [Parameter(Mandatory)][string]$UpgradeMsi,
    [Parameter(Mandatory)][string]$Token,
    [Parameter(Mandatory)][string]$RootPem
)
$ErrorActionPreference = "Stop"
$svcName = "EndpointManagerAgent"
$data = "C:\ProgramData\EndpointManager"
$evtKey = "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application\$svcName"

function Check($cond, $msg) {
    if (-not $cond) { throw "FAIL: $msg" }
    Write-Host "ok: $msg"
}
function Msiexec($argList) {
    $p = Start-Process msiexec.exe -ArgumentList $argList -Wait -PassThru
    return $p.ExitCode
}
function B64($pem) { ((Get-Content $pem) | Where-Object { $_ -notmatch "^-----" }) -join "" }

# 安裝：不帶任何命令列參數，設定全部來自 MSI 內
Check ((Msiexec "/i `"$Msi`" /qn /l*v install.log") -eq 0) "install"
Check ((Get-Service $svcName).Status -eq "Running") "service running"
Check ((Get-CimInstance Win32_Service -Filter "Name='$svcName'").StartMode -eq "Auto") "auto start"
$cfg = Get-Content "$data\config.json" -Raw | ConvertFrom-Json
Check ($cfg.server_url -eq "https://localhost:9") "server_url from MSI"
Check ($cfg.enroll_token -eq $Token) "token from MSI"
Check ((B64 "$data\root.pem") -eq (B64 $RootPem)) "root.pem from MSI"
$sddl = (Get-Acl $data).Sddl
Check ($sddl -match "^O:BA" -and $sddl -notmatch ";;;(BU|AU|WD|IU)\)") "data dir ACL: $sddl"
Check ((sc.exe qfailure $svcName | Out-String) -match "RESTART") "recovery = restart"
Check ((sc.exe qfailureflag $svcName | Out-String) -match "TRUE") "recovery on non-crash failures"
$sd = sc.exe sdshow $svcName | Out-String
foreach ($m in [regex]::Matches($sd, "\(A;;([A-Z]*);;;(IU|AU|BU|SU|WD)\)")) {
    Check ($m.Groups[1].Value -notmatch "WP") "users cannot stop service ($($m.Value))"
}
Check (Test-Path $evtKey) "event source registered"
Check (-not (Select-String -Path install.log -Pattern $Token -SimpleMatch -Quiet)) "token not in MSI log"

# 升級：用新版通用範本，資料與設定沿用
Set-Content "$data\keep.txt" "x"
Check ((Msiexec "/i `"$UpgradeMsi`" /qn /l*v upgrade.log") -eq 0) "upgrade"
Check (Test-Path "$data\keep.txt") "upgrade keeps data dir"
Check ((Get-Content "$data\config.json" -Raw | ConvertFrom-Json).enroll_token -eq $Token) "upgrade keeps token"
Check ((Get-Service $svcName).Status -eq "Running") "service running after upgrade"

# 解除安裝：全部移除
Check ((Msiexec "/x `"$UpgradeMsi`" /qn /l*v uninstall.log") -eq 0) "uninstall"
Check (-not (Get-Service $svcName -ErrorAction SilentlyContinue)) "service removed"
Check (-not (Test-Path $data)) "data dir removed"
Check (-not (Test-Path $evtKey)) "event source removed"
Write-Host "all MSI checks passed"
