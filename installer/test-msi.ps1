# MSI 安裝／升級／解除安裝測試。需要系統管理員權限（CI 的 windows runner）。
# $Msi：以 agent-msi 產生、已包好設定的安裝檔（https://localhost:9、$Token）；
# $Msi2：同版本、另一次下載的安裝檔（https://localhost:10、$Token2）；
# $UpgradeMsi：較新版本的通用範本（不帶任何屬性）。
param(
    [Parameter(Mandatory)][string]$Msi,
    [Parameter(Mandatory)][string]$Msi2,
    [Parameter(Mandatory)][string]$UpgradeMsi,
    [Parameter(Mandatory)][string]$Token,
    [Parameter(Mandatory)][string]$Token2,
    [Parameter(Mandatory)][string]$RootPem
)
$ErrorActionPreference = "Stop"
# msiexec 只接受絕對路徑（相對路徑含 / 會回 1324）
$Msi = (Resolve-Path $Msi).Path
$Msi2 = (Resolve-Path $Msi2).Path
$UpgradeMsi = (Resolve-Path $UpgradeMsi).Path
$svcName = "EndpointManagerAgent"
$data = "C:\ProgramData\EndpointManager"
$evtKey = "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application\$svcName"
$badRoot = "ROOT_CA=bm90YWNlcnQ="

function Check($cond, $msg) {
    if (-not $cond) { throw "FAIL: $msg" }
    Write-Host "ok: $msg"
}
function Msiexec($argList) {
    $p = Start-Process msiexec.exe -ArgumentList $argList -Wait -PassThru
    return $p.ExitCode
}
function B64($pem) { ((Get-Content $pem) | Where-Object { $_ -notmatch "^-----" }) -join "" }
function Config() { Get-Content "$data\config.json" -Raw | ConvertFrom-Json }
function Installed() {
    @(Get-ChildItem HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall |
        Where-Object { $_.GetValue("DisplayName") -eq "Endpoint Manager Agent" }).Count
}

# 全新安裝失敗（根憑證不正確，Configure 失敗）：回復時刪除這次建立的資料目錄
Check ((Msiexec "/i `"$Msi`" /qn /l*v failed.log $badRoot") -eq 1603) "bad ROOT_CA fails install"
Check (-not (Test-Path $data)) "rollback removes data dir created by the failed install"
Check (-not (Get-Service $svcName -ErrorAction SilentlyContinue)) "rollback removes service"

# 安裝：不帶任何命令列參數，設定全部來自 MSI 內
Check ((Msiexec "/i `"$Msi`" /qn /l*v install.log") -eq 0) "install"
Check ((Get-Service $svcName).Status -eq "Running") "service running"
Check ((Get-CimInstance Win32_Service -Filter "Name='$svcName'").StartMode -eq "Auto") "auto start"
Check ((Config).server_url -eq "https://localhost:9") "server_url from MSI"
Check ((Config).enroll_token -eq $Token) "token from MSI"
Check ((B64 "$data\root.pem") -eq (B64 $RootPem)) "root.pem from MSI"
$sddl = (Get-Acl $data).Sddl
Check ($sddl -match "^O:BA" -and $sddl -match "D:P" -and $sddl -notmatch ";;;(BU|AU|WD|IU)\)") "data dir ACL: $sddl"
Check ((sc.exe qfailure $svcName | Out-String) -match "RESTART") "recovery = restart"
Check ((sc.exe qfailureflag $svcName | Out-String) -match "TRUE") "recovery on non-crash failures"
$sd = sc.exe sdshow $svcName | Out-String
foreach ($m in [regex]::Matches($sd, "\(A;;([A-Z]*);;;(IU|AU|BU|SU|WD)\)")) {
    Check ($m.Groups[1].Value -notmatch "WP") "users cannot stop service ($($m.Value))"
}
Check (Test-Path $evtKey) "event source registered"
Check (-not (Select-String -Path install.log -Pattern $Token -SimpleMatch -Quiet)) "token not in MSI log"

# 同版本、另一次下載的安裝檔：取代原本的安裝（改網址），資料目錄保留
Set-Content "$data\keep.txt" "x"
Check ((Msiexec "/i `"$Msi2`" /qn /l*v same-version.log") -eq 0) "same-version install of another download"
Check ((Config).server_url -eq "https://localhost:10") "server_url replaced"
Check ((Config).enroll_token -eq $Token2) "token replaced (not enrolled yet)"
Check (Test-Path "$data\keep.txt") "same-version upgrade keeps data dir"
Check ((Installed) -eq 1) "only one product registered"
Check ((Get-Service $svcName).Status -eq "Running") "service running after same-version upgrade"

# 升級失敗：還原舊版，既有資料目錄不可被回復動作刪除
Check ((Msiexec "/i `"$UpgradeMsi`" /qn /l*v failed-upgrade.log $badRoot") -eq 1603) "bad ROOT_CA fails upgrade"
Check (Test-Path "$data\keep.txt") "failed upgrade keeps existing data dir"
Check ((Config).server_url -eq "https://localhost:10") "failed upgrade keeps config"
Check ((Installed) -eq 1) "old product still registered"
Check ((Get-Service $svcName).Status -eq "Running") "old version restored and running"

# 升級：用新版通用範本，資料與設定沿用
Check ((Msiexec "/i `"$UpgradeMsi`" /qn /l*v upgrade.log") -eq 0) "upgrade"
Check (Test-Path "$data\keep.txt") "upgrade keeps data dir"
Check ((Config).enroll_token -eq $Token2) "upgrade keeps token"
Check ((Installed) -eq 1) "only one product registered after upgrade"
Check ((Get-Service $svcName).Status -eq "Running") "service running after upgrade"

# 解除安裝：全部移除
Check ((Msiexec "/x `"$UpgradeMsi`" /qn /l*v uninstall.log") -eq 0) "uninstall"
Check (-not (Get-Service $svcName -ErrorAction SilentlyContinue)) "service removed"
Check (-not (Test-Path $data)) "data dir removed"
Check (-not (Test-Path $evtKey)) "event source removed"
Write-Host "all MSI checks passed"
