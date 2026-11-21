# 容器與虛擬機盤點 設計

日期：2026-11-22。狀態：等使用者審閱。

標「（設計者決定）」的項目是我做的決定，使用者沒有特別表示意見，審閱時可以推翻。

## 1. 目的

現在 Agent 裝在跑容器的 Linux 主機上，後台看得到主機，看不到主機上跑了哪些容器。這份規格補上：

1. **主機上的容器清單**：Linux Agent 回報主機上的容器（Docker、Podman、containerd、LXC／Incus）。
2. **Agent 自己在哪裡執行**：Agent 偵測自己是否在容器或 WSL 裡，後台標示出來，避免把短命的容器誤當成一般主機管理。
3. **找出跑某個映像的主機**、**容器相關的合規規則**。
4. **主機上的虛擬機清單**（Hyper-V、KVM／libvirt、Proxmox），並把虛擬機對到後台裡已註冊的裝置（§5.5）。

### 1.1 範圍

**做：**
- Linux Agent 新區段 `containers`：容器執行環境與容器清單。
- `basic` 區段新增「執行環境」欄位：實體或虛擬機、容器、WSL。
- 後台：裝置頁「容器」分頁、全域的「容器映像」頁、時間軸記錄容器增減。
- 合規規則三種：禁止映像、容器權限、映像未固定版本。

**不做：**
- 從後台啟動、停止、刪除容器。需要時可以用遠端指令跑 `docker` 指令。
- 映像弱點掃描（交給 Trivy 這類工具在 CI 或映像倉庫做）。
- Kubernetes 叢集層級的檢視（Deployment、Namespace 等）。只看得到每個節點上實際跑的容器。
- Windows 上的容器（Docker Desktop、Windows 容器）。理由見 §6。
- 容器內的程序、環境變數、啟動參數。這些常含密碼或金鑰，**一律不收集**。
- 從後台開關虛擬機、建立快照。
- VMware ESXi 與 vCenter：ESXi 不能裝 Agent，要串 vCenter API，另開規格。

### 1.2 成功標準

- 在一台跑 Docker 的主機上，裝置頁看得到每個容器的名稱、映像、狀態、啟動時間。
- 輸入 `nginx*`，可以列出所有跑 nginx 映像的主機。
- 在容器或 WSL 裡安裝的 Agent，裝置頁和清單都會標示「容器」或「WSL」。
- 舊版伺服器搭配新版 Agent、新版伺服器搭配舊版 Agent，都能照常報到。

## 2. 支援的容器執行環境

Agent 以 root 執行，依序偵測下列指令；**有幾種就收幾種**，同一台主機可以同時有 Docker 和 Podman。

| 執行環境 | 偵測與讀取方式 | 備註 |
|---|---|---|
| Docker | `docker ps -a -q --no-trunc` 取 ID，再一次 `docker inspect <ID…>` | |
| Podman | 同 Docker（`podman`），另外列出每個使用者的 rootless 容器（見下） | |
| containerd（Kubernetes 節點） | `crictl ps -a -o json`、`crictl inspect` | 只有 `k8s.io` 命名空間；附上 Pod 與 Namespace |
| containerd（非 Kubernetes） | `nerdctl ps -a --format json`，逐一命名空間 | 沒裝 nerdctl 就看不到（見 §2.2） |
| LXC／LXD／Incus | `incus list --format json`，沒有時用 `lxc list --format json` | 系統容器；它們裡面也可以另外裝 Agent |

- 用 CLI 而不是直接連 socket（設計者決定）：跟現在讀套件清單的方式一樣（`run_capture`，60 秒逾時），不用在 Agent 裡實作 HTTP over Unix socket，各執行環境的輸出格式也比 API 穩定。
- 指令不存在就跳過這個執行環境。指令存在但執行失敗（例如 daemon 沒啟動），就把錯誤記在該執行環境的 `error`，不讓整個區段失敗。
- 一個執行環境都沒有：區段照常回報空清單，裝置頁不顯示「容器」分頁。這是大多數主機的情況，不算錯誤。

### 2.1 Podman 的 rootless 容器

Podman 的一般使用者容器各自存放在使用者家目錄，root 執行 `podman ps` 看不到。Agent 對 `/etc/passwd` 中 UID ≥ `UID_MIN`、而且有 `~/.local/share/containers` 的使用者，以該使用者身分（`runuser -u <使用者> -- podman ps …`）各讀一次，每個容器附上 `owner`。最多讀 50 個使用者（設計者決定）。

### 2.2 偵測不到的情況

README 要寫清楚：
- containerd 沒有裝 `crictl` 或 `nerdctl` 的主機看不到容器（containerd 本身沒有好用的 CLI）。
- 以其他使用者身分執行的 rootless Docker 看不到。
- 自己編譯的執行環境、`systemd-nspawn`、Firecracker 等不支援。
- 虛擬機（KVM、Hyper-V、VMware）不是容器，不在這份規格裡；要管理就在虛擬機裡裝 Agent。

## 3. Agent 執行環境（`basic` 新欄位）

`BasicInfo` 新增：

```
runs_in: Option<RunsIn>   // 舊版 Agent 不送，伺服器當作 None（未知）
RunsIn { kind: "host" | "container" | "wsl", detail: Option<String> }
```

Linux 偵測順序（第一個成立的為準）：
1. `/proc/sys/kernel/osrelease` 含 `microsoft` 或 `WSL` → `wsl`。`detail` 放 WSL 版本：有 `WSL2` 就是 2，否則是 1。
2. `systemd-detect-virt --container` 輸出不是 `none` → `container`，`detail` 是輸出（`docker`、`podman`、`lxc`…）。
3. 沒有 systemd 時：有 `/.dockerenv` → `container`／`docker`；有 `/run/.containerenv` → `container`／`podman`；`/proc/1/environ` 有 `container=` → `container`／該值。
4. 都不是 → `host`。`detail` 放 `systemd-detect-virt --vm` 的結果（`kvm`、`vmware`、`microsoft`…；`none` 表示實體機），沒有這個指令就讀 `/sys/class/dmi/id/sys_vendor` 判斷。

Windows Agent 回報 `host`，`detail` 依 WMI 的製造商與型號判斷是否為虛擬機（`Microsoft Corporation`＋`Virtual Machine`、`VMware*`、`QEMU`、`Xen` 等）。

後台在裝置頁顯示「實體機」或「虛擬機（KVM）」這類文字。

後台顯示：
- 裝置清單與裝置頁標題旁加標籤「容器」或「WSL」；裝置清單的篩選加上「執行環境」。
- 在容器裡的裝置，裝置頁加一則提示：容器重建後 Agent 會重新註冊成新裝置，除非 Agent 的狀態目錄是持久卷；建議改在主機上安裝。

### 3.1 WSL 裡的 Agent

WSL 2 新版可以啟用 systemd，Agent 照常以服務執行；沒有 systemd 時安裝不會失敗，但要使用者自己啟動 Agent（現在的行為不變）。WSL 的 IP 與主機不同，主機名稱通常跟 Windows 相同，所以：
- 後台以「WSL」標籤區分，**不列入「疑似重複」**：主機名稱相同、一台 `wsl`、一台 Windows 的組合是正常的。
- 不處理「把 WSL 綁到所在的 Windows 主機」（設計者決定：兩邊沒有可靠的共同識別碼，第一版只標示）。

## 4. `containers` 區段

```
ContainersInfo {
  runtimes: Vec<RuntimeInfo>,
  containers: Vec<ContainerItem>,
  truncated: bool,           // 超過上限被截斷
}
RuntimeInfo { kind, version: Option<String>, error: Option<String> }
  kind: "docker" | "podman" | "containerd" | "lxc" | "incus"
ContainerItem {
  runtime: String,           // 同 RuntimeInfo.kind
  id: String,                // 前 12 碼
  name: String,
  image: String,             // 原樣，例如 "nginx:1.27" 或 "registry.example.com/app@sha256:…"
  image_digest: Option<String>,
  state: String,             // running | paused | restarting | exited | created | stopped
  health: Option<String>,    // healthy | unhealthy | starting
  created_at: Option<OffsetDateTime>,
  started_at: Option<OffsetDateTime>,
  restart_policy: Option<String>,
  privileged: Option<bool>,  // 讀不到（例如 CRI 沒有）就 None
  host_network: Option<bool>,
  ports: Vec<String>,        // "0.0.0.0:8080->80/tcp"
  host_mounts: Vec<String>,  // bind mount 的主機路徑，最多 20 個
  owner: Option<String>,     // rootless Podman 的使用者
  k8s: Option<K8sRef>,       // { namespace, pod }
}
```

- **不收集**：環境變數、指令與參數、標籤（Kubernetes 的 Pod 與 Namespace 例外）、容器內的檔案。
- **不放會一直變的欄位**：Docker 的 `Status`（「Up 3 hours」）每分鐘都變，會讓區段雜湊一直改、每次報到都上傳。只放 `state` 與時間戳。
- **數量**：
  - running、paused、restarting 全收。
  - exited、created、stopped 只收 7 天內結束的（設計者決定：CI 主機上停止的容器可能有上千個）。
  - 總數最多 500 個，執行中的優先；超過就設 `truncated`，後台顯示「只列出前 500 個」。
- **頻率**：使用 `services_secs` 的間隔（設計者決定：不新增設定；容器的變化頻率跟服務差不多）。
- 時間欄位用 `protocol::timefmt`，跟其他區段一樣。

### 4.1 相容性

- 舊版伺服器不認得 `containers` 區段，收到會讓整個報到失敗。現在的 `server_supports_config` 只能表示「支援 security／registry」，不能用來判斷 `containers`。
- 新增 `CheckinResponse.supported_sections: Vec<String>`，由伺服器列出它認得的區段名稱。用字串而不是 `Section`，舊版 Agent 才不會因為看不懂的值解析失敗。
- Agent 只在 `supported_sections` 含 `containers` 時收集與回報這個區段。沒有這個欄位（舊版伺服器）就不送；換到舊版伺服器時清掉快取，做法比照現在的 `drop_config_sections`。
- 舊版 Agent 不回報 `containers`，伺服器也只會要求 Agent 回報過的區段（`sections_to_request`），所以不會影響舊版 Agent。
- `BasicInfo.runs_in` 是選填欄位：舊版伺服器會忽略，新版伺服器收到舊版 Agent 的資料時當作 None。

## 5. 伺服器與後台

### 5.1 儲存

- 新資料表 `device_containers (device_id, data jsonb, updated_at)`，寫法比照 `device_accounts`：雜湊相同就不寫。
- `devices.runs_in`（text，可為 null），由 `basic` 區段寫入。
- 差異寫進 `inventory_changes`，只記：
  - 新增或移除的容器（以「執行環境＋名稱」為鍵）。
  - 同名容器的映像改變（例如 `app:1.4` → `app:1.5`）。
- 狀態變化（running ↔ exited）不記（設計者決定：排程工作會一直起停，時間軸會被洗版）。

### 5.2 裝置頁「容器」分頁

- 只在 Linux 裝置、而且有偵測到執行環境時顯示。
- 上方列出執行環境與版本；有錯誤時顯示錯誤訊息。
- 容器表格欄位：名稱、映像、狀態、健康、啟動時間、連接埠。
- 特權容器、使用主機網路、掛載 `/var/run/docker.sock` 或 `/` 的容器，加上警示標籤。
- 有 Pod 的容器顯示「Namespace／Pod」。
- 依狀態分組，執行中的在前；已停止的預設收合（用 `details`，不需要 JS）。

### 5.3 「容器映像」頁 `/containers`

- 放在側邊欄「資產」底下，排在「軟體」之後。
- 以映像倉庫與名稱分組（不含版本標籤），欄位：映像、版本標籤（最多列 5 個，其餘顯示「另 N 個」）、主機數、執行中容器數。
- 篩選：映像名稱（萬用字元，與軟體頁相同）、執行環境、群組、只看執行中。
- 點映像進入明細：列出跑這個映像的主機與容器，可依主機名稱、版本標籤、啟動時間排序（沿用 `web/sort.rs`）。
- 群組管理員只看得到範圍內的主機。

### 5.4 合規規則

三種新的規則類型，只評估 Linux 裝置：

| 類型 | 參數 | 違規條件 |
|---|---|---|
| 禁止映像 `forbidden_image` | 映像（萬用字元）、只看執行中（預設是） | 有容器的映像符合 |
| 容器權限 `container_privilege` | 檢查特權／主機網路／掛載 docker.sock（各自勾選）、例外映像（萬用字元，可多個） | 有執行中容器符合勾選條件，且映像不在例外 |
| 映像未固定版本 `unpinned_image` | 例外映像 | 有執行中容器的映像沒有版本標籤、標籤是 `latest`，而且沒有 digest |

- 沒有回報 `containers` 區段（舊版 Agent，或伺服器剛升級）的裝置：**不適用**，不算違規也不算未知（設計者決定：大多數主機沒有容器，標成未知會淹沒合規頁）。
- 執行環境收集失敗：未知，並附上錯誤訊息。
- `privileged` 是 None（CRI 讀不到）的容器不計入權限檢查，違規明細註明「N 個容器無法判斷」。
- 違規明細列出符合的容器（最多 20 個），格式與「禁止軟體」相同。

### 5.5 虛擬機

虛擬機本身是完整的作業系統，**在裡面裝 Agent 就跟一般電腦一樣管理**，現在就可以這樣用。這一節補上的是從虛擬化主機那一側看：主機上有哪些虛擬機、哪些還沒裝 Agent。

**收集**：新區段 `vms`，相容性做法同 §4.1。

| 平台 | Agent | 讀取方式 |
|---|---|---|
| Hyper-V | Windows | WMI `root\virtualization\v2`：`Msvm_ComputerSystem` 與 `Msvm_VirtualSystemSettingData` |
| KVM／libvirt | Linux | `virsh list --all --uuid --name`，`virsh dominfo`、`virsh dumpxml` |
| Proxmox VE | Linux | `qm list`、`qm config`；LXC 用 `pct list` |

```
VmsInfo { platforms: Vec<RuntimeInfo>, vms: Vec<VmItem> }
VmItem {
  platform, id, name,
  state,                     // running | stopped | paused | saved | other
  bios_uuid: Option<String>, // 客體看到的 SMBIOS UUID（Hyper-V 是 BIOSGUID）
  vcpus: Option<u32>, memory_mb: Option<u64>,
  os_hint: Option<String>,   // 平台記錄的客體作業系統類型，沒有就 None
}
```

不收集磁碟檔路徑以外的設定，也不收集主控台密碼與 cloud-init 資料。數量上限 500。

**對到已註冊的裝置**：
- Agent 註冊時已經回報 `smbios_uuid`。虛擬機的 BIOS UUID 與客體裡讀到的 SMBIOS UUID 相同，就能配對。
- 有些平台客體端讀到的前三段位元組順序會反過來，所以兩種寫法都要比對。
- 後台顯示：
  - 主機的「虛擬機」分頁：每台虛擬機旁顯示對到的裝置連結，對不到的標示「未安裝 Agent」。
  - 虛擬機裝置的裝置頁：顯示「執行於 <主機>」。
- 總覽的「需要處理」加一項：執行中、但沒有對到任何裝置的虛擬機數量（設計者決定：這正是「漏裝 Agent」的清單）。

**限制**（README 要寫）：叢集環境中虛擬機會在主機間搬移，後台顯示最後回報的主機。

## 6. 為什麼不做 Windows 上的容器與 WSL 清單

- Docker Desktop 在 WSL 2 的虛擬機裡執行，Docker 的 named pipe 只開放給 `docker-users` 群組，Agent 以 SYSTEM 身分執行，連不上。
- WSL 的發行版是**每個使用者各自**安裝的，清單存在使用者的登錄檔（`HKU\<SID>\Software\Microsoft\Windows\CurrentVersion\Lxss`）。使用者沒有登入時，登錄檔沒有載入，Agent 讀不到，結果會時有時無。
- 如果需要「這台 Windows 有沒有裝 WSL、裝了哪些發行版」，另外開一份規格：讀已載入的使用者登錄檔，並註明「只在使用者登入時看得到」。這份規格不包含。
- 要管理 WSL 裡的 Linux，就在 WSL 裡裝 Linux Agent（§3.1）。

## 7. 測試

- **Agent 解析**：每種執行環境的 JSON 輸出各一組範例，放在 `linux_parse` 的測試資料，涵蓋：
  - 截斷與 7 天規則。
  - 不收集環境變數（範例裡放一個密碼，確認輸出裡沒有）。
  - 時間格式、`privileged` 讀不到的情況。
- **執行環境偵測**：`osrelease`、`.dockerenv`、`.containerenv`、`/proc/1/environ` 用暫存目錄模擬（函式接受根目錄參數）。
- **相容性**：
  - 沒有 `supported_sections` 時不收集 `containers`。
  - 換到舊版伺服器時清掉快取。
  - 伺服器收到沒有 `runs_in` 的 `basic` 仍正常。
- **伺服器**：
  - 區段寫入與差異：新增、移除、映像改變；狀態改變不記。
  - 「容器映像」頁的分組、篩選、群組管理員範圍。
  - 三種規則的符合、違規、不適用、未知。
  - WSL 裝置不列入疑似重複。
- **CI**：`agent-linux` 工作已經有 Docker，加一個整合測試：啟動一個 `busybox` 容器，確認收集到它的名稱與映像。

## 8. 分期

1. **執行環境偵測**（§3）：改動小，可以先做，馬上解決「容器裡的 Agent 被當成一般主機」的問題。
2. **容器清單**：
   - Docker 與 Podman（§2、§4、§5.1、§5.2）。
   - 協定相容（§4.1）。
3. **containerd、LXC／Incus**、**容器映像頁**（§5.3）。
4. **合規規則**（§5.4）。
5. **虛擬機**（§5.5）：Hyper-V、libvirt、Proxmox，以及和已註冊裝置的配對。

每期各自發 PR；第 2 期要搭配新版 Agent，發佈說明要寫清楚「伺服器先升級，Agent 再升級才會開始回報容器」。
