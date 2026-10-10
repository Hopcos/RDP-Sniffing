# RdpSniffer — .NET 10 RDP 检测服务

基于 **.NET 10** 的 RDP（远程桌面）开放性与连通性检测服务。

**默认场景**：扫描 `10.0.5.1 ~ 10.0.5.255` 网段内除 `10.0.5.88` 之外的每一台主机，检测其 3389 端口的 RDP 是否开放、是否能够建立连接。

- `VerifyCredentials=false`：仅探测 RDP 端口是否开放（不需要账号密码）；
- `VerifyCredentials=true`：先做端口开放验证，再**验证账号密码能否登录** —— 默认优先使用系统远程桌面客户端组件（与 Remote Desktop Connection / mstsc.exe 同源）完整模拟登录；当系统缺少 RDP ActiveX 组件时，**自动改用纯协议方式**（CredSSP/NLA 握手，无需任何远程桌面组件）完成凭据验证，两种客户端均通过 `LoginVerificationMethod` 配置（`Auto` / `Mstsc` / `Protocol`）。

所有配置均集中在 `appsettings.json` 中，无需改代码即可调整扫描范围、排除地址、端口、验证模式、并发、超时与报告。

---

## 目录

1. [功能特性](#功能特性)
2. [架构设计](#架构设计)
3. [目录结构](#目录结构)
4. [环境要求](#环境要求)
5. [快速开始](#快速开始)
6. [配置说明](#配置说明)
7. [验证模式详解](#验证模式详解)
8. [扫描行为说明](#扫描行为说明)
9. [输出与报告](#输出与报告)
10. [单元测试](#单元测试)
11. [扩展指南](#扩展指南)
12. [常见问题（FAQ）](#常见问题faq)
13. [安全与合规](#安全与合规)

---

## 功能特性

- **全配置驱动**：扫描网段、排除地址、端口、凭据、超时、并发、调度、报告，全部来自 `appsettings.json`（支持环境变量覆盖）。
- **两种验证模式**（`VerifyCredentials` 开关）：
  - `false`：跨平台端口探测 —— TCP 建连 + 可选 RDP X.224 握手确认，判定 RDP 是否“开放”；
  - `true`：**两阶段验证** —— 先做与 `false` 相同的端口开放验证并输出（可用地址不丢失），再对确认开放的地址做登录验证，明确区分「登录成功 / 凭据被拒 / 连不上 / 超时」。登录验证的客户端由 `LoginVerificationMethod` 选择：**MSTSC ActiveX**（与 `mstsc.exe` 同一客户端栈）或**纯协议 CredSSP/NLA**（TCP→X.224→TLS→NTLM 握手，NLA 认证通过即证明凭据有效，与 nmap/crackmapexec 同原理）；`Auto`（默认）在 ActiveX 缺失时自动切换为协议方式，不再出现“组件未找到”的僵局。
- **友好排除规则**：默认排除扫描机自身 `10.0.5.88`；支持排除任意多个地址。
- **地址枚举策略**：默认覆盖 `x.x.x.1 ~ x.x.x.255`（网络地址 .0 默认跳过、广播地址 .255 默认保留，均可配置）；支持 `/30`、`/31`、`/32` 等特殊前缀。
- **规模保护**：`MaxScanAddresses` 防止误配超大网段拖垮进程。
- **并发控制**：`SemaphoreSlim` 限流 + `CancellationToken` 优雅取消。
- **结构化报告**：每轮扫描输出 JSON 报告（配置快照 + 汇总 + 逐地址明细），便于审计与后续自动化。
- **服务器证书名展示**：对每个确认开放的 RDP 地址额外抓取服务端 TLS 证书名称（CN，即远程桌面客户端显示的服务器身份，如 `WIN-XXXX` 或域机器证书名），随日志与 JSON 报告输出；旧式无 TLS 服务器显示 `[Cert: n/a]`（可用 `CollectCertificateName` 关闭）。
- **可测试架构**：核心逻辑全部面向接口，内置 96 个单元测试（含回环 TCP/TLS/NTLM 端到端测试）。

---

## 架构设计

### 分层

```
┌─────────────────────────────────────────────────────────────┐
│ RdpSniffer.Service（宿主）                                    │
│   Program.cs  DI/配置装配 · RdpScanWorker 周期调度             │
│   appsettings.json 全部配置                                    │
├─────────────────────────────────────────────────────────────┤
│ RdpSniffer.Core（核心：平台无关、可完全单测）                    │
│   Options/模型 · RdpTargetCalculator 地址计算                  │
│   RdpScanRunner 并发编排 · RdpProbeFactory.SelectKind(纯函数)   │
│   MstscLoginProbe 登录编排(依赖抽象) · JsonReportWriter 报告    │
├──────────────────────────────┬──────────────────────────────┤
│ RdpSniffer.Probes.Tcp        │ RdpSniffer.Probes.CredSsp     │
│  TcpRdpConnectionFactory     │  CredSspLoginClient            │
│  RdpBannerParser (X.224)     │  (X.224→TLS→TSRequest→NTLM)    │
│  TcpRdpProbe 端口探测         │  纯协议凭据验证 (无 ActiveX)    │
├──────────────────────────────┼──────────────────────────────┤
│ RdpSniffer.Probes.Mstsc      │                              │
│  ComMstscLoginClient         │                              │
│  MstscSession (STA/AxHost)   │                              │
│  完整登录验证 (Windows 专用)   │                              │
└──────────────────────────────┴──────────────────────────────┘
        全部实现接口；由宿主层组合根（RdpProbeComposition 选探测、
        MstscLoginClientComposition 选登录客户端）按配置+平台选择
```

### 关键抽象（为什么这样做）

| 抽象 | 作用 | 好处 |
|---|---|---|
| `IRdpProbe` | “一个地址探测一次”的统一契约 | 探测器可插拔：端口探测 / 登录验证 / 未来新增方式 |
| `IRdpConnectionFactory` / `IRdpConnection` | 把“如何建 TCP 连接”从探测逻辑剥离 | 探测逻辑可在单元测试中用假实现全覆盖，不依赖真实网络 |
| `RdpConnectionException` (Kind) | 区分 超时/拒绝/不可达 | 生成友好的人类可读失败原因 |
| `IMstscLoginClientFactory` / `IMstscLoginClient` | 登录细节隔离 | 登录编排（MstscLoginProbe）可单测；两种真实实现（MSTSC ActiveX 与纯协议 CredSSP/NLA）按配置注入，互不依赖 |
| `IRdpCertificateNameProvider` | 抓取开放端点的服务端 TLS 证书 CN（X.224→TLS，不做登录） | 端口探测与登录验证统一获得证书名；抓取失败返回 null，绝不影响“端口开放”结论 |
| `RdpProbeFactory.SelectKind`（纯函数，Core）<br>+ `RdpProbeComposition`（组合根，Service） | 按配置 + 平台选择探测器 | 切换验证模式零代码改动；组合根下沉宿主层，避免 Core 反向依赖探测器程序集 |
| `IReportWriter` | 报告输出抽象 | 后续可加 InfluxDB / 控制台 / 日志扩展 |
| `TimeProvider` | 时间注入 | 扫描编排可测（时间不依赖真实钟） |

### 关键设计决策

1. **登录验证为何既可以走 MSTSC 组件、也可以走纯协议？**
   完整桌面会话必须使用系统组件；但如果**只需要确认“账号密码能否登录”**，RDP 的 NLA（Network Level Authentication / CredSSP）本身就是“先认证、后连接”：
   NTLM 认证被服务端接受即证明凭据有效，无需真正建立桌面会话 —— 这正是 nmap `rdp-enum-encryption`、Metasploit `rdp_login`、crackmapexec 验证 RDP 凭据的原理。
   `RdpSniffer.Probes.CredSsp` 用纯托管代码实现这一握手（X.224 协商 → TLS → CredSSP TSRequest → SPNEGO/NTLM，NTLM 走 Windows 内置 SSPI），
   **不依赖任何远程桌面组件**，解决了“本机未安装 RDP ActiveX 组件时登录验证无法进行”的问题；代价是需要目标启用 NLA（Windows RDP 默认开启），
   且 NTLM 依赖 Windows 平台。`Auto` 模式下组件缺失会自动切换，两种实现共享同一套探测/报告流程。

2. **为何把“端口探测”和“完整登录”做成两个独立实现？**
   职责单一：探测端口开放不需要凭据也不依赖窗口/COM 环境；登录验证是更重、平台相关的操作。
   两者通过 `IRdpProbe` 统一，扫描编排器对探测方式完全无感知。

3. **无界面登录验证的线程模型**
   远程桌面 ActiveX 是 COM/UI 组件，必须在 **STA 线程 + 消息泵** 中工作。
   `ComMstscLoginClient` 为每次登录启动独立 STA 线程，承载隐藏窗口（`AxHost`+隐藏 Form），
   用 `Application.DoEvents()` 驱动消息泵，并同时具备两条结果判定通道：
   事件通道（尽力绑定 `OnLoginComplete / OnLogonError / OnDisconnected / OnConnected` 事件）与轮询通道（轮询 `Connected` 属性兜底）。

---

## 目录结构

```
rdp_sniffing/
├── RdpSniffer.slnx                 # 解决方案（.NET 10 SDK 默认的 slnx 格式）
├── global.json                     # 固定 .NET 10 SDK
├── Directory.Build.props
├── README.md
├── src/
│   ├── RdpSniffer.Core/            # 核心库（平台无关）
│   │   ├── Abstractions/           # IRdpProbe / IRdpConnection / IMstscLoginClient / IReportWriter
│   │   ├── Detection/              # 地址计算器 / 扫描编排 / 探测选择(纯函数) / 两阶段复合探测 / 登录探测编排
│   │   ├── Models/                 # 目标 / 结果 / 状态 / 报告模型
│   │   ├── Options/                # 配置模型 + 校验器
│   │   └── Reporting/              # JSON 报告写入器
│   ├── RdpSniffer.Probes.Tcp/      # 端口探测（跨平台）
│   ├── RdpSniffer.Probes.CredSsp/  # 纯协议登录验证（X.224→TLS→CredSSP/NLA，无 ActiveX 依赖）
│   ├── RdpSniffer.Probes.Mstsc/    # MSTSC 完整登录验证（Windows 专用）
│   └── RdpSniffer.Service/         # 可执行服务（Generic Host + 托管服务）
│       ├── Composition/            # 组合根：按配置+平台装配最终探测器与登录客户端
│       ├── Workers/                # 周期扫描托管服务
│       └── appsettings.json        # ★ 全部配置
└── tests/
    └── RdpSniffer.Tests/           # xUnit 单元测试（87 个用例）
```

---

## 环境要求

| 项 | 说明 |
|---|---|
| .NET SDK | **10.0.301+**（已提供 `global.json` 固定版本） |
| 操作系统 | 推荐 **Windows**（10/11/Server）：完整登录验证依赖系统远程桌面组件；服务宿主（含组合根/托管服务）以 `net10.0-windows` 为目标框架 |
| 端口探测逻辑 | 核心库 `Core` 与 `Probes.Tcp` 为 `net10.0`，可在 Linux/macOS 上单独引用构建自定义宿主；仓库内完整服务宿主按 Windows 目标框架构建 |
| 完整登录验证模式 | 两种客户端二选一：**MSTSC ActiveX**（需系统“远程桌面连接”组件，Windows）或 **纯协议 CredSSP/NLA**（无组件依赖，但需 Windows 的 SSPI，且目标服务端需启用 NLA） |
| .NET 运行时 | 10.0.x（WindowsDesktop 运行时，登录验证模式需要） |
| 网络 | 扫描机与目标网段三层可达；端口探测模式需要出站 TCP 到目标 3389 |

---

## 快速开始

```bash
# 1) 构建
dotnet restore RdpSniffer.slnx
dotnet build RdpSniffer.slnx -c Release

# 2) 直接运行（默认配置：探测 10.0.5.1~255 除 .88 的 3389 端口）
dotnet run --project src/RdpSniffer.Service -c Release

# 3) 运行单元测试
dotnet test RdpSniffer.slnx -c Release

# 4) 带覆盖率
dotnet test RdpSniffer.slnx -c Release --collect:"XPlat Code Coverage"
```

> 提示：默认 `RunContinuously=true`，服务会按 `ScanInterval` 周期扫描。
> 快速验证建议先用小网段（如 `Network: "10.0.5.80/28"`）或把端口探测直接对准单机（`"10.0.5.89/32"`）。

---

## 配置说明

完整配置位于 `src/RdpSniffer.Service/appsettings.json` 的 **`RdpDetection`** 节点：

```jsonc
{
  "RdpDetection": {
    // ---------- 扫描范围 ----------
    "Network": "10.0.5.0/24",          // 网段：CIDR 写法；也可纯 IP "10.0.5.0" 配合 PrefixLength
    "PrefixLength": 24,                // 仅当 Network 不带 "/前缀" 时生效
    "ExcludedAddresses": [ "10.0.5.88" ],  // 排除地址（如扫描机自身）
    "MaxScanAddresses": 65536,         // 单轮扫描地址数上限（防误配超大网段）
    "IncludeNetworkAddress": false,    // 是否包含网络地址（/24 的 .0）
    "IncludeBroadcastAddress": true,   // 是否包含广播地址（/24 的 .255）

    // ---------- RDP 端点 ----------
    "Port": 3389,                      // RDP 端口

    // ---------- 验证模式 ----------
    "VerifyCredentials": false,        // false=仅判断端口开放；true=完整凭据登录验证
    "LoginVerificationMethod": "Auto", // 登录验证客户端：Auto=组件可用用 MSTSC、否则协议(默认)；Mstsc=强制 ActiveX；Protocol=强制纯协议
    "Credentials": {                   // VerifyCredentials=true 时必填
      "UserName": "",                  // 账号（如 "admin" 或 "CORP\\admin"）
      "Password": "",                  // 密码
      "Domain": ""                     // 域（可选，为空则按用户名内嵌域解析）
    },
    "RequireRdpBanner": false,         // 端口探测模式下是否强制要求 RDP 握手响应才判“开放”
    "CollectCertificateName": true,    // 对开放端点抓取服务端 TLS 证书名（CN）并展示；旧式无 TLS 服务器为 n/a

    // ---------- 超时（秒）----------
    "ConnectTimeoutSeconds": 3,        // TCP 建连超时
    "HandshakeTimeoutSeconds": 3,      // RDP 握手响应等待超时（端口探测模式）
    "LoginTimeoutSeconds": 15,         // 完整登录验证总超时

    // ---------- 并发 ----------
    "MaxConcurrentProbes": 50,         // 同时执行的探测数上限

    // ---------- 运行调度 ----------
    "RunOnStart": true,                // 启动后立即扫描一次
    "RunContinuously": true,           // 是否周期持续扫描；false=扫一次退出
    "ScanInterval": "00:10:00",        // 周期（格式 hh:mm:ss，最小 5 秒）

    // ---------- MSTSC 登录验证细节 ----------
    "MstscPollingIntervalMilliseconds": 500, // 状态轮询间隔
    "MstscEnableCredSspSupport": true,       // 启用 NLA/CredSSP
    "MstscAuthenticationLevel": 2,           // 服务器认证级别：0/1/2/3

    // ---------- 报告 ----------
    "Report": {
      "Enabled": true,
      "FilePath": "rdp-scan-report.json"     // 相对进程工作目录，或绝对路径
    }
  }
}
```

### 配置覆盖（环境变量 / 命令行）

Generic Host 内置配置覆盖机制，**启动时环境变量优先于 appsettings**，适合不想把密码写进配置文件的情形：

```bash
# PowerShell / CMD
$env:RdpDetection__VerifyCredentials = "true"
$env:RdpDetection__Credentials__UserName = "CORP\scan"
$env:RdpDetection__Credentials__Password = "YourPass"
$env:RdpDetection__Credentials__Domain   = ""
$env:RdpDetection__Network               = "10.0.5.0/24"
dotnet run --project src/RdpSniffer.Service

# 命令行参数形式（等价）
dotnet run --project src/RdpSniffer.Service --RdpDetection:VerifyCredentials=true --RdpDetection:Credentials:Password=YourPass
```

### 配置校验规则（启动即校验，违规直接拒绝启动）

- `Network` 必须能解析为 IPv4 网段；`ExcludedAddresses` 必须是合法 IPv4；
- `Port` ∈ [1, 65535]；各项超时/并发均有上下限；
- `VerifyCredentials=true` 时 **必须**同时提供 `UserName` 与 `Password`；
- `ScanInterval` 必须可解析且 ≥ 5 秒。

---

## 验证模式详解

### 模式一：`VerifyCredentials=false` —— 仅判断 RDP 是否开放（默认）

对每个地址：

1. TCP 建连 `IP:3389`（超时 `ConnectTimeoutSeconds`）；
   - 连接被拒绝 / 超时 / 主机不可达 → `PortNotOpen`（并给出具体原因）；
2. （可选）当 `RequireRdpBanner=true` 时，发送 X.224 连接请求，校验服务端响应：
   - 返回 X.224 连接确认（`0x03`）或 TLS 记录（`0x16`）→ `PortOpen`（协议确认为 RDP）；
   - 超时无响应 / 数据无法识别 → `PortNotOpen`（提示“可能是非 RDP 服务”）；
3. `RequireRdpBanner=false`（默认）：TCP 连通即判定 `PortOpen`，不发送额外探测包，最安静。

不需要任何账号密码，跨平台可运行。

### 模式二：`VerifyCredentials=true` —— 两阶段：先验开放，再完整登录验证

该模式**先执行与模式一完全相同的端口开放验证并输出**（因此“RDP 可用地址”绝不丢失），再对确认开放
的端点使用系统的**远程桌面 ActiveX 客户端（MsRdpClient，`mstsc.exe` 底层同一套组件）**做完整登录验证：

1. **阶段一（必做）：RDP 开放验证** —— 与 `VerifyCredentials=false` 完全一致的 TCP 连通（+可选 X.224 握手确认）；
   - 未开放 → `PortNotOpen`，**不再尝试登录**；
   - 开放 → 进入阶段二，且该地址已计入“RDP 可用地址”；
2. **阶段二：登录验证** —— 仅对阶段一确认开放的地址，客户端按 `LoginVerificationMethod` 选择：
   - **MSTSC ActiveX**：在独立 **STA 线程 + 隐藏窗口** 中创建远程桌面会话，注入 `Server`、`UserName`、`Domain`、
     `ClearTextPassword` 与高级设置（CredSSP/NLA、认证级别等）；调用 `Connect()` 后通过「事件 + 轮询」确认登录结果；
   - **纯协议 CredSSP/NLA**（`Protocol`，或 `Auto` 下 ActiveX 缺失时自动使用）：对目标执行
     TCP 建连 → X.224 连接协商（确认服务端支持 TLS/NLA）→ TLS 握手 → CredSSP TSRequest 交换
     （SPNEGO/NTLM，NTLM 由 Windows SSPI 计算）→ 服务端接受认证（凭据正确）则成功，认证后被服务端
     立即断开（凭据错误）则判定被拒。全程不需要任何远程桌面组件与图形会话；
   - 阶段二总超时为 `LoginTimeoutSeconds`；
3. 结果映射：

| 客户端结果 | 探测状态 | 含义 |
|---|---|---|
| 登录成功（Connected / LoginComplete，或协议 NLA 认证通过） | `LoginSucceeded` | RDP 开放且凭据正确，可完整建立会话 |
| 凭据被拒绝（OnLogonError，或协议客户端认证后被服务端立刻断开） | `LoginFailed` | RDP 开放但账号/密码错误（或账户无远程登录权限） |
| 阶段二无法完成（MSTSC 组件缺失 / 目标不支持 NLA / TLS 协商失败 / 客户端异常） | `LoginFailed` | **RDP 端口已确认开放**，但登录验证无法完成（明细带原因，如 `RDP ActiveX client component (MsRdpClient*) was not found`、`does not support NLA…`） |
| 超时未完成 | `LoginFailed` | 服务端响应缓慢或静默失败 |

> 关键改进：无论阶段二成功与否，阶段一经确认开放的地址都会以 `RDP 可用地址` 输出；
> 登录阶段的失败只影响状态分类（`LoginSucceeded` / `LoginFailed`），**不会把开放地址误判为不可用**。

**平台要求与限制（务必阅读）**

- **MSTSC 客户端**：仅 Windows，且系统需具备远程桌面客户端组件（Win10/11/Server 默认自带；`MsRdpClient6/8/9*NotSafeForScripting` 任选其一）；
  进程需要可创建窗口/桌面的环境：**不要在纯 Session 0 的非交互服务中使用**，建议以交互会话或允许桌面的服务方式运行；
- **协议（CredSSP/NLA）客户端**：同样仅 Windows（NTLM 走系统 SSPI），但**不需要任何 ActiveX/图形环境**；
  要求**目标服务端启用 NLA**（Windows RDP 默认设置“仅允许运行使用网络级别身份验证的远程桌面的计算机连接”即为此项）：
  - 目标不支持 NLA（旧式加密）时，阶段二会明确报告“server does not support NLA”，无法仅凭 NLA 判定凭据；
  - 凭据错误时服务端会在 NTLM 认证后立即断开，凭据正确时服务端继续 CredSSP 交换 —— 这是该方式判断“账号密码能否登录”的依据；
  - 该握手不会建立桌面会话，因此**比 MSTSC 方式更安静**（但同样是认证尝试，仍会留下安全日志，见[安全与合规](#安全与合规)）；
- 两种方式的登录失败均按上表分类，开放地址始终保留在“RDP 可用地址”输出中；
- 确认真实行为时可用同一账号手工 `mstsc /v:目标IP` 对照。

---

## 扫描行为说明

- **地址枚举**：`Network` 计算出的 `first ~ last` 升序遍历；网络地址（.0）默认跳过、广播地址（.255）默认保留；`/31` 双地址、`/32` 单地址按语义处理；排除地址在枚举后过滤。
- **并发**：`MaxConcurrentProbes` 个并行任务（`SemaphoreSlim`），单目标失败互不影响，异常降级为 `ProbeFailed` 记录明细。
- **取消**：进程退出（Ctrl+C / 服务停止）时通过 `CancellationToken` 取消，已探测结果丢弃、不写半成品报告。
- **调度**：`RunOnStart` 立即首扫 → `RunContinuously` 周期循环；`RunContinuously=false` 单轮后正常退出。

---

## 输出与报告

### 控制台日志（每轮）

```
[信息] RDP 检测服务启动：Network=10.0.5.0/24, Excluded=[10.0.5.88], Port=3389, VerifyCredentials=False
[信息] 开始扫描 254 个地址（并发上限 50 …）
[信息] 扫描完成：总计 254，未开放 244，端口开放 10，登录成功 0，登录失败 0，探测失败 0，耗时 00:00:06
[信息] RDP 可用地址(2): 10.0.5.11 [Cert: WIN-0ABC123], 10.0.5.12 [Cert: n/a]
[信息] 扫描报告已写入: …\rdp-scan-report.json
```

### JSON 报告（`rdp-scan-report.json`）

```jsonc
{
  "generatedAtUtc": "2026-01-02T03:04:05.1234567+00:00",
  "network": "10.0.5.0/24",
  "port": 3389,
  "verifyCredentials": false,
  "requireRdpBanner": false,
  "excludedAddresses": ["10.0.5.88"],
  "summary": {
    "total": 254, "skipped": 0, "portNotOpen": 244, "portOpen": 10,
    "loginSucceeded": 0, "loginFailed": 0, "probeFailed": 0,
    "elapsed": "00:00:06.1234567"
  },
  "results": [
    {
      "target": { "ip": "10.0.5.11" },
      "state": "PortOpen",
      "rdpProtocolConfirmed": true,
      "duration": "00:00:00.0123456",
      "certificateName": "WIN-0ABC123",
      "detail": "收到 RDP 服务端握手响应（X224ConnectionConfirm）",
      "checkedAtUtc": "2026-01-02T03:04:03.9876543+00:00"
    }
  ]
}
```

> 每个开放端点的结果还附带 `certificateName` 字段（服务端 TLS 证书 CN，与远程桌面客户端显示的服务器身份一致）；
> 旧式无 TLS/NLA 的服务器该字段为 `null`（日志中显示 `[Cert: n/a]`）。

**状态枚举含义**

| state | 含义 |
|---|---|
| `PortNotOpen` | 端口未开放 / 无服务监听 / 主机不可达 |
| `PortOpen` | 端口开放（TCP 连通；`RequireRdpBanner=true` 时已确认为 RDP 协议） |
| `LoginSucceeded` | 完整登录验证成功 |
| `LoginFailed` | RDP 端口已确认开放，但登录验证未通过（凭据被拒 / 登录超时 / 登录阶段无法完成） |
| `ProbeFailed` | 探测过程内部异常 |
| `Skipped` | 保留位（未来扩展） |

---

## 单元测试

```bash
dotnet test RdpSniffer.slnx -c Release
```

测试项目 `tests/RdpSniffer.Tests`（xUnit，当前 **96 个用例**，约 10~30 秒跑完），全部不依赖真实目标网段（回环 TCP/TLS/NTLM 除外）。
由于测试需要引用 Service 组合根（装配验证），测试项目目标框架为 `net10.0-windows`，**请在本机 Windows 上运行测试**：

| 测试文件 | 覆盖点 |
|---|---|
| `RdpTargetCalculatorTests` | 地址枚举（/24、/30、/31、/32）、网络/广播地址开关、排除列表、升序去重、规模上限、纯IP+前缀 |
| `OptionsValidationTests` | 默认配置、凭据成对校验、非法网段/端口/间隔、前缀越界、多错误收集 |
| `RdpBannerParserTests` | X.224 握手载荷结构、响应分类（无响应/X.224/TLS/未知） |
| `TcpRdpProbeTests` | 假连接工厂全覆盖：拒绝/超时/不可达、PortOpen 判定、RequireBanner 各分支、发送载荷校验、证书名抓取（成功/关闭/失败不影响开放结论）、异常降级、取消传播 |
| `MstscLoginProbeTests` | 登录成功/凭据拒绝/连接失败/超时映射、请求参数透传、客户端释放、异常兜底、取消传播 |
| `RdpScanRunnerTests` | 并发上限、结果排序、统计、单点异常隔离、空目标、取消、配置快照、耗时记录 |
| `JsonReportWriterTests` | 启用/禁用、空路径、JSON 结构断言、嵌套目录自动创建 |
| `RdpProbeFactoryTests` | 配置+平台→探测器选择（SelectKind 纯函数 + 组合根 DI 装配） |
| `VerifyCredentialsProbeTests` | 两阶段复合探测：先端口开放验证、后登录验证；登录阶段失败不掩盖“端口已开放”事实；证书名从阶段一透传至最终结果；时长累计、取消传播 |
| `MstscLoginClientCompositionTests` | 登录客户端选择装配：Mstsc→ActiveX 工厂、Protocol→CredSSP 工厂 |
| `TsRequestCodecTests` | CredSSP TSRequest BER 编解码：单令牌往返、长格式长度、pubKeyAuth/errorCode 解析、非法数据 |
| `CredSspLoginClientTests` | 协议客户端平台守卫（非 Windows 直接返回 ProtocolError） |
| `CredSspLoginClientIntegrationTests` | 回环端到端：假 NLA RDP 服务器（X.224→TLS→真实 SSPI NTLM challenge）——接受后续接/认证后断开分别验证 `Succeeded` 与凭据被拒判定；旧式无 NLA 服务器返回 ProtocolError |
| `TlsCertificateNameProviderTests` | 证书名抓取回环端到端：TLS 服务端返回证书 CN、旧式无 TLS 返回 null、关闭端口返回 null |
| `TcpRdpProbeLoopbackTests` | 回环 TCP 端到端：真实 RDP 服务端应答、未监听端口、服务端静默超时 |

---

## 扩展指南

- **新增一种探测实现**：实现 `IRdpProbe`，在 `RdpProbeFactory.SelectKind` 中扩展选择逻辑，并在 `RdpProbeComposition`（组合根）中补充装配，扫描编排与报告无需改动。
- **新增报告后端**：实现 `IReportWriter`（如写数据库、推送 Webhook），替换 DI 注册。
- **调整登录验证实现**（如未来引入 FreeRDP 进程/库）：实现 `IMstscLoginClientFactory`，加入 `MstscLoginClientComposition` 的选择逻辑即可，`MstscLoginProbe` 与扫描编排无需改动（本仓库已内置 MSTSC 与纯协议 CredSSP 两种实现）。

---

## 常见问题（FAQ）

**Q1：运行时提示“Network 无法解析”？**
检查 `Network` 是否为 `10.0.5.0/24` 或合法 IPv4 + `PrefixLength`。

**Q2：启动即报配置校验错误“VerifyCredentials=true 时必须配置 Credentials.UserName”？**
完整登录模式必须提供账号密码；只测端口开放请把 `VerifyCredentials` 设为 `false`。

**Q3：`VerifyCredentials=true` 但结果全是 `PortNotOpen`？**
依次排查：目标 3389 是否真的开放（本地防火墙/远程防火墙）、扫描机到目标网络可达性、
进程是否运行在无桌面环境（Session 0）、系统是否安装远程桌面客户端组件。

**Q4：登录验证报“调用 RDP 客户端 Connect() 失败”？**
多为组件未注册或进程账户无交互桌面权限。用 `regsvr32 /s msrdp.ax` 检验组件，或在交互会话运行。

**Q5：Windows 控制台中文乱码？**
`Program.cs` 未强制设置代码页：可在运行前执行 `chcp 65001`，或在 `RdpScanWorker` 处使用英文日志；
本仓库日志与报告均为 UTF-8，报告文件无乱码问题。

**Q6：扫整个 /24 太慢 / 想先重点验证几台？**
调高 `MaxConcurrentProbes`、调低 `ConnectTimeoutSeconds`；或临时把 `Network` 改为
`"10.0.5.88/32"`（单主机）快速验证。

**Q7：扫描超大网段（/16 以上）被拒绝？**
`MaxScanAddresses`（默认 65536）会拦截；确认业务确需后调大该值（注意内存与带宽）。

**Q8：`RequireRdpBanner=true` 时，为什么有些开放的端口被判未开放？**
部分中间设备（如端口转发、只放行 TCP 的防火墙）会接受连接但无法转发 RDP 协议流量，
此时收不到 X.224 响应属正常现象；若以“端口是否可连接”为准，请使用默认 `RequireRdpBanner=false`。

**Q9：登录验证模式下 `Connected` 无法表示“失败”？**
客户端事件（`OnLogonError`/`OnDisconnected`）已尽力反射绑定；个别组件版本签名不同会回退到轮询，
此时“凭据被拒”以超时形式体现为 `LoginFailed`，可在报告中通过 `detail` 查看。

**Q10：本机没有/无法安装 RDP ActiveX 组件（日志提示 `MsRdpClient* was not found`），还能验证账号密码吗？**
能。保持默认 `LoginVerificationMethod=Auto`（组件缺失时自动切换），或显式设为 `Protocol`，登录验证将走
**纯协议 CredSSP/NLA**：TCP→X.224→TLS→NTLM 认证（NTLM 用系统 SSPI），不需要任何远程桌面组件与图形会话；
目标启用 NLA（Windows RDP 默认）时，凭据错误会在认证后被服务端立即断开，凭据正确则继续 CredSSP 交换，
据此判定 `LoginFailed`（凭据被拒）或 `LoginSucceeded`。若目标不支持 NLA，阶段二会明确报告原因，开放地址仍保留在结果中。

**Q11：协议方式会不会建立远程桌面会话 / 影响目标？**
不会建立会话，认证完成即断开，比 MSTSC 方式更安静；但 NTLM 认证尝试仍会在目标上产生登录安全日志（与登录失败审计一致），
实施前请与相关方确认（见[安全与合规](#安全与合规)）。

---

## 安全与合规

- 本工具用于**授权网络**的 RDP 暴露面检测（如内网资产巡检、基线核查）。
  请在获得授权的前提下使用，遵守所在地区与单位的网络安全法规。
- `Credentials.Password` 会以明文写进 `appsettings.json`；生产环境请改用
  **环境变量 / 用户机密 / 凭据注入**（见[配置覆盖](#配置覆盖环境变量--命令行)），
  并注意报告文件中不含密码。
- 完整登录验证会在目标上留下安全事件日志（登录尝试），属正常行为，实施前请与相关方确认。
- 建议将扫描时间放在业务低谷，并控制并发与超时，避免对目标造成压力。
