# Agent 数据外泄监控 — Phase 0 PoC

监控 AI 编码代理（Claude Code / Grok CLI / Codex / Cursor / Aider / Cline 等）
是否在开发者不知情的情况下，把整个代码仓库上传到厂商云端。

> 形态：独立 CLI（Windows 优先）。模式：仅监控告警、不拦截。

## 检测原理（两层）

- **层 A · 内容级（Node 系代理）**：以注入 `SSLKEYLOGFILE` 环境变量的方式启动代理，
  Node/OpenSSL 会在 TLS 握手时把会话密钥写入该文件；抓包后用 `tshark` 配合密钥文件
  **解密请求体明文**，从而做蜜罐令牌 / 仓库指纹检测。**无需安装自签 CA、无需 MITM、纯被动**。
- **层 B · 元数据级（所有代理）**：用 Npcap 被动抓包，从 TLS `ClientHello` 提取
  **SNI（目标域名）** 并统计**上行字节数**。仅靠这两项即可发现「编码时突发数 MB 上传到厂商云」
  这类整仓打包外泄，不依赖解密。

## Phase 0 实测结论（2026-07-13）

- ✅ **假设 1（抓包 + SNI）部分验证通过**：SNI 解析器单元测试 PASS（成功解析
  `api.anthropic.com`）；Npcap 已安装在 `C:\Windows\System32\Npcap`；实时抓包代码路径
  可初始化。实时捕获需**管理员权限**，沙箱无管理员故未跑通真实捕获，需在管理员终端验证。
- ❌ **假设 2（Node 尊重 SSLKEYLOGFILE）被证伪**：裸 Node 的 TLS 1.3 握手成功，但仅设置
  `SSLKEYLOGFILE` 环境变量时密钥文件为空（不自动写）；手动把 `keylog` 事件接到文件可导出
  938 字节密钥，证明机制存在但**环境变量不会自动触发**。
  → 推论：**闭源 Node 代理（Claude Code / Grok / Codex 等）不能靠设 `SSLKEYLOGFILE` 做内容解密**，
  除非该代理自身显式接线。需逐代理单独验证。
- **架构调整**：
  - 元数据监控（SNI 域名 + 上行体积）作为**常驻核心**，无需 CA、无需注入环境变量，对闭源代理同样有效；
    对「整仓打包上传到厂商云」这类高危场景（大体积 + 厂商域名）可可靠捕获。
  - 内容级检测（蜜罐令牌 / 仓库指纹）降级为**可选"深度模式"**：用 MITM 代理
    （注入 `NODE_EXTRA_CA_CERTS` + `HTTPS_PROXY`，需安装自签 CA）解密请求体；或逐代理验证其
    是否支持 `SSLKEYLOGFILE`。

## 目录结构

```
agent-egress-monitor/
  cli/main.py    # CLI：selftest / monitor / dashboard / tray / mitm / canary
  core/
    sni.py       # TLS ClientHello SNI 解析（纯 Python）
    event.py     # 事件模型
    keylog.py    # SSLKEYLOGFILE 启动器
    canary.py    # 蜜罐令牌生成/加载 + 仓库指纹扫描
    capture.py   # scapy + Npcap 被动抓包（SNI + 上行字节 + 源端口 + Ether 重解析）
    procattr.py  # 进程归因：本地端口 -> PID -> 进程名（psutil 纯 Python）
    dashboard.py # 本地 Web 面板 HTTP 服务 + 原生告警通知
    tray.py      # 系统托盘常驻（任务栏图标 + 右键菜单）
    logger.py    # CSV/JSON 文件日志
    mitm.py      # MITM 深度检测（mitmproxy + 蜜罐/指纹扫描）
    notify.py    # Windows MessageBox 弹窗 + SMTP 邮件告警
    decrypt.py   # tshark 解密封装
    rules.py     # 规则引擎（蜜罐/指纹/体积/域名 + 已知 AI 域名）
  ui/dashboard.html  # Web 面板前端（含浏览器 Notification 桌面通知）
  config/
    mitm_ca.pem       # MITM 自签 CA 证书（首次运行自动生成）
    agents.json       # 已知代理清单
```

## 运行环境准备

1. Python 3.13（已用隔离 venv，scapy 已装）。
2. **Npcap**：已在 `C:\Windows\System32\Npcap`，无需重装。抓包需**管理员权限**运行。
3. **tshark（可选，用于内容解密）**：安装 Wireshark 并勾选把 `tshark` 加入 PATH。
   未安装时，层 B（元数据）仍可工作，仅层 A 内容解密不可用。

## 使用

```bash
# 1) 跑 Phase 0 自测（验证 SNI 解析 / SSLKEYLOGFILE / 实时抓包）
python cli/main.py selftest

# 2) 启动 Web 面板（推荐！浏览器实时查看外联画像）
python cli/main.py dashboard --iface WLAN
#   → 浏览器打开 http://127.0.0.1:9876

# 3) CLI 实时监控（需管理员）。每条流量都会标注进程名
python cli/main.py monitor --iface WLAN

# 4) 只看某个进程（如 WorkBuddy / CodeBuddy 的子进程）
python cli/main.py monitor --iface WLAN --only-proc workbuddy

# 5) 只列出已知 AI/云/代理域名（过滤掉普通网站噪声）
python cli/main.py monitor --iface WLAN --known-only

# 6) 预览输出格式（无需管理员）
python cli/main.py monitor --demo

# 7) 落盘日志（CSV + JSON，事后回看）
python cli/main.py monitor --iface WLAN --to-file egress_log
python cli/main.py dashboard --iface WLAN --to-file egress_log

# 8) 以密钥日志方式启动某个代理，结束后用 tshark 解密抓到的 pcap
python cli/main.py launch --cmd "claude"

# 9) 在仓库内生成蜜罐诱饵
python cli/main.py canary gen --repo .
```

### 一键启动 bat（Windows）

`run_monitor.bat` 会自动切到项目目录、调用隔离 venv 的 Python：
- `run_monitor.bat selftest` → 免提权自检
- `run_monitor.bat monitor` → 自动请求 UAC 提权后 CLI 持续抓包（可追加参数，如
  `run_monitor.bat monitor --iface WLAN --only-proc workbuddy`）
- `run_monitor.bat dashboard` → 自动请求 UAC 提权后启动 Web 面板，**自动打开浏览器**，
  出现超阈值上传时**浏览器弹桌面通知 + Windows 弹窗**（`--no-browser` 可抑制自动打开）
- `run_monitor.bat tray` → 系统托盘常驻（任务栏图标，右键菜单：打开面板/状态/退出）
  图标颜色：🟢正常 / 🟡有Agent流量 / 🔴告警
- `run_monitor.bat mitm --cmd "claude"` → MITM 深度模式（拦截 HTTPS，扫描蜜罐+指纹）
  需先安装 CA 证书：`certmgr.msc` → 导入 `config/mitm_ca.pem`
- `run_monitor.bat monitor --demo` → 免提权预览输出格式

### 开机自启 / 无窗口后台常驻

1. **`start_daemon.vbs`** — 用 `pythonw.exe` 后台启动**系统托盘模式**，完全无窗口：
   ```
   start_daemon.vbs
   ```
2. **开机自启**：在文件资源管理器地址栏输入 `shell:startup`，把 `start_daemon.vbs`
   的快捷方式放进去，下次开机自动启动监控。

### 面板功能速览

启动 `dashboard` 后浏览器显示：
- **统计卡片**：域名数 / 总上行 / AI后端数 / 告警数
- **域名排行表**：按上行体积排序，AI 后端域名黄色高亮 `[AGENT]`
- **实时事件流**：时间/进程/域名/上行体积/标记，每 2s 刷新
- **桌面通知**：出现超阈值上传时浏览器弹 Windows 通知

## 监控 WorkBuddy 的推荐流程

目标：把抓到的出向流量**归因到 WorkBuddy 进程**，看清它往哪些域名传了多少数据。

1. **先看全貌（无过滤）**：用管理员身份跑 `monitor`。每条 TLS 握手会打印
   `[时间戳] NEW <进程名> -> <域名> [AGENT] uplink=<体积> dst=<IP:端口>`。
   观察哪几个进程名对应 WorkBuddy（常见为 `WorkBuddy.exe` / `CodeBuddy.exe` 或
   其 Electron helper / `node.exe` 子进程）。
2. **确认进程名后过滤**：例如确认是 `CodeBuddy.exe`，就跑
   `monitor --only-proc codebuddy`，只留它的流量。
3. **结合 `[AGENT]` 高亮 + `[WARN] 超阈值`**：WorkBuddy 的后端域名
   （如 `apihub.agnes-ai.com` / `platform.agnes-ai.com`）会被标 `[AGENT]`；
   若某连接突发数 MB 上行，会触发 `[WARN]`，这正是「整仓上传」式外泄的关键信号。
4. **注意**：本工具是**纯元数据监控**，只能看到「域名 + 上行体积 + 进程」，**看不到请求体明文**。
   若要内容级检测（蜜罐/指纹），需启用可选 MITM 深度模式（见上面架构调整）。

> 进程归因依赖 `Get-NetTCPConnection`，在 Windows 管理员下可用；非 Windows 或权限不足时
> 进程列显示 `(unknown)`，但 SNI/体积仍正常。

## Phase 0 验证目标（证伪两个关键假设）

- [ ] **假设 1**：Windows + Npcap 能抓到代理出站 TLS，并解析出 SNI / 上行字节。
      → 由 `selftest` 的实时抓包项与 `monitor` 验证。
- [ ] **假设 2**：给 Node 系代理注入 `SSLKEYLOGFILE` 后，`tshark` 能解密出请求体明文。
      → 由 `selftest` 的 SSLKEYLOGFILE 项（Node 是否写密钥）+ 抓包 pcap 经 `decrypt_pcap` 验证。

## 已知局限

- 抓包需管理员权限。
- TLS 1.3 + ECH（加密 ClientHello）会隐藏 SNI；目前 Anthropic / xAI 的 API 域名不用 ECH。
- Python 系代理（Aider）默认不写 `SSLKEYLOGFILE`，仅能靠层 B 元数据检测。
- 当前为 PoC：规则为静态阈值，Phase 3 再做白名单自学习。
