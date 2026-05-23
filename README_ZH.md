<p align="center">
<img width="250px" src="https://user-images.githubusercontent.com/18649508/139117888-4f631b07-0b40-4d24-b478-fb805ceef689.png" />
</p>
<hr/>

# cproxy

[![Crates.io](https://img.shields.io/crates/v/cproxy)](https://crates.io/crates/cproxy) [![CI](https://github.com/NOBLES5E/cproxy/actions/workflows/build.yml/badge.svg)](https://github.com/NOBLES5E/cproxy/actions/workflows/build.yml) ![Crates.io](https://img.shields.io/crates/d/cproxy) ![Crates.io](https://img.shields.io/crates/l/cproxy)

你是否曾希望在某些程序自己不知情的情况下，让它们强制走代理？那么，向你介绍 `cproxy`。

## 核心特性

- **透明重定向**：支持对 TCP 和 UDP 流量的透明重定向。
- **进程级隔离**：支持针对特定应用/进程配置不同的代理服务。
- **卓越的兼容性**：兼容所有程序，包括静态链接的 Go 二进制文件。
- **DNS 重定向**：支持 DNS 请求的拦截与劫持。
- **极简的使用体验**：使用方式极其简单，体验类似于 `proxychains`。
- **代理现有进程**：不仅能启动新进程走代理，还能直接代理已经运行的进程。
- **丰富的网络模式**：同时支持 iptables `REDIRECT`（重定向）和 `TPROXY`（透明代理）两种模式。
- **DNS 服务器覆写**：在 `TPROXY` 模式下，支持动态重写和指定特定的 DNS 服务器。
- **流量调试跟踪**：可使用 iptables `LOG` 靶目标，在内核级追踪并调试程序的网络活动。
- **完备的 Cgroup 支持**：兼容 Linux cgroup v1 和 v2。
- **零守护进程运行**：完全无需常驻后台的 daemon 守护进程。
- **无缝集成**：可轻松与 V2Ray、Xray、Sing-Box、Shadowsocks 等现有主流网络代理软件集成。
- **内置 TCP 桥接器 (`--upstream`)**：无需额外启动透明代理中转，即可直接将流量桥接到远程 HTTP / SOCKS5 代理。
- **多防火墙后端**：支持 `nftables`（自动检测，若不支持则自动回退到 `iptables`）。

> [!TIP]
> 默认情况下，`cproxy` 假设 `--port` 指向的是你自己启动的**透明代理入站端口**（如 V2Ray 的 `dokodemo-door` 协议入站或 shadowsocks 的 `ss-redir`）。如果你只有一个普通的非透明 HTTP CONNECT 或 SOCKS5 代理监听器（例如代理运行在你的 Windows 宿主机上，而 cproxy 运行在 WSL 中），只需传入 `--upstream`，`cproxy` 会自动在本地为你运行一个小巧的 TCP 桥接器。详见下面的 [WSL + Windows 代理](#wsl--windows-代理-内置-tcp-桥接模式) 部分。

## 安装方式

你可以直接在 [Release 页面](https://github.com/NOBLES5E/cproxy/releases) 下载编译好的二进制文件，或通过 Cargo 安装：

```bash
cargo install cproxy
```

或者，使用以下一键安装脚本下载最新版本并放入 `/usr/local/bin` 中（适合高效的开发者）：

```bash
curl -s https://api.github.com/repos/NOBLES5E/cproxy/releases/latest | grep "browser_download_url.*x86_64-unknown-linux-musl.zip" | cut -d : -f 2,3 | tr -d \" | wget -qi - -O /tmp/cproxy.zip && unzip -j /tmp/cproxy.zip cproxy -d /tmp && sudo mv /tmp/cproxy /usr/local/bin/ && sudo chmod +x /usr/local/bin/cproxy && rm /tmp/cproxy.zip
```

---

## 常用指南

### 1. 基础魔术：像 `proxychains` 一样直接运行新程序

你可以直接通过 `cproxy` 运行一个新的应用程序：

```bash
sudo cproxy --port <destination-local-port> -- <your-program> --arg1 --arg2 ...
```

这将使该程序发起的所有 TCP 连接全部被透明代理。如果你的本地透明代理支持 DNS 地址解析代理，你还可以通过传入 `--redirect-dns` 来重定向并代理其 UDP 53 端口的 DNS 流量：

```bash
sudo cproxy --port <destination-local-port> --redirect-dns -- <your-program> --arg1 --arg2 ...
```

> [!NOTE]
> 害怕在命令中输入 `sudo`？我们需要 root 权限来在系统级别创建和配置 cgroup。但不必担心安全性：被代理的目标程序**不会以 root 权限运行**。`cproxy` 在完成必要的 cgroup 和防火墙规则初始化后，会**立即自动降权**回你执行命令时的原用户身份，确保目标程序与你直接启动它时拥有完全一样的系统权限。

### 2. TPROXY 模式 (TCP & UDP 完美支持)

如果你的系统以及你所使用的本地代理客户端支持 `TPROXY`，你可以在命令中加入 `--mode tproxy`：

```bash
sudo cproxy --port <destination-local-port> --mode tproxy -- <your-program> --arg1 --arg2 ...
# 或者代理已有的进程
sudo cproxy --port <destination-local-port> --mode tproxy --pid <existing-process-pid>
```

开启 `--mode tproxy` 后，将带来以下变化：
- **完美的 UDP 代理**：所有进程发出的 UDP 流量都会被完美拦截并代理，而不仅仅只是代理 UDP 53 的 DNS 请求。
- **支持自定义覆盖 DNS**：你可以通过 `cproxy --mode tproxy --override-dns <dns-server-ip> ...` 强制覆写该应用程序所使用的 DNS 服务器。对于想要为特定应用指定特定 DNS 的场景非常实用。
- **代理软件配置要求**：你在本地 `--port` 运行的 V2Ray、Xray 或 Shadowsocks 必须开启了 TPROXY 监听。例如，V2Ray 的入站配置 `sockopt` 必须包含 `"tproxy": "tproxy"`；Shadowsocks 的 `ss-redir` 需要使用 `-u` 参数启动。

### 3. 进阶用法：代理已经运行的现有进程

通过 `cproxy`，你甚至可以在进程运行途中直接对其进行代理。这在需要代理类似 `docker` 等后台系统服务时极其方便：

```bash
sudo cproxy --port <destination-local-port> --pid <existing-process-pid>
```

只要 `cproxy` 进程在运行，目标进程的流量就会一直处于被代理状态。按下 `Ctrl-C` 退出 `cproxy` 即可瞬间恢复原样。

### 4. 进阶用法：使用 Iptables LOG 追踪调试网络活动

如果你需要调试某个程序在网络底层的流量走向，可以运行：

```bash
sudo cproxy --mode trace <your-program>
```

随后你可以在系统日志（通过命令 `dmesg -w` 或阅读 `/var/log/syslog`）中看到该程序触发的所有网络包日志。该模式需要较新的内核和 `iptables` 命令行支持。

### 5. 进阶用法：代理特定 Cgroup 路径下的所有进程

`cproxy` 允许你直接代理特定 Cgroup 路径下的所有进程。这对于管理和控制一组关联进程的流量非常有效，而无需你单独指定每个进程的 PID。

假设你有一个位于 `/sys/fs/cgroup/mygroup` 的 cgroup 目录，里面运行着若干进程。你只需执行：

```bash
sudo cproxy --port 1080 --cgroup-path /sys/fs/cgroup/mygroup --mode tproxy
```

此命令会拦截并代理该 Cgroup 路径下运行的所有进程产生的 TCP 和 UDP 流量。

---

## WSL + Windows 代理 (内置 TCP 桥接模式)

当你想使用的代理是运行在宿主机（例如 Windows，而 cproxy 运行在 WSL 或容器中）上的普通 SOCKS5 或 HTTP 代理（如 Clash, mihomo, sing-box, V2RayN 等）时，`cproxy` 可以直接将流量转发到该代理，而无需你单独启动任何本地透明代理中间件。

通过传入 `--upstream` 参数，`cproxy` 会在本地启动一个轻量级的**内置 TCP 桥接器**，自动接收被重定向过来的 TCP 流量，使用 `SO_ORIGINAL_DST`（以及 TLS SNI/HTTP Host 嗅探）解析出真实的目的地址，并通过 SOCKS5/HTTP CONNECT 握手协议转发给上游代理。

#### `--port` 与 `--upstream` 是如何协同工作的：
* **`--port <local_port>`** (默认值: `1080`)：`cproxy` **内置 TCP 桥接器在本地 `127.0.0.1` 监听的端口**。`cproxy` 会自动配置防火墙规则，将目标进程的所有原始 TCP 数据包重定向到该端口。
* **`--upstream <proxy_url>`**：你的**外部/远程代理服务地址**（例如 `socks5://192.168.1.10:1080`）。内置桥接器接收到被劫持的连接后，会在此进行协议封装并转发给这个上游代理地址。

> [!WARNING]
> **端口冲突警告**：如果你的上游代理服务也运行在当前这台机器的 `127.0.0.1:1080`，你**必须**使用 `--port` 将 `cproxy` 的本地桥接端口修改为其他端口（如 `--port 1090`），否则会因为在同一个本地 IP 绑定相同的端口而导致“端口已被占用”冲突！

#### 示例命令：
```bash
# 拦截原始 TCP 流量并重定向到本地 1090 端口的内置桥接器，
# 桥接器会自动进行 SOCKS5 握手并转发给运行在 Windows 宿主机 192.168.1.10:1080 的代理端口。
sudo cproxy \
  --port 1090 \
  --upstream socks5://192.168.1.10:1080 \
  -- curl https://www.google.com

# 对接普通的 HTTP 代理同样简单：
sudo cproxy --port 1090 --upstream http://192.168.1.10:7890 -- ./your-program
```

#### 注意事项：
- **仅支持 TCP**：内置桥接器目前仅支持传输 TCP 流量（暂不支持常规 UDP 及 DNS-over-UDP 重写）。因此，`--upstream` 与 `--redirect-dns` 无法同时使用，两者混用时 `cproxy` 将拒绝启动。
- **模式限制**：使用 `--upstream` 时，`cproxy` 的防火墙规则仅支持配合 `--mode redirect`。
- **防环回标记 (SO_MARK)**：桥接器的出站套接字（Socket）会被打上 `SO_MARK = 0xC9B3` 标记。防火墙规则会在检测到该标记时直接 `RETURN` 放行，从而确保桥接器与上游代理的连接本身不会陷入“自己重定向给自己”的死循环。
- **权限要求**：使用 `SO_MARK` 选项要求拥有 `CAP_NET_ADMIN` 权限。因此，在开启 `--upstream` 时，`cproxy` 的父进程会在运行期间持续保持 root 权限以保障套接字标记操作正常（被代理的子进程仍然会自动降权到常规用户）。如果权限不足，程序在启动时会进行检测并提供清晰的报错。
- **鉴权说明**：目前不支持上游代理 URL 中包含用户名密码鉴权（带 `user:pass@` 的 URL 会被拦截报错）。
- **WSL IP 获取**：WSL 不会自动获取宿主机 IP，你需要手动填写。如果在不同网络环境下切换，你可以通过 `ip route show default | awk '/default/ {print $3}'` 获取宿主机网关 IP，并利用环境变量 `CPROXY_UPSTREAM` 注入。

---

## 防火墙后端选择

`cproxy` 提供了两种功能完备的防火墙操作后端：
- `iptables`（默认回退后端）：兼容 cgroup v1 和 cgroup v2。
- `nftables`（自动优先推荐）：当检测到系统中 `nft` 命令行工具可用且主机正在运行 cgroup v2 时，将自动首选此后端。

你可以使用 `--firewall {auto,nft,iptables}` 强制覆盖后端选择：
```bash
sudo cproxy --firewall nft --upstream socks5://10.0.0.1:1080 -- curl https://example.com
```

*使用提示*：使用 `--firewall nft` 要求主机环境使用 cgroup v2 并且 Linux 内核/nftables 支持 `socket cgroupv2 level N` 特性。若在较旧的 Linux 发行版中运行，请使用 `--firewall iptables`（或默认使用 `auto` 自动降级处理）。若自动选择或手动指定了 `iptables` 后端，请确保系统 `PATH` 路径中包含可用的 `iptables` 可执行文件。

---

## 实现原理解密

`cproxy` 的技术原理其实非常朴素且优雅：
1. 它通过 Linux 内核的 `cgroup` 机制为启动的（或指定的）目标程序以及其衍生的所有子进程创建一个专属且隔离的 `cgroup` 控制组。
2. 借由 Linux Netfilter 防火墙规则（`iptables` 或 `nftables`），匹配这个专属 `cgroup` 产生的所有网络数据包。
3. 对这些特定的数据包应用 `REDIRECT` 或 `TPROXY` 动作，无感地将网络流量重定向到指定的代理接收端口，最终实现完全透明且非侵入式的代理机制。

---

## 局限性

- 需要 `root` 权限来创建和管理系统 `cgroup`。
- 目前仅在 Linux 环境下进行了完备的测试。

---

## 类似项目对比

- [graftcp](https://github.com/hmgle/graftcp)：兼容大部分软件，但无法代理 UDP 流量（例如 DNS）。此外，它通过 `ptrace` 机制拦截系统调用，在处理高并发或吞吐较大的程序时对子程序会有较为明显的性能影响。
- [proxychains](https://github.com/haad/proxychains) 和 [proxychains-ng](https://github.com/rofl0r/proxychains-ng)：非常经典且易用，但它们使用 `LD_PRELOAD` 动态劫持 libc 的网络套接字 API。对于采用静态链接、不依赖外部动态链接库的语言编译出的程序（例如 Go 语言编写的程序），它们将完全失效。
- [cgproxy](https://github.com/springzfx/cgproxy)：与 `cproxy` 采用类似的 Cgroup 流量劫持思路。但在使用体验和环境要求上有所差异：
  - `cgproxy` 强制要求 cgroup v2 架构，而 `cproxy` 同时支持 cgroup v1 与 v2，对老旧系统更友好。
  - `cgproxy` 必须在后台持续运行一个守护进程 `cgproxyd`，而 `cproxy` 则是无状态、开箱即用的，用完即退。
  - `cgproxy` 强制依赖内核 TPROXY 支持，而 `cproxy` 中 TPROXY 是可选的，允许回退至兼容性更好的 REDIRECT。
  - `cgproxy` 旨在做全局代理，而 `cproxy` 则专注于简单精准地单进程代理。
