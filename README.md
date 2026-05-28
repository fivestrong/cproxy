<p align="center">
<img width="250px" src="https://user-images.githubusercontent.com/18649508/139117888-4f631b07-0b40-4d24-b478-fb805ceef689.png" />
</p>
<hr/>

[![Crates.io](https://img.shields.io/crates/v/cproxy)](https://crates.io/crates/cproxy) [![CI](https://github.com/NOBLES5E/cproxy/actions/workflows/build.yml/badge.svg)](https://github.com/NOBLES5E/cproxy/actions/workflows/build.yml) ![Crates.io](https://img.shields.io/crates/d/cproxy) ![Crates.io](https://img.shields.io/crates/l/cproxy)

Ever wished you could make your stubborn programs use a proxy without them even knowing? Well, say hello to `cproxy`.

## Key Features

- Transparent redirection of TCP and UDP traffic
- Support for different proxies per application/process
- Compatible with all programs, including statically linked Go binaries
- DNS request redirection
- Simple usage similar to `proxychains`
- Ability to proxy existing running processes
- Support for both iptables `REDIRECT` and `TPROXY` modes
- DNS server override in `TPROXY` mode
- Network activity tracing using iptables `LOG` target
- Compatible with cgroup v1 and v2
- No background daemon required
- Easy integration with existing software like V2Ray, Xray, and Shadowsocks
- Direct dial-out to a remote HTTP / SOCKS5 proxy via the built-in TCP bridge (`--upstream`)
- Optional `nftables` backend (auto-detected, falls back to `iptables`)

> [!TIP]
> By default cproxy assumes `--port` points at a transparent proxy you started yourself (like V2Ray's `dokodemo-door` inbound or shadowsocks `ss-redir`). If you only have a regular HTTP CONNECT or SOCKS5 proxy (e.g. one running on your Windows host while cproxy runs in WSL), pass it via `--upstream` and cproxy will run a small TCP bridge for you. See the [WSL section](#wsl--windows-proxy) below.

## Installation

You can install by downloading the binary from the [release page](https://github.com/NOBLES5E/cproxy/releases) or install with: `cargo install cproxy`.

Alternatively, here's a oneliner that downloads the latest release and put it in your `/usr/local/bin/` (for the lazy... I mean, efficient folks):

```
curl -s https://api.github.com/repos/NOBLES5E/cproxy/releases/latest | grep "browser_download_url.*x86_64-unknown-linux-musl.zip" | cut -d : -f 2,3 | tr -d \" | wget -qi - -O /tmp/cproxy.zip && unzip -j /tmp/cproxy.zip cproxy -d /tmp && sudo mv /tmp/cproxy /usr/local/bin/ && sudo chmod +x /usr/local/bin/cproxy && rm /tmp/cproxy.zip
```

## Usage

### Basic Magic Trick: Just Like `proxychains`

You can launch a new program with `cproxy` with:

```
sudo cproxy --port <destination-local-port> -- <your-program> --arg1 --arg2 ...
```

All TCP connections requests will be proxied. If your local transparent proxy support DNS address overriding, you can
also redirect DNS traffic with `--redirect-dns`:

```
sudo cproxy --port <destination-local-port> --redirect-dns -- <your-program> --arg1 --arg2 ...
```

For an example setup, see [wiki](https://github.com/NOBLES5E/cproxy/wiki/Example-setup-with-V2Ray).

> [!NOTE]
> Scared of `sudo` in the command? Well, that's what we need to have the permission to modify cgroup. But don't worry too much, the program you run will still be run under your original user, not as root. `cproxy` automatically drops privileges after setting up the necessary cgroup configurations, ensuring that your program runs with the same permissions as if you had launched it directly.

### The TPROXY Twist

If your system support `tproxy`, you can use `tproxy` with `--mode tproxy`:

```bash
sudo cproxy --port <destination-local-port> --mode tproxy -- <your-program> --arg1 --arg2 ...
# or for existing process
sudo cproxy --port <destination-local-port> --mode tproxy --pid <existing-process-pid>
```

With `--mode tproxy`, there are several differences:

* All UDP traffic are proxied instead of only DNS UDP traffic to port 53.
* Your V2Ray or shadowsocks service should have `tproxy` enabled on the inbound port. For V2Ray, you
  need `"tproxy": "tproxy"` as
  in [V2Ray Documentation](https://www.v2ray.com/en/configuration/transport.html#sockoptobject). For shadowsocks, you
  need `-u` as shown in [shadowsocks manpage](http://manpages.org/ss-redir).

An example setup can be found [here](https://github.com/NOBLES5E/cproxy/wiki/Example-setup-with-V2Ray).

Note that when you are using the `tproxy` mode, you can override the DNS server address
with `cproxy --mode tproxy --override-dns <your-dns-server-addr> ...`. This is useful when you want to use a different
DNS server for a specific application.

### Advanced Usage: Proxy an Existing Process

With `cproxy`, you can even proxy an existing process. This is very handy when you want to proxy existing system
services such as `docker`. To do this, just run

```
sudo cproxy --port <destination-local-port> --pid <existing-process-pid>
```

The target process will be proxied as long as this `cproxy` command is running. You can press Ctrl-C to stop proxying.

### Advanced Usage: Debug a Program's Network Activity with Iptables LOG Target

With `cproxy`, you can easily debug a program's traffic in netfilter. Just run the program with

```bash
sudo cproxy --mode trace <your-program>
```

You will be able to see log in `dmesg`. Note that this requires a recent enough kernel and iptables.

### Advanced Usage: Proxy Specific Cgroup Paths

`cproxy` allows you to proxy all processes within specific cgroup paths. This is particularly useful for managing groups of related processes without specifying individual PIDs.

Suppose you have a cgroup at `/sys/fs/cgroup/mygroup` containing several processes you wish to proxy. You can run:

```bash
sudo cproxy --port 1080 --cgroup-path /sys/fs/cgroup/mygroup --mode tproxy
```

This command will proxy all TCP and UDP traffic from processes within the `/sys/fs/cgroup/mygroup` cgroup using TPROXY mode on port `1080`.

### WSL + Windows Proxy (Built-in TCP Bridge)

When the proxy you want to use is a standard HTTP CONNECT or SOCKS5 listener (e.g. running on your Windows host while cproxy runs inside WSL/containers, like Clash, mihomo, sing-box, etc.), cproxy can forward connections to it directly without requiring you to run a separate transparent-proxy helper. 

By passing `--upstream`, cproxy starts a lightweight, **internal TCP bridge** to bridge the gap between raw diverted TCP traffic and application-layer proxy protocols.

#### How `--port` and `--upstream` work together:
* **`--port <local_port>`**: The **local port** on `127.0.0.1` where `cproxy`'s internal TCP bridge will listen. When omitted in `--upstream` mode, cproxy asks the OS for an available port and configures the firewall to redirect your target program's raw TCP packets to that chosen port.
* **`--upstream <proxy_url>`**: The address and port of your **external/remote proxy server** (e.g. `socks5://192.168.1.10:1080`). The internal bridge will forward the parsed connections to this address.

> [!NOTE]
> In non-`--upstream` modes, omitted `--port` still defaults to `1080` because it points at an external transparent proxy that cproxy does not own. In `--upstream` mode, only an explicitly supplied `--port` can conflict.

#### Example usage:
```bash
# cproxy picks a free local bridge port automatically, wraps redirected
# TCP traffic in SOCKS5, and sends it to the Windows host proxy.
sudo cproxy \
  --upstream socks5://192.168.1.10:1080 \
  -- curl https://www.google.com

# Pin the local bridge port only when another tool needs to know it:
sudo cproxy --port 1090 --upstream http://192.168.1.10:7890 -- ./your-program
```

Notes:

* Only TCP is supported through `--upstream` for now (no UDP, no DNS-over-UDP rewrite). `--upstream` and `--redirect-dns` cannot be combined for the same reason and cproxy will refuse the combination.
* Only `--mode redirect` is supported together with `--upstream`.
* The bridge tags its own outbound sockets with `SO_MARK = 0xC9B3` and the firewall rules return early on that mark, so the bridge's connection to the upstream proxy is **not** routed back into itself.
* `SO_MARK` requires `CAP_NET_ADMIN`. cproxy keeps the parent process at effective root for the lifetime of the bridge in `--upstream` mode and probes the capability at startup, so it fails fast with a clear error if you try to run it under a less privileged user. The child program you launch still drops to your invoking user.
* Authentication is not supported in this build; URLs with `user:pass@` are rejected.
* WSL does not auto-detect your Windows host IP; specify it explicitly. If you switch networks regularly you can read the gateway with `ip route show default | awk '/default/ {print $3}'` and inject it via `CPROXY_UPSTREAM`.

### Firewall Backend Selection

Cproxy supports two firewall backends:

* `iptables` (default fallback) – works with both cgroup v1 and v2.
* `nftables` – auto-preferred when `nft` is available **and** the host is running cgroup v2.

Override with `--firewall {auto,nft,iptables}`:

```bash
sudo cproxy --firewall nft --upstream socks5://10.0.0.1:1080 -- curl https://example.com
```

`--firewall nft` requires cgroup v2 and a kernel/nftables combination that supports `socket cgroupv2 level N`. On older systems use `--firewall iptables` (or rely on `auto`, which detects this and falls back automatically).

If `auto` or `--firewall iptables` selects the iptables backend, the `iptables` userspace command must be installed on `PATH`; otherwise cproxy now fails fast with a backend selection error instead of a later rule-creation failure.

## The Secret Sauce

`cproxy` simply creates a unique `cgroup` for the proxied program, and redirect its traffic with packet rules.

## Limitations

* `cproxy` requires root access to modify `cgroup`.
* Currently only tested on Linux.

## Similar Projects

There are some awesome existing work:

* [graftcp](https://github.com/hmgle/graftcp): work on most programs, but cannot proxy UDP (such as DNS)
  requests. `graftcp` also has performance hit on the underlying program, since it uses `ptrace`.
* [proxychains](https://github.com/haad/proxychains): easy to use, but not working on static linked programs (such as Go
  programs).
* [proxychains-ng](https://github.com/rofl0r/proxychains-ng): similar to proxychains.
* [cgproxy](https://github.com/springzfx/cgproxy): `cgproxy` also uses cgroup to do transparent proxy, and the idea is
  similar to `cproxy`'s. There are some differences in UX and system requirements:
    * `cgproxy` requires system `cgroup` v2 support, while `cproxy` works with both v1 and v2.
    * `cgproxy` requires a background daemon process `cgproxyd` running, while `cproxy` does not.
    * `cgproxy` requires `tproxy`, which is optional in `cproxy`.
    * `cgproxy` can be used to do global proxy, while `cproxy` does not intended to support global proxy.
