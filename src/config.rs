use eyre::{eyre, Result};
use structopt::StructOpt;

/// Reserved fwmark for cproxy's own outbound sockets (the bridge in `--upstream`
/// mode). Netfilter rules return early when they see this mark so the bridge's
/// connection to the remote HTTP/SOCKS proxy does not get redirected back into
/// itself.
pub const BRIDGE_MARK: u32 = 0xC9B3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Redirect,
    Tproxy,
    Trace,
}

impl Mode {
    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "redirect" => Ok(Mode::Redirect),
            "tproxy" => Ok(Mode::Tproxy),
            "trace" => Ok(Mode::Trace),
            other => Err(eyre!(
                "invalid --mode '{}', expected one of: redirect, tproxy, trace",
                other
            )),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirewallChoice {
    Auto,
    Nft,
    Iptables,
}

impl FirewallChoice {
    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "auto" => Ok(FirewallChoice::Auto),
            "nft" | "nftables" => Ok(FirewallChoice::Nft),
            "iptables" => Ok(FirewallChoice::Iptables),
            other => Err(eyre!(
                "invalid --firewall '{}', expected one of: auto, nft, iptables",
                other
            )),
        }
    }
}

#[derive(StructOpt, Debug)]
#[structopt(name = "cproxy", about = "Transparent proxy built on cgroup net_cls.")]
pub struct Cli {
    /// Redirect traffic to specific local port. When --upstream is provided this
    /// is the local port that the built-in bridge listens on (still on
    /// 127.0.0.1); otherwise it is the address of an external transparent
    /// proxy that you started yourself.
    #[structopt(long, env = "CPROXY_PORT", default_value = "1080")]
    pub port: u32,

    /// redirect DNS traffic. This option only works with redirect mode
    #[structopt(long)]
    pub redirect_dns: bool,

    /// Proxy mode can be `trace` (use iptables TRACE target to debug program network), `tproxy`, or `redirect`.
    #[structopt(long, default_value = "redirect")]
    pub mode: String,

    /// Override dns server address. This option only works with tproxy mode
    #[structopt(long)]
    pub override_dns: Option<String>,

    /// Proxy an existing process.
    #[structopt(long)]
    pub pid: Option<u32>,

    /// Proxy specific cgroup paths, can be specified multiple times)
    #[structopt(long)]
    pub cgroup_path: Vec<String>,

    /// Optional remote upstream proxy. When set, cproxy starts an internal TCP
    /// bridge on `--port` and forwards each redirected connection to this
    /// upstream via HTTP CONNECT or SOCKS5 CONNECT. Examples:
    ///   --upstream http://192.168.1.10:7890
    ///   --upstream socks5://192.168.1.10:1080
    /// Only `redirect` mode is supported together with --upstream.
    #[structopt(long, env = "CPROXY_UPSTREAM")]
    pub upstream: Option<String>,

    /// Firewall backend selection. `auto` (default) prefers nft when available
    /// and falls back to iptables; `nft` and `iptables` force a specific
    /// backend.
    #[structopt(long, default_value = "auto")]
    pub firewall: String,

    #[structopt(subcommand)]
    pub command: Option<ChildCommand>,
}

#[derive(StructOpt, Debug)]
pub enum ChildCommand {
    #[structopt(external_subcommand)]
    Command(Vec<String>),
}

impl Cli {
    pub fn mode_enum(&self) -> Result<Mode> {
        Mode::parse(&self.mode)
    }

    pub fn firewall_choice(&self) -> Result<FirewallChoice> {
        FirewallChoice::parse(&self.firewall)
    }

    /// Validate combinations that we explicitly do not support to fail fast
    /// instead of producing weird runtime behaviour.
    pub fn validate(&self) -> Result<()> {
        let mode = self.mode_enum()?;
        let _ = self.firewall_choice()?;

        if self.upstream.is_some() && mode != Mode::Redirect {
            return Err(eyre!(
                "--upstream is only supported together with --mode redirect (got --mode {})",
                self.mode
            ));
        }
        // The built-in bridge only speaks TCP. Redirecting UDP/53 into it
        // would silently blackhole DNS, so refuse the combination outright.
        if self.upstream.is_some() && self.redirect_dns {
            return Err(eyre!(
                "--upstream cannot be combined with --redirect-dns: the built-in bridge \
                 speaks TCP only and would blackhole UDP/53; either drop --redirect-dns \
                 or run a separate transparent UDP forwarder"
            ));
        }
        Ok(())
    }
}
