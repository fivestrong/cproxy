use crate::config::FirewallChoice;
use eyre::{eyre, Result};
use std::sync::Arc;

pub mod iptables;
pub mod nft;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BackendResolution {
    Iptables(&'static str),
    Nft(&'static str),
}

/// How to match the target cgroup in firewall rules.
///
/// `class_id` is always populated (even under v2 we synthesize one when
/// building the cgroup, see `CGroupGuard`), and `v2_path` is `Some` only when
/// the system is on the unified (v2) hierarchy. Backends that prefer path-based
/// matching (`iptables -m cgroup --path`, `nft socket cgroupv2`) use
/// `v2_path` when present and fall back to `class_id` for v1.
#[derive(Debug, Clone)]
pub struct CgroupMatch {
    pub class_id: u32,
    pub v2_path: Option<String>,
}

impl CgroupMatch {
    #[allow(dead_code)]
    pub fn is_v2(&self) -> bool {
        self.v2_path.is_some()
    }
}

#[derive(Debug, Clone)]
pub struct RedirectParams {
    pub chain_name: String,
    pub listen_port: u32,
    pub cgroup: CgroupMatch,
    pub redirect_dns: bool,
    /// Optional fwmark that should bypass the redirect (used by the built-in
    /// bridge so it can reach its remote upstream without being rerouted into
    /// itself).
    pub bridge_mark_exempt: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct TProxyParams {
    pub output_chain_name: String,
    pub prerouting_chain_name: String,
    pub listen_port: u32,
    pub mark: u32,
    pub cgroup: CgroupMatch,
    pub override_dns: Option<String>,
}

#[derive(Debug, Clone)]
pub struct TraceParams {
    pub output_chain_name: String,
    /// Reserved for a future enhancement where trace mode logs PREROUTING
    /// hooks too. The original code path kept this field but never used it.
    #[allow(dead_code)]
    pub prerouting_chain_name: String,
    pub cgroup: CgroupMatch,
}

pub trait FirewallBackend: Send + Sync {
    fn name(&self) -> &'static str;
    fn setup_redirect(&self, params: &RedirectParams) -> Result<()>;
    fn teardown_redirect(&self, params: &RedirectParams) -> Result<()>;
    fn setup_tproxy(&self, params: &TProxyParams) -> Result<()>;
    fn teardown_tproxy(&self, params: &TProxyParams) -> Result<()>;
    fn setup_trace(&self, params: &TraceParams) -> Result<()>;
    fn teardown_trace(&self, params: &TraceParams) -> Result<()>;
}

/// Resolve the user's `--firewall` choice into an actual backend.
///
/// Auto-detection requires three things to choose nft:
///   1. cgroup v2 hierarchy (we don't implement v1 in nft);
///   2. `nft` binary present;
///   3. the kernel + nftables combination actually understands
///      `socket cgroupv2 level N "name"` (probed via `nft -c`).
///
/// Any failure on those three falls back to iptables in `auto` mode, but only
/// if the `iptables` binary is available too. Forced backend selection surfaces
/// a precise dependency error up front.
fn resolve_backend(
    choice: FirewallChoice,
    cgroup_v2: bool,
    iptables_available: bool,
    nft_available: bool,
    nft_supports_socket_cgroupv2: bool,
) -> Result<BackendResolution> {
    match choice {
        FirewallChoice::Iptables => {
            if !iptables_available {
                return Err(eyre!(
                    "--firewall iptables requested but the `iptables` command is not available"
                ));
            }
            Ok(BackendResolution::Iptables("forced"))
        }
        FirewallChoice::Nft => {
            if !nft_available {
                return Err(eyre!(
                    "--firewall nft requested but the `nft` command is not available"
                ));
            }
            if !cgroup_v2 {
                return Err(eyre!(
                    "--firewall nft only supports cgroup v2 in this build; \
                     your system is running cgroup v1, please use --firewall iptables"
                ));
            }
            if !nft_supports_socket_cgroupv2 {
                return Err(eyre!(
                    "--firewall nft requested but the running kernel/nftables \
                     does not support `socket cgroupv2` matching; \
                     please upgrade nftables/kernel or use --firewall iptables"
                ));
            }
            Ok(BackendResolution::Nft("forced"))
        }
        FirewallChoice::Auto => {
            if !cgroup_v2 {
                if !iptables_available {
                    return Err(eyre!(
                        "--firewall auto resolved to iptables because this host is running cgroup v1, \
                         but the `iptables` command is not available"
                    ));
                }
                return Ok(BackendResolution::Iptables("auto; cgroup v1"));
            }
            if !nft_available {
                if !iptables_available {
                    return Err(eyre!(
                        "--firewall auto fell back to iptables because the `nft` command is not available, \
                         but the `iptables` command is also not available"
                    ));
                }
                return Ok(BackendResolution::Iptables("auto; nft not installed"));
            }
            if !nft_supports_socket_cgroupv2 {
                if !iptables_available {
                    return Err(eyre!(
                        "--firewall auto fell back to iptables because nft lacks `socket cgroupv2` support, \
                         but the `iptables` command is also not available"
                    ));
                }
                return Ok(BackendResolution::Iptables(
                    "auto; nft lacks `socket cgroupv2` support",
                ));
            }
            Ok(BackendResolution::Nft("auto"))
        }
    }
}

pub fn select_backend(choice: FirewallChoice, cgroup_v2: bool) -> Result<Arc<dyn FirewallBackend>> {
    match resolve_backend(
        choice,
        cgroup_v2,
        iptables::is_available(),
        nft::is_available(),
        nft::supports_socket_cgroupv2(),
    )? {
        BackendResolution::Iptables(reason) => {
            tracing::info!("firewall backend = iptables ({})", reason);
            Ok(Arc::new(iptables::IptablesBackend::new()))
        }
        BackendResolution::Nft(reason) => {
            tracing::info!("firewall backend = nft ({})", reason);
            Ok(Arc::new(nft::NftablesBackend::new()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forced_iptables_requires_command() {
        let err = resolve_backend(FirewallChoice::Iptables, true, false, true, true).unwrap_err();
        assert!(err
            .to_string()
            .contains("--firewall iptables requested but the `iptables` command is not available"));
    }

    #[test]
    fn auto_cgroup_v1_requires_iptables_for_fallback() {
        let err = resolve_backend(FirewallChoice::Auto, false, false, true, true).unwrap_err();
        assert!(err.to_string().contains(
            "--firewall auto resolved to iptables because this host is running cgroup v1"
        ));
    }

    #[test]
    fn auto_uses_iptables_when_nft_is_missing_but_fallback_exists() {
        let resolved = resolve_backend(FirewallChoice::Auto, true, true, false, false).unwrap();
        assert_eq!(
            resolved,
            BackendResolution::Iptables("auto; nft not installed")
        );
    }

    #[test]
    fn auto_uses_nft_when_supported() {
        let resolved = resolve_backend(FirewallChoice::Auto, true, true, true, true).unwrap();
        assert_eq!(resolved, BackendResolution::Nft("auto"));
    }
}
