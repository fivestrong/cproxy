use super::{CgroupMatch, FirewallBackend, RedirectParams, TProxyParams, TraceParams};
use eyre::{eyre, Result};
use std::io::Write;
use std::process::{Command, Stdio};

pub struct NftablesBackend;

impl NftablesBackend {
    pub fn new() -> Self {
        Self
    }
}

/// Returns true if the `nft` command is available on PATH.
pub fn is_available() -> bool {
    Command::new("nft").arg("--version").output().is_ok()
}

/// Probe whether the running kernel + nftables combination understands
/// `socket cgroupv2 level N "name"`. We need this match for redirect/tproxy
/// rules; without it the backend is unusable. We use `nft -c` (check-only) so
/// the probe never modifies system state.
pub fn supports_socket_cgroupv2() -> bool {
    let program = "add table ip cproxy_probe; \
                   add chain ip cproxy_probe c { type filter hook output priority 0; }; \
                   add rule ip cproxy_probe c socket cgroupv2 level 1 \"x\" return";
    let out = Command::new("nft").args(["-c", "--", program]).output();
    match out {
        Ok(o) => {
            if o.status.success() {
                return true;
            }
            let err = String::from_utf8_lossy(&o.stderr);
            tracing::debug!(
                "nft does not support `socket cgroupv2`: status={} stderr={}",
                o.status,
                err.trim()
            );
            false
        }
        Err(e) => {
            tracing::debug!("nft probe failed to run: {}", e);
            false
        }
    }
}

/// Run a multi-line nft program by piping it into `nft -f -`. This applies
/// atomically: either every rule lands or none do.
fn nft_apply(program: &str) -> Result<()> {
    tracing::debug!("applying nft program:\n{}", program);
    let mut child = Command::new("nft")
        .arg("-f")
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| eyre!("failed to spawn nft: {}", e))?;
    {
        let stdin = child
            .stdin
            .as_mut()
            .ok_or_else(|| eyre!("failed to open nft stdin"))?;
        stdin
            .write_all(program.as_bytes())
            .map_err(|e| eyre!("failed to write nft program: {}", e))?;
    }
    let output = child
        .wait_with_output()
        .map_err(|e| eyre!("failed to wait nft: {}", e))?;
    if !output.status.success() {
        return Err(eyre!(
            "nft program failed (status {}): stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(())
}

/// Translate a cproxy cgroup path (either relative like `cproxy-1234` or
/// absolute like `/sys/fs/cgroup/foo/bar`) into the (level, name) tuple that
/// `nft socket cgroupv2 level N "name"` expects.
fn cgroupv2_level_name(cg: &CgroupMatch) -> Result<(u32, String)> {
    let path = cg
        .v2_path
        .as_ref()
        .ok_or_else(|| eyre!("nftables backend requires cgroup v2"))?;
    let trimmed = path.trim_start_matches('/');
    let trimmed = trimmed.strip_prefix("sys/fs/cgroup/").unwrap_or(trimmed);
    let trimmed = trimmed.trim_matches('/');
    let parts: Vec<&str> = trimmed.split('/').filter(|s| !s.is_empty()).collect();
    if parts.is_empty() {
        return Err(eyre!("cgroup path '{}' resolves to an empty name", path));
    }
    let level = parts.len() as u32;
    let name = parts
        .last()
        .map(|s| (*s).to_string())
        .ok_or_else(|| eyre!("cgroup path '{}' has no leaf component", path))?;
    Ok((level, name))
}

fn table_name(chain_name: &str) -> String {
    format!("cproxy_{}", chain_name)
}

fn delete_table_if_exists(name: &str) -> Result<()> {
    // `nft delete table` errors out when the table doesn't exist; ignore that
    // case so teardown is idempotent.
    let out = Command::new("nft")
        .args(["delete", "table", "ip", name])
        .output();
    match out {
        Ok(o) if o.status.success() => Ok(()),
        Ok(o) => {
            let err = String::from_utf8_lossy(&o.stderr);
            if err.contains("No such file or directory") || err.contains("does not exist") {
                Ok(())
            } else {
                Err(eyre!("nft delete table failed: {}", err))
            }
        }
        Err(e) => Err(eyre!("failed to invoke nft delete: {}", e)),
    }
}

impl FirewallBackend for NftablesBackend {
    fn name(&self) -> &'static str {
        "nftables"
    }

    fn setup_redirect(&self, p: &RedirectParams) -> Result<()> {
        let (level, name) = cgroupv2_level_name(&p.cgroup)?;
        let table = table_name(&p.chain_name);
        let port = p.listen_port;

        // Build the program. Order matters: lo bypass, mark exemption, then
        // the cgroup-matching redirect.
        let mut prog = String::new();
        prog.push_str(&format!("add table ip {table}\n"));
        prog.push_str(&format!(
            "add chain ip {table} output {{ type nat hook output priority -100; policy accept; }}\n"
        ));
        prog.push_str(&format!(
            "add rule ip {table} output oifname \"lo\" return\n"
        ));
        if let Some(mark) = p.bridge_mark_exempt {
            prog.push_str(&format!(
                "add rule ip {table} output meta mark 0x{mark:x} return\n"
            ));
        }
        prog.push_str(&format!(
            "add rule ip {table} output meta l4proto tcp socket cgroupv2 level {level} \"{name}\" redirect to :{port}\n"
        ));
        if p.redirect_dns {
            prog.push_str(&format!(
                "add rule ip {table} output meta l4proto udp socket cgroupv2 level {level} \"{name}\" udp dport 53 redirect to :{port}\n"
            ));
        }
        nft_apply(&prog)
    }

    fn teardown_redirect(&self, p: &RedirectParams) -> Result<()> {
        delete_table_if_exists(&table_name(&p.chain_name))
    }

    fn setup_tproxy(&self, p: &TProxyParams) -> Result<()> {
        let (level, name) = cgroupv2_level_name(&p.cgroup)?;
        let table = table_name(&p.output_chain_name);
        let port = p.listen_port;
        let mark = p.mark;

        let mut prog = String::new();
        prog.push_str(&format!("add table ip {table}\n"));

        // MARK packets on OUTPUT (mangle priority).
        prog.push_str(&format!(
            "add chain ip {table} output {{ type route hook output priority mangle; policy accept; }}\n"
        ));
        prog.push_str(&format!(
            "add rule ip {table} output oifname \"lo\" return\n"
        ));
        prog.push_str(&format!(
            "add rule ip {table} output meta l4proto tcp socket cgroupv2 level {level} \"{name}\" meta mark set 0x{mark:x}\n"
        ));
        prog.push_str(&format!(
            "add rule ip {table} output meta l4proto udp socket cgroupv2 level {level} \"{name}\" meta mark set 0x{mark:x}\n"
        ));

        // TPROXY on PREROUTING for marked traffic.
        prog.push_str(&format!(
            "add chain ip {table} prerouting {{ type filter hook prerouting priority mangle; policy accept; }}\n"
        ));
        prog.push_str(&format!(
            "add rule ip {table} prerouting iifname \"lo\" return\n"
        ));
        prog.push_str(&format!(
            "add rule ip {table} prerouting meta l4proto tcp meta mark 0x{mark:x} tproxy to :{port}\n"
        ));
        prog.push_str(&format!(
            "add rule ip {table} prerouting meta l4proto udp meta mark 0x{mark:x} tproxy to :{port}\n"
        ));

        if let Some(override_dns) = &p.override_dns {
            prog.push_str(&format!(
                "add chain ip {table} output_nat {{ type nat hook output priority -100; policy accept; }}\n"
            ));
            prog.push_str(&format!(
                "add rule ip {table} output_nat oifname \"lo\" return\n"
            ));
            prog.push_str(&format!(
                "add rule ip {table} output_nat meta l4proto udp socket cgroupv2 level {level} \"{name}\" udp dport 53 dnat to {override_dns}\n"
            ));
        }
        nft_apply(&prog)
    }

    fn teardown_tproxy(&self, p: &TProxyParams) -> Result<()> {
        delete_table_if_exists(&table_name(&p.output_chain_name))
    }

    fn setup_trace(&self, p: &TraceParams) -> Result<()> {
        let (level, name) = cgroupv2_level_name(&p.cgroup)?;
        let table = table_name(&p.output_chain_name);
        let mut prog = String::new();
        prog.push_str(&format!("add table ip {table}\n"));
        prog.push_str(&format!(
            "add chain ip {table} output {{ type filter hook output priority raw; policy accept; }}\n"
        ));
        prog.push_str(&format!(
            "add rule ip {table} output meta l4proto tcp socket cgroupv2 level {level} \"{name}\" log\n"
        ));
        prog.push_str(&format!(
            "add rule ip {table} output meta l4proto udp socket cgroupv2 level {level} \"{name}\" log\n"
        ));
        nft_apply(&prog)
    }

    fn teardown_trace(&self, p: &TraceParams) -> Result<()> {
        delete_table_if_exists(&table_name(&p.output_chain_name))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cgroupv2_level_name_handles_relative_path() {
        let cg = CgroupMatch {
            class_id: 1,
            v2_path: Some("cproxy-1234".into()),
        };
        let (level, name) = cgroupv2_level_name(&cg).unwrap();
        assert_eq!(level, 1);
        assert_eq!(name, "cproxy-1234");
    }

    #[test]
    fn cgroupv2_level_name_handles_absolute_path() {
        let cg = CgroupMatch {
            class_id: 1,
            v2_path: Some("/sys/fs/cgroup/myapp".into()),
        };
        let (level, name) = cgroupv2_level_name(&cg).unwrap();
        assert_eq!(level, 1);
        assert_eq!(name, "myapp");
    }

    #[test]
    fn cgroupv2_level_name_handles_nested_path() {
        let cg = CgroupMatch {
            class_id: 1,
            v2_path: Some("/sys/fs/cgroup/a/b/c".into()),
        };
        let (level, name) = cgroupv2_level_name(&cg).unwrap();
        assert_eq!(level, 3);
        assert_eq!(name, "c");
    }

    #[test]
    fn cgroupv2_level_name_rejects_v1() {
        let cg = CgroupMatch {
            class_id: 1,
            v2_path: None,
        };
        assert!(cgroupv2_level_name(&cg).is_err());
    }
}
