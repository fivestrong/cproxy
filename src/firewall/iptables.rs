use super::{CgroupMatch, FirewallBackend, RedirectParams, TProxyParams, TraceParams};
use eyre::Result;
use std::process::Command;

pub struct IptablesBackend;

impl IptablesBackend {
    pub fn new() -> Self {
        Self
    }
}

/// Returns true if the `iptables` command is available on PATH.
pub fn is_available() -> bool {
    Command::new("iptables").arg("--version").output().is_ok()
}

fn append_cgroup_match(cg: &CgroupMatch, sink: &mut Vec<String>) {
    if let Some(path) = &cg.v2_path {
        sink.push("-m".into());
        sink.push("cgroup".into());
        sink.push("--path".into());
        sink.push(path.clone());
    } else {
        sink.push("-m".into());
        sink.push("cgroup".into());
        sink.push("--cgroup".into());
        sink.push(cg.class_id.to_string());
    }
}

fn run_iptables(args: &[&str]) -> Result<()> {
    cmd_lib::run_cmd!(iptables $[args])?;
    Ok(())
}

impl FirewallBackend for IptablesBackend {
    fn name(&self) -> &'static str {
        "iptables"
    }

    fn setup_redirect(&self, p: &RedirectParams) -> Result<()> {
        let chain = p.chain_name.as_str();
        let port = p.listen_port;

        cmd_lib::run_cmd! {
            iptables -t nat -N ${chain};
            iptables -t nat -A OUTPUT -j ${chain};
            iptables -t nat -A ${chain} -p udp -o lo -j RETURN;
            iptables -t nat -A ${chain} -p tcp -o lo -j RETURN;
        }?;

        if let Some(mark) = p.bridge_mark_exempt {
            let mark_str = format!("0x{:x}", mark);
            cmd_lib::run_cmd! {
                iptables -t nat -A ${chain} -m mark --mark ${mark_str} -j RETURN;
            }?;
        }

        let mut tcp_args: Vec<String> = vec![
            "-t".into(),
            "nat".into(),
            "-A".into(),
            chain.into(),
            "-p".into(),
            "tcp".into(),
        ];
        append_cgroup_match(&p.cgroup, &mut tcp_args);
        tcp_args.extend([
            "-j".into(),
            "REDIRECT".into(),
            "--to-ports".into(),
            port.to_string(),
        ]);
        let tcp_args_ref: Vec<&str> = tcp_args.iter().map(|s| s.as_str()).collect();
        run_iptables(&tcp_args_ref)?;

        if p.redirect_dns {
            let mut udp_args: Vec<String> = vec![
                "-t".into(),
                "nat".into(),
                "-A".into(),
                chain.into(),
                "-p".into(),
                "udp".into(),
            ];
            append_cgroup_match(&p.cgroup, &mut udp_args);
            udp_args.extend([
                "--dport".into(),
                "53".into(),
                "-j".into(),
                "REDIRECT".into(),
                "--to-ports".into(),
                port.to_string(),
            ]);
            let udp_args_ref: Vec<&str> = udp_args.iter().map(|s| s.as_str()).collect();
            run_iptables(&udp_args_ref)?;
        }

        Ok(())
    }

    fn teardown_redirect(&self, p: &RedirectParams) -> Result<()> {
        let chain = p.chain_name.as_str();
        cmd_lib::run_cmd! {
            iptables -t nat -D OUTPUT -j ${chain};
            iptables -t nat -F ${chain};
            iptables -t nat -X ${chain};
        }?;
        Ok(())
    }

    fn setup_tproxy(&self, p: &TProxyParams) -> Result<()> {
        let output_chain = p.output_chain_name.as_str();
        let prerouting_chain = p.prerouting_chain_name.as_str();
        let mark = p.mark;
        let port = p.listen_port;

        cmd_lib::run_cmd! {
            iptables -t mangle -N ${prerouting_chain};
            iptables -t mangle -A PREROUTING -j ${prerouting_chain};
            iptables -t mangle -A ${prerouting_chain} -p tcp -o lo -j RETURN;
            iptables -t mangle -A ${prerouting_chain} -p udp -o lo -j RETURN;
            iptables -t mangle -A ${prerouting_chain} -p udp -m mark --mark ${mark} -j TPROXY --on-ip 127.0.0.1 --on-port ${port};
            iptables -t mangle -A ${prerouting_chain} -p tcp -m mark --mark ${mark} -j TPROXY --on-ip 127.0.0.1 --on-port ${port};

            iptables -t mangle -N ${output_chain};
            iptables -t mangle -A OUTPUT -j ${output_chain};
            iptables -t mangle -A ${output_chain} -p tcp -o lo -j RETURN;
            iptables -t mangle -A ${output_chain} -p udp -o lo -j RETURN;
        }?;

        if p.override_dns.is_some() {
            cmd_lib::run_cmd! {
                iptables -t nat -N ${output_chain};
                iptables -t nat -A OUTPUT -j ${output_chain};
                iptables -t nat -A ${output_chain} -p udp -o lo -j RETURN;
            }?;
        }

        for proto in &["tcp", "udp"] {
            let mut args: Vec<String> = vec![
                "-t".into(),
                "mangle".into(),
                "-A".into(),
                output_chain.into(),
                "-p".into(),
                (*proto).into(),
            ];
            append_cgroup_match(&p.cgroup, &mut args);
            args.extend([
                "-j".into(),
                "MARK".into(),
                "--set-mark".into(),
                mark.to_string(),
            ]);
            let args_ref: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
            run_iptables(&args_ref)?;
        }

        if let Some(override_dns) = &p.override_dns {
            let mut args: Vec<String> = vec![
                "-t".into(),
                "nat".into(),
                "-A".into(),
                output_chain.into(),
                "-p".into(),
                "udp".into(),
            ];
            append_cgroup_match(&p.cgroup, &mut args);
            args.extend([
                "--dport".into(),
                "53".into(),
                "-j".into(),
                "DNAT".into(),
                "--to-destination".into(),
                override_dns.clone(),
            ]);
            let args_ref: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
            run_iptables(&args_ref)?;
        }
        Ok(())
    }

    fn teardown_tproxy(&self, p: &TProxyParams) -> Result<()> {
        let output_chain = p.output_chain_name.as_str();
        let prerouting_chain = p.prerouting_chain_name.as_str();

        cmd_lib::run_cmd! {
            iptables -t mangle -D PREROUTING -j ${prerouting_chain};
            iptables -t mangle -F ${prerouting_chain};
            iptables -t mangle -X ${prerouting_chain};

            iptables -t mangle -D OUTPUT -j ${output_chain};
            iptables -t mangle -F ${output_chain};
            iptables -t mangle -X ${output_chain};
        }?;

        if p.override_dns.is_some() {
            cmd_lib::run_cmd! {
                iptables -t nat -D OUTPUT -j ${output_chain};
                iptables -t nat -F ${output_chain};
                iptables -t nat -X ${output_chain};
            }?;
        }
        Ok(())
    }

    fn setup_trace(&self, p: &TraceParams) -> Result<()> {
        let output_chain = p.output_chain_name.as_str();
        // Preserve historical behaviour: trace mode always matches by numeric
        // classid regardless of cgroup hierarchy. CGroupGuard synthesizes a
        // classid even under v2, so this mirrors the pre-refactor logic 1:1.
        let class_id = p.cgroup.class_id;
        cmd_lib::run_cmd! {
            iptables -t raw -N ${output_chain};
            iptables -t raw -A OUTPUT -j ${output_chain};
            iptables -t raw -A ${output_chain} -m cgroup --cgroup ${class_id} -p tcp -j LOG;
            iptables -t raw -A ${output_chain} -m cgroup --cgroup ${class_id} -p udp -j LOG;
        }?;
        Ok(())
    }

    fn teardown_trace(&self, p: &TraceParams) -> Result<()> {
        let output_chain = p.output_chain_name.as_str();
        cmd_lib::run_cmd! {
            iptables -t raw -D OUTPUT -j ${output_chain};
            iptables -t raw -F ${output_chain};
            iptables -t raw -X ${output_chain};
        }?;
        Ok(())
    }
}
