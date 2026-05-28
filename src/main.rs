#![allow(dyn_drop)]

use crate::bridge::BridgeGuard;
use crate::config::{ChildCommand, Cli, Mode, BRIDGE_MARK};
use crate::firewall::{select_backend, FirewallBackend};
use crate::guards::TraceGuard;
use crate::upstream::UpstreamConfig;
use eyre::Result;
use guards::{CGroupGuard, RedirectGuard, TProxyGuard};
use std::os::unix::prelude::CommandExt;
use std::process::ExitStatus;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use structopt::StructOpt;

mod bridge;
mod config;
mod firewall;
mod guards;
mod upstream;

/// Build the firewall guard for the chosen mode. When an upstream is supplied
/// `--mode redirect` also enables a SO_MARK exemption so the bridge's outbound
/// connection bypasses the redirect rule.
fn build_guard(
    backend: Arc<dyn FirewallBackend>,
    mode: Mode,
    args: &Cli,
    listen_port: u32,
    cgroup_guard: CGroupGuard,
    id_for_chain: u32,
    bridge_mark_exempt: Option<u32>,
) -> Result<Box<dyn Drop>> {
    match mode {
        Mode::Redirect => {
            let output_chain_name = format!("cp_rd_out_{}", id_for_chain);
            Ok(Box::new(RedirectGuard::new(
                backend,
                listen_port,
                output_chain_name.as_str(),
                cgroup_guard,
                args.redirect_dns,
                bridge_mark_exempt,
            )?))
        }
        Mode::Tproxy => {
            let output_chain_name = format!("cp_tp_out_{}", id_for_chain);
            let prerouting_chain_name = format!("cp_tp_pre_{}", id_for_chain);
            let mark = id_for_chain;
            Ok(Box::new(TProxyGuard::new(
                backend,
                listen_port,
                mark,
                output_chain_name.as_str(),
                prerouting_chain_name.as_str(),
                cgroup_guard,
                args.override_dns.clone(),
            )?))
        }
        Mode::Trace => {
            let prerouting_chain_name = format!("cp_tr_pre_{}", id_for_chain);
            let output_chain_name = format!("cp_tr_out_{}", id_for_chain);
            Ok(Box::new(TraceGuard::new(
                backend,
                output_chain_name.as_str(),
                prerouting_chain_name.as_str(),
                cgroup_guard,
            )?))
        }
    }
}

/// Spin up the optional internal bridge (`--upstream`). Returns `None` when no
/// upstream was requested.
fn maybe_start_bridge(args: &Cli) -> Result<Option<BridgeGuard>> {
    let url = match &args.upstream {
        Some(u) => u,
        None => return Ok(None),
    };
    let upstream = UpstreamConfig::parse(url)?;
    let port = args.requested_listen_port()?;
    let guard = BridgeGuard::spawn(port, upstream, BRIDGE_MARK)?;
    Ok(Some(guard))
}

fn listen_port_for_firewall(args: &Cli, bridge_guard: Option<&BridgeGuard>) -> Result<u32> {
    match bridge_guard {
        Some(bridge_guard) => Ok(u32::from(bridge_guard.listen_port())),
        None => Ok(u32::from(args.requested_listen_port()?)),
    }
}

fn redirect_bridge_mark(args: &Cli) -> Option<u32> {
    if args.upstream.is_some() {
        Some(BRIDGE_MARK)
    } else {
        None
    }
}

fn proxy_new_command(args: &Cli) -> Result<ExitStatus> {
    let pid = std::process::id();
    let ChildCommand::Command(child_command) = &args
        .command
        .as_ref()
        .expect("must have command specified if --pid not provided");
    tracing::info!("subcommand {:?}", child_command);

    let mode = args.mode_enum()?;

    // Bridge first so the firewall rules below land on a port that's already
    // listening; otherwise the very first redirected connection could race
    // with bind(2).
    let bridge_guard = maybe_start_bridge(args)?;
    let listen_port = listen_port_for_firewall(args, bridge_guard.as_ref())?;

    let cgroup_guard = CGroupGuard::new(pid)?;
    let backend = select_backend(args.firewall_choice()?, cgroup_guard.hier_v2)?;
    let _guard = build_guard(
        backend,
        mode,
        args,
        listen_port,
        cgroup_guard,
        pid,
        redirect_bridge_mark(args),
    )?;

    let sudo_uid = std::env::var("SUDO_UID").ok();
    let sudo_gid = std::env::var("SUDO_GID").ok();
    let sudo_home = std::env::var("SUDO_HOME").ok();

    let original_uid = nix::unistd::getuid();
    let original_gid = nix::unistd::getgid();
    let mut command = std::process::Command::new(&child_command[0]);
    if let Some(sudo_uid) = sudo_uid {
        command.uid(sudo_uid.parse().expect("invalid uid"));
    }
    if let Some(sudo_gid) = sudo_gid {
        command.gid(sudo_gid.parse().expect("invalid gid"));
    }
    command.env("CPROXY_ENV", format!("cproxy/{}", listen_port));
    if let Some(sudo_home) = sudo_home {
        command.env("HOME", sudo_home);
    }
    let mut child = command.args(&child_command[1..]).spawn()?;
    // The child program was already configured to run as the invoking user
    // via `command.uid()/gid()`, so historically we also dropped the parent
    // process' euid here as defense-in-depth. With `--upstream` that is
    // actively wrong: the in-process bridge runs under the parent and calls
    // `setsockopt(SO_MARK)` for every upstream connection, which requires
    // CAP_NET_ADMIN. glibc's NPTL synchronises `seteuid` across all threads,
    // so dropping the parent here would also strip the bridge worker
    // threads of the capability and every redirected connection would fail
    // with EPERM at the first SO_MARK call. Keep the parent privileged in
    // upstream mode; the child still ran as the invoking user.
    if args.upstream.is_none() {
        nix::unistd::seteuid(original_uid)?;
        nix::unistd::setegid(original_gid)?;
    } else {
        tracing::debug!(
            "keeping parent euid=root for the duration of the bridge (--upstream is set)"
        );
    }

    ctrlc::set_handler(move || {
        println!("received ctrl-c, terminating...");
    })?;

    let exit_status = child.wait()?;
    Ok(exit_status)
}

fn proxy_existing_pid(pid: u32, args: &Cli) -> Result<()> {
    let mode = args.mode_enum()?;

    let bridge_guard = maybe_start_bridge(args)?;
    let listen_port = listen_port_for_firewall(args, bridge_guard.as_ref())?;

    let cgroup_guard = CGroupGuard::new(pid)?;
    let backend = select_backend(args.firewall_choice()?, cgroup_guard.hier_v2)?;
    let _guard = build_guard(
        backend,
        mode,
        args,
        listen_port,
        cgroup_guard,
        pid,
        redirect_bridge_mark(args),
    )?;

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    ctrlc::set_handler(move || {
        println!("received ctrl-c, terminating...");
        r.store(false, Ordering::SeqCst);
    })?;

    while running.load(Ordering::SeqCst) {
        std::thread::sleep(Duration::from_millis(100));
    }

    Ok(())
}

fn proxy_cgroup_paths(paths: Vec<String>, args: &Cli) -> Result<()> {
    let mode = args.mode_enum()?;

    let bridge_guard = maybe_start_bridge(args)?;
    let listen_port = listen_port_for_firewall(args, bridge_guard.as_ref())?;

    let mut guards: Vec<Box<dyn Drop>> = Vec::new();
    let mut shared_backend: Option<Arc<dyn FirewallBackend>> = None;

    for path in paths {
        let cgroup_guard = CGroupGuard::from_path(&path)?;
        let backend = if let Some(b) = &shared_backend {
            b.clone()
        } else {
            let b = select_backend(args.firewall_choice()?, cgroup_guard.hier_v2)?;
            shared_backend = Some(b.clone());
            b
        };
        let id_for_chain = cgroup_guard.class_id;
        let guard = build_guard(
            backend,
            mode,
            args,
            listen_port,
            cgroup_guard,
            id_for_chain,
            redirect_bridge_mark(args),
        )?;
        guards.push(guard);
    }

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    ctrlc::set_handler(move || {
        println!("received ctrl-c, terminating...");
        r.store(false, Ordering::SeqCst);
    })?;

    while running.load(Ordering::SeqCst) {
        std::thread::sleep(Duration::from_millis(100));
    }

    Ok(())
}

fn main() -> Result<()> {
    color_eyre::install()?;
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    nix::unistd::seteuid(nix::unistd::Uid::from_raw(0))
        .expect("cproxy failed to seteuid, please run as root");
    nix::unistd::setegid(nix::unistd::Gid::from_raw(0))
        .expect("cproxy failed to seteuid, please run as root");
    let args: Cli = Cli::from_args();
    args.validate()?;

    if args.cgroup_path.len() > 0 {
        proxy_cgroup_paths(args.cgroup_path.clone(), &args)?;
    } else {
        match args.pid {
            None => {
                let exit_status = proxy_new_command(&args)?;
                std::process::exit(exit_status.code().unwrap_or(1));
            }
            Some(existing_pid) => {
                proxy_existing_pid(existing_pid, &args)?;
            }
        }
    }

    Ok(())
}
