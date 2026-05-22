use crate::firewall::{CgroupMatch, FirewallBackend, RedirectParams, TProxyParams, TraceParams};
use cgroups_rs::cgroup_builder::CgroupBuilder;
use cgroups_rs::{Cgroup, CgroupPid};
use eyre::Result;
use std::sync::Arc;
use std::time::Duration;

#[allow(unused)]
pub struct CGroupGuard {
    pub pid: Option<u32>,
    pub cg: Cgroup,
    pub cg_path: String,
    pub class_id: u32,
    pub hier_v2: bool,
}

impl CGroupGuard {
    pub fn new(pid: u32) -> Result<Self> {
        let hier = cgroups_rs::hierarchies::auto();
        let hier_v2 = hier.v2();
        let class_id = pid;
        let cg_path = format!("cproxy-{}", pid);
        let cg: Cgroup = CgroupBuilder::new(cg_path.as_str())
            .network()
            .class_id(class_id as u64)
            .done()
            .build(hier)?;
        cg.add_task_by_tgid(CgroupPid::from(pid as u64))
            .expect("add task failed");
        Ok(Self {
            pid: Some(pid),
            hier_v2,
            cg,
            cg_path,
            class_id,
        })
    }

    pub fn from_path(path: &str) -> Result<Self> {
        let hier = cgroups_rs::hierarchies::auto();
        let hier_v2 = hier.v2();
        let class_id = {
            use std::hash::{Hash, Hasher};
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            path.hash(&mut hasher);
            hasher.finish() as u32
        };

        let cg = CgroupBuilder::new(path)
            .network()
            .class_id(class_id as u64)
            .done()
            .build(hier)?;

        Ok(Self {
            pid: None,
            hier_v2,
            cg,
            cg_path: path.to_string(),
            class_id,
        })
    }

    /// Build a `CgroupMatch` suitable for handing to a firewall backend.
    pub fn to_match(&self) -> CgroupMatch {
        CgroupMatch {
            class_id: self.class_id,
            v2_path: if self.hier_v2 {
                Some(self.cg_path.clone())
            } else {
                None
            },
        }
    }
}

impl Drop for CGroupGuard {
    fn drop(&mut self) {
        for t in self.cg.procs() {
            let t_dbg_string = format!("{:?}", t);
            if let Err(e) = self.cg.remove_task_by_tgid(t) {
                tracing::error!(
                    "failed to remove process from cgroup. pid: {}. error: {}",
                    t_dbg_string,
                    e
                );
            }
        }
        if let Err(e) = self.cg.delete() {
            tracing::warn!("failed to delete cgroup. error: {}", e)
        }
    }
}

#[allow(unused)]
pub struct RedirectGuard {
    backend: Arc<dyn FirewallBackend>,
    params: RedirectParams,
    cgroup_guard: CGroupGuard,
}

impl RedirectGuard {
    pub fn new(
        backend: Arc<dyn FirewallBackend>,
        port: u32,
        output_chain_name: &str,
        cgroup_guard: CGroupGuard,
        redirect_dns: bool,
        bridge_mark_exempt: Option<u32>,
    ) -> Result<Self> {
        tracing::debug!(
            "creating redirect guard on port {}, with redirect_dns: {}, backend: {}",
            port,
            redirect_dns,
            backend.name()
        );
        let params = RedirectParams {
            chain_name: output_chain_name.to_owned(),
            listen_port: port,
            cgroup: cgroup_guard.to_match(),
            redirect_dns,
            bridge_mark_exempt,
        };
        backend.setup_redirect(&params)?;
        Ok(Self {
            backend,
            params,
            cgroup_guard,
        })
    }
}

impl Drop for RedirectGuard {
    fn drop(&mut self) {
        if let Err(e) = self.backend.teardown_redirect(&self.params) {
            tracing::error!("failed to tear down redirect rules: {}", e);
        }
    }
}

pub struct IpRuleGuardInner {
    fwmark: u32,
    table: u32,
    guard_thread: std::thread::JoinHandle<()>,
    stop_channel: flume::Sender<()>,
}

#[allow(unused)]
pub struct IpRuleGuard {
    inner: Box<dyn Drop>,
}

impl IpRuleGuard {
    pub fn new(fwmark: u32, table: u32) -> Self {
        let (sender, receiver) = flume::unbounded();
        let thread = std::thread::spawn(move || {
            (cmd_lib::run_cmd! {
              ip rule add fwmark ${fwmark} table ${table};
              ip route add local 0.0.0.0/0 dev lo table ${table};
            })
            .expect("set routing rules failed");
            loop {
                if (cmd_lib::run_fun! { ip rule list fwmark ${fwmark} })
                    .expect("get routing rules failed")
                    .is_empty()
                {
                    tracing::warn!("detected disappearing routing policy, possibly due to interruped network, resetting");
                    (cmd_lib::run_cmd! {
                      ip rule add fwmark ${fwmark} table ${table};
                    })
                    .expect("set routing rules failed");
                }
                if receiver.recv_timeout(Duration::from_secs(1)).is_ok() {
                    break;
                }
            }
        });
        let inner = IpRuleGuardInner {
            fwmark,
            table,
            guard_thread: thread,
            stop_channel: sender,
        };
        let inner = with_drop::with_drop(inner, |x| {
            x.stop_channel.send(()).unwrap();
            x.guard_thread.join().unwrap();
            let mark = x.fwmark;
            let table = x.table;
            (cmd_lib::run_cmd! {
                ip rule delete fwmark ${mark} table ${table};
                ip route delete local 0.0.0.0/0 dev lo table ${table};
            })
            .expect("drop routing rules failed");
        });
        Self {
            inner: Box::new(inner),
        }
    }
}

#[allow(unused)]
pub struct TProxyGuard {
    backend: Arc<dyn FirewallBackend>,
    params: TProxyParams,
    iprule_guard: IpRuleGuard,
    cgroup_guard: CGroupGuard,
}

impl TProxyGuard {
    pub fn new(
        backend: Arc<dyn FirewallBackend>,
        port: u32,
        mark: u32,
        output_chain_name: &str,
        prerouting_chain_name: &str,
        cgroup_guard: CGroupGuard,
        override_dns: Option<String>,
    ) -> Result<Self> {
        tracing::debug!(
            "creating tproxy guard on port {}, with override_dns: {:?}, backend: {}",
            port,
            override_dns,
            backend.name()
        );
        let iprule_guard = IpRuleGuard::new(mark, mark);
        let params = TProxyParams {
            output_chain_name: output_chain_name.to_owned(),
            prerouting_chain_name: prerouting_chain_name.to_owned(),
            listen_port: port,
            mark,
            cgroup: cgroup_guard.to_match(),
            override_dns,
        };
        backend.setup_tproxy(&params)?;
        Ok(Self {
            backend,
            params,
            iprule_guard,
            cgroup_guard,
        })
    }
}

impl Drop for TProxyGuard {
    fn drop(&mut self) {
        std::thread::sleep(Duration::from_millis(100));
        if let Err(e) = self.backend.teardown_tproxy(&self.params) {
            tracing::error!("failed to tear down tproxy rules: {}", e);
        }
    }
}

#[allow(unused)]
pub struct TraceGuard {
    backend: Arc<dyn FirewallBackend>,
    params: TraceParams,
    cgroup_guard: CGroupGuard,
}

impl TraceGuard {
    pub fn new(
        backend: Arc<dyn FirewallBackend>,
        output_chain_name: &str,
        prerouting_chain_name: &str,
        cgroup_guard: CGroupGuard,
    ) -> Result<Self> {
        let params = TraceParams {
            output_chain_name: output_chain_name.to_owned(),
            prerouting_chain_name: prerouting_chain_name.to_owned(),
            cgroup: cgroup_guard.to_match(),
        };
        backend.setup_trace(&params)?;
        Ok(Self {
            backend,
            params,
            cgroup_guard,
        })
    }
}

impl Drop for TraceGuard {
    fn drop(&mut self) {
        std::thread::sleep(Duration::from_millis(100));
        if let Err(e) = self.backend.teardown_trace(&self.params) {
            tracing::error!("failed to tear down trace rules: {}", e);
        }
    }
}
