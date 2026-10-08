use crate::firewall::{CgroupMatch, FirewallBackend, RedirectParams, TProxyParams, TraceParams};
use cgroups_rs::fs::cgroup::get_cgroups_relative_paths_by_pid;
use cgroups_rs::fs::cgroup_builder::CgroupBuilder;
use cgroups_rs::fs::{hierarchies, Cgroup, Hierarchy};
use cgroups_rs::CgroupPid;
use eyre::{eyre, Result};
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
        let hier = hierarchies::auto();
        let hier_v2 = hier.v2();
        let class_id = pid;
        let cg_path = if hier_v2 {
            let paths = get_cgroups_relative_paths_by_pid(pid)?;
            let parent = paths
                .get("")
                .ok_or_else(|| eyre!("no cgroup v2 membership found for pid {}", pid))?
                .trim_start_matches('/');
            if parent.is_empty() {
                format!("cproxy-{}", pid)
            } else {
                format!("{}/cproxy-{}", parent, pid)
            }
        } else {
            format!("cproxy-{}", pid)
        };
        let cg = Self::create_cgroup(hier, &cg_path, class_id)?;
        let guard = Self {
            pid: Some(pid),
            hier_v2,
            cg,
            cg_path,
            class_id,
        };
        guard.cg.add_task_by_tgid(CgroupPid::from(pid as u64))?;
        Ok(guard)
    }

    pub fn from_path(path: &str) -> Result<Self> {
        let hier = hierarchies::auto();
        let hier_v2 = hier.v2();
        let class_id = {
            use std::hash::{Hash, Hasher};
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            path.hash(&mut hasher);
            hasher.finish() as u32
        };

        let cg = Self::create_cgroup(hier, path, class_id)?;

        Ok(Self {
            pid: None,
            hier_v2,
            cg,
            cg_path: path.to_string(),
            class_id,
        })
    }

    fn create_cgroup(hier: Box<dyn Hierarchy>, path: &str, class_id: u32) -> Result<Cgroup> {
        if hier.v2() {
            // v2 packet matching needs only membership, not resource controllers.
            std::fs::create_dir_all(hier.root().join(path))?;
            let cg = Cgroup::load(hier, path);
            let parent = cg.parent_control_group();
            // The hierarchy root has no cgroup.type and can host domain children.
            if !parent.path().is_empty() {
                let parent_type = parent.get_cgroup_type()?;
                if parent_type == "domain threaded" || parent_type == "threaded" {
                    cg.set_cgroup_type("threaded")?;
                }
            }
            Ok(cg)
        } else {
            Ok(CgroupBuilder::new(path)
                .network()
                .class_id(class_id as u64)
                .done()
                .build(hier)?)
        }
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
        let tasks = if self.hier_v2 && self.cg.get_cgroup_type().ok().as_deref() == Some("threaded")
        {
            self.cg.tasks()
        } else {
            self.cg.procs()
        };
        for t in tasks {
            let t_dbg_string = format!("{:?}", t);
            if let Err(e) = self.cg.move_task_to_parent_by_tgid(t) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use cgroups_rs::fs::{cpu::CpuController, Subsystem};
    use std::path::{Path, PathBuf};

    #[derive(Debug)]
    struct TestRoot {
        path: PathBuf,
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.path).expect("remove test cgroup directory");
        }
    }

    #[derive(Debug, Clone)]
    struct TestHierarchy {
        root: Arc<TestRoot>,
    }

    impl TestHierarchy {
        fn new() -> Self {
            let nonce = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "cproxy-cgroup-test-{}-{}",
                std::process::id(),
                nonce
            ));
            std::fs::create_dir(&path).unwrap();
            Self {
                root: Arc::new(TestRoot { path }),
            }
        }
    }

    impl Hierarchy for TestHierarchy {
        fn v2(&self) -> bool {
            true
        }

        fn root(&self) -> PathBuf {
            self.root.path.clone()
        }

        fn subsystems(&self) -> Vec<Subsystem> {
            vec![Subsystem::Cpu(CpuController::new(
                self.root(),
                PathBuf::new(),
                true,
            ))]
        }

        fn root_control_group(&self) -> Cgroup {
            Cgroup::load(Box::new(self.clone()), "")
        }

        fn parent_control_group(&self, path: &str) -> Cgroup {
            Cgroup::load(Box::new(self.clone()), Path::new(path).parent().unwrap())
        }
    }

    #[test]
    fn creates_cgroup_under_root_without_cgroup_type() {
        let hier = TestHierarchy::new();
        assert!(!hier.root().join("cgroup.type").exists());
        let cg = CGroupGuard::create_cgroup(Box::new(hier.clone()), "proxy", 1).unwrap();
        assert_eq!(cg.path(), "proxy");
        assert!(hier.root().join("proxy").is_dir());
        assert!(!hier.root().join("proxy/cgroup.type").exists());
    }

    #[test]
    fn preserves_nested_parent_type_handling() {
        for parent_type in ["domain", "threaded", "domain threaded"] {
            let hier = TestHierarchy::new();
            let parent = hier.root().join("parent");
            std::fs::create_dir(&parent).unwrap();
            std::fs::write(parent.join("cgroup.type"), format!("{}\n", parent_type)).unwrap();
            let _cg =
                CGroupGuard::create_cgroup(Box::new(hier.clone()), "parent/proxy", 1).unwrap();
            let child_type = parent.join("proxy/cgroup.type");
            if parent_type == "domain" {
                assert!(!child_type.exists());
            } else {
                assert_eq!(std::fs::read_to_string(child_type).unwrap(), "threaded");
            }
        }
    }

    #[test]
    fn missing_non_root_parent_type_returns_error() {
        let hier = TestHierarchy::new();
        let expected_path = hier.root().join("parent/cgroup.type");
        let error = CGroupGuard::create_cgroup(Box::new(hier), "parent/proxy", 1).unwrap_err();
        assert!(error.to_string().contains(expected_path.to_str().unwrap()));
        assert!(error.chain().any(|cause| {
            cause
                .downcast_ref::<std::io::Error>()
                .map_or(false, |error| error.kind() == std::io::ErrorKind::NotFound)
        }));
    }

    #[test]
    fn threaded_type_write_failure_returns_error() {
        let hier = TestHierarchy::new();
        let parent = hier.root().join("parent");
        std::fs::create_dir_all(parent.join("proxy/cgroup.type")).unwrap();
        std::fs::write(parent.join("cgroup.type"), "threaded\n").unwrap();
        assert!(CGroupGuard::create_cgroup(Box::new(hier), "parent/proxy", 1).is_err());
    }

    #[test]
    fn missing_pid_returns_error() {
        if hierarchies::auto().v2() {
            assert!(CGroupGuard::new(u32::MAX).is_err());
        }
    }

    #[test]
    #[ignore = "requires root and a writable cgroup v2 hierarchy"]
    fn restores_process_membership_on_drop() {
        assert!(hierarchies::auto().v2());
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let result = (|| -> Result<()> {
            let original = get_cgroups_relative_paths_by_pid(child.id())?;
            let guard = CGroupGuard::new(child.id())?;
            let cg = guard.cg.clone();
            assert_ne!(get_cgroups_relative_paths_by_pid(child.id())?, original);
            drop(guard);
            assert_eq!(get_cgroups_relative_paths_by_pid(child.id())?, original);
            assert!(!cg.exists());
            Ok(())
        })();
        let _ = child.kill();
        let _ = child.wait();
        result.unwrap();
    }
}
