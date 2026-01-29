use aya::maps::{Array, HashMap, RingBuf};
use aya::programs::{CgroupSockAddr, Lsm, SchedClassifier, TcAttachType, Xdp, XdpFlags};
use aya::{Bpf, BpfLoader, Btf};
use clap::Parser;
use ebpf_common::{
    Action, EventType, FileRule, Mode, NetDirection, PacketModRule, PktModKey, PktModValue,
    ProcessRule, RuleEntry, UnifiedEvent,
};
use log::{error, info, warn};
use serde::{Deserialize, Serialize};
use std::fs;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::signal;

struct SysctlState {
    accept_local_iface_original: Option<String>,
    accept_local_all_original: Option<String>,
    ip_forward_original: Option<String>,
    interface: String,
}

#[derive(Parser, Debug)]
#[command(name = "unified-agent")]
struct Args {
    /// Path to the unified configuration file (JSON)
    #[arg(short, long)]
    config: PathBuf,

    /// Path to the BPF object file
    #[arg(short, long, default_value = "bpf/unified_agent.bpf.o")]
    bpf_obj: PathBuf,

    /// Cgroup path to attach to (default: /sys/fs/cgroup)
    #[arg(long, default_value = "/sys/fs/cgroup")]
    cgroup: PathBuf,
}

#[derive(Debug, Serialize, Deserialize)]
struct UnifiedConfig {
    pub file_mode: Option<Mode>,
    pub process_mode: Option<Mode>,
    pub network_mode: Option<Mode>,
    #[serde(default)]
    pub file_rules: Vec<FileRule>,
    #[serde(default)]
    pub process_rules: Vec<ProcessRule>,
    #[serde(default)]
    pub network: NetworkConfig,
}

fn default_mode() -> Mode {
    Mode::Monitor
}

#[derive(Debug, Serialize, Deserialize, Default)]
struct NetworkConfig {
    pub enabled: bool,
    pub engine: String, // "tc" or "xdp"
    pub interface: String,
    #[serde(default)]
    pub block_ports: Vec<u16>,
    #[serde(default)]
    pub mod_rules: Vec<PacketModRuleConfig>,
    #[serde(default)]
    pub forward_rules: Vec<ForwardRuleConfig>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ForwardRuleConfig {
    pub listen_port: Vec<serde_json::Value>,
    pub target_host: String,
    pub target_port: u16,
    pub protocol: String,
    #[serde(default)]
    pub allowed_sources: Vec<String>,
}

impl ForwardRuleConfig {
    fn expand_ports(&self) -> Vec<u16> {
        let mut ports = Vec::new();
        for port_val in &self.listen_port {
            if let Some(port) = port_val.as_u64() {
                ports.push(port as u16);
            } else if let Some(range) = port_val.as_str() {
                let parts: Vec<&str> = range.split('-').collect();
                if parts.len() == 2 {
                    if let (Ok(start), Ok(end)) = (parts[0].parse::<u16>(), parts[1].parse::<u16>())
                    {
                        for p in start..=end {
                            ports.push(p);
                        }
                    }
                }
            }
        }
        ports
    }
}

fn parse_cidr(cidr: &str) -> anyhow::Result<(u32, u32)> {
    if let Some(pos) = cidr.find('/') {
        let ip_str = &cidr[..pos];
        let prefix_str = &cidr[pos + 1..];
        let ip: Ipv4Addr = ip_str.parse()?;
        let prefix: u32 = prefix_str.parse()?;
        let mask = if prefix == 0 {
            0
        } else {
            !0u32 << (32 - prefix)
        };
        Ok((u32::from(ip).to_be(), mask.to_be()))
    } else if let Some(pos) = cidr.find('-') {
        // Simple range support: 192.168.1.1-192.168.1.10 -> convert to /32 of first IP for now
        // Or just handle as exact IP if no range.
        // Real range support in BPF would need multiple rules.
        let start_ip: Ipv4Addr = cidr[..pos].parse()?;
        Ok((u32::from(start_ip).to_be(), u32::MAX.to_be()))
    } else {
        let ip: Ipv4Addr = cidr.parse()?;
        Ok((u32::from(ip).to_be(), u32::MAX.to_be()))
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct PacketModRuleConfig {
    pub match_rule: PacketMatchConfig,
    pub modification: ebpf_common::PacketMod,
}

#[derive(Debug, Serialize, Deserialize)]
struct PacketMatchConfig {
    pub protocol: String,
    #[serde(default)]
    pub direction: NetDirection,
    pub src_port: u16,
    pub dst_port: serde_json::Value, // Can be u16 or "2000-2010"
    pub dst_ip: [u8; 4],
}

impl PacketMatchConfig {
    fn expand_dst_ports(&self) -> Vec<u16> {
        if let Some(port) = self.dst_port.as_u64() {
            vec![port as u16]
        } else if let Some(range) = self.dst_port.as_str() {
            let parts: Vec<&str> = range.split('-').collect();
            if parts.len() == 2 {
                if let (Ok(start), Ok(end)) = (parts[0].parse::<u16>(), parts[1].parse::<u16>()) {
                    return (start..=end).collect();
                }
            }
            vec![]
        } else {
            vec![]
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "info");
    }
    env_logger::init();
    let args = Args::parse();

    info!("Starting unified-agent...");
    println!(
        "Starting unified-agent with config: {}",
        args.config.display()
    );

    // 1. Load config
    let config_str = fs::read_to_string(&args.config)?;
    let config: UnifiedConfig = serde_json::from_str(&config_str)?;
    info!(
        "Loaded unified configuration from {}",
        args.config.display()
    );

    // Setup cleanup state tracking
    let tc_cleanup = Arc::new(TcCleanupState::new());
    let tc_cleanup_clone = tc_cleanup.clone();
    let interface = config.network.interface.clone();
    let engine = config.network.engine.clone();
    let network_enabled = config.network.enabled;

    // Setup system configuration
    let sysctl_state = if network_enabled {
        Some(Arc::new(setup_sysctl(&interface)?))
    } else {
        None
    };
    let sysctl_state_clone = sysctl_state.clone();

    // Setup Ctrl+C handler
    tokio::spawn(async move {
        signal::ctrl_c().await.expect("Failed to listen for Ctrl+C");
        info!("Received Ctrl+C, cleaning up...");
        cleanup_network(&interface, &engine, network_enabled, &tc_cleanup_clone);
        if let Some(ref sysctl) = sysctl_state_clone {
            restore_sysctl(sysctl);
        }
        std::process::exit(0);
    });

    // 2. Load BPF
    let mut bpf = BpfLoader::default()
        .allow_unsupported_maps()
        .load_file(&args.bpf_obj)?;
    info!("Loaded BPF object: {}", args.bpf_obj.display());

    // 3. Populate Maps
    populate_maps(&mut bpf, &config)?;

    // 4. Attach Hooks
    attach_hooks(&mut bpf, &config, &args.cgroup, &tc_cleanup)?;

    // 5. Process Events
    info!("Agent is running. Press Ctrl+C to stop.");
    let mut ringbuf = RingBuf::try_from(bpf.map_mut("event_ringbuf").unwrap())?;

    loop {
        while let Some(item) = ringbuf.next() {
            let event: UnifiedEvent = unsafe { std::ptr::read(item.as_ptr() as *const _) };
            handle_event(&event);
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
}

fn populate_maps(bpf: &mut Bpf, config: &UnifiedConfig) -> anyhow::Result<()> {
    // File and Process rules
    let mut pattern_rules: HashMap<_, [u8; 32], RuleEntry> =
        HashMap::try_from(bpf.map_mut("pattern_rules").unwrap())?;

    for rule in &config.file_rules {
        let mut key = [0u8; 32];
        let bytes = rule.path_prefix.as_bytes();
        let len = bytes.len().min(31);
        key[..len].copy_from_slice(&bytes[..len]);

        let effective_mode = rule.mode.or(config.file_mode).unwrap_or(Mode::Monitor);

        let mut ops_mask = 0u8;
        for op in &rule.operations {
            ops_mask |= 1 << (*op as u8);
        }

        pattern_rules.insert(
            key,
            RuleEntry {
                action: rule.action as u8,
                event_type: 1,
                mode: effective_mode as u8,
                ops_mask,
                padding: [0; 4],
            },
            0,
        )?;
    }

    for rule in &config.process_rules {
        let mut key = [0u8; 32];
        let bytes = rule.comm.as_bytes();
        let len = bytes.len().min(31);
        key[..len].copy_from_slice(&bytes[..len]);

        let effective_mode = rule.mode.or(config.process_mode).unwrap_or(Mode::Monitor);

        pattern_rules.insert(
            key,
            RuleEntry {
                action: rule.action as u8,
                event_type: 2,
                mode: effective_mode as u8,
                ops_mask: 0, // Not used for process rules
                padding: [0; 4],
            },
            0,
        )?;
    }

    // Network blocking
    let mut block_rules: HashMap<_, u16, u8> =
        HashMap::try_from(bpf.map_mut("block_rules").unwrap())?;
    for &port in &config.network.block_ports {
        block_rules.insert(port, 1, 0)?;
    }

    // Network modification rules
    let mut pkt_mod_rules: HashMap<_, PktModKey, PktModValue> =
        HashMap::try_from(bpf.map_mut("pkt_mod_rules").unwrap())?;

    // Process old style mod_rules if any
    for rule in &config.network.mod_rules {
        for expanded_dst_port in rule.match_rule.expand_dst_ports() {
            let key = PktModKey {
                protocol: match rule.match_rule.protocol.as_str() {
                    "tcp" => 6,
                    "udp" => 17,
                    _ => 0,
                },
                direction: match rule.match_rule.direction {
                    NetDirection::Any => 0,
                    NetDirection::Ingress => 1,
                    NetDirection::Egress => 2,
                },
                padding: [0; 2],
                dst_ip: u32::from_be_bytes(rule.match_rule.dst_ip).to_be(),
                src_port: rule.match_rule.src_port.to_be(),
                dst_port: expanded_dst_port.to_be(),
            };

            let mut val = PktModValue {
                tcp_flags_enable: 0,
                tcp_set_ecn_echo: 0,
                tcp_set_cwr: 0,
                tcp_set_reserved: 0,
                tcp_flags_mask: 0,
                tcp_flags_value: 0,
                reserved_bits_mask: 0,
                reserved_bits_value: 0,
                port_mod_enable: 0,
                new_src_port: 0,
                new_dst_port: 0,
                ip_mod_enable: 0,
                new_src_ip: 0,
                new_dst_ip: 0,
                allowed_ip: 0,
                allowed_mask: 0,
                padding: [0; 3],
            };

            if let Some(m) = &rule.modification.tcp_flags {
                val.tcp_flags_enable = 1;
                if m.set_ecn_echo.unwrap_or(false) {
                    val.tcp_set_ecn_echo = 1;
                }
                if m.set_cwr.unwrap_or(false) {
                    val.tcp_set_cwr = 1;
                }
                if m.set_reserved_bits.unwrap_or(false) {
                    val.tcp_set_reserved = 1;
                }
                val.tcp_flags_mask = m.flags_mask.unwrap_or(0);
                val.tcp_flags_value = m.flags_value.unwrap_or(0);
                val.reserved_bits_mask = m.reserved_bits_mask.unwrap_or(0);
                val.reserved_bits_value = m.reserved_bits_value.unwrap_or(0);
            }

            if let Some(m) = &rule.modification.port_mod {
                val.port_mod_enable = 1;
                val.new_src_port = m.new_src_port.unwrap_or(0).to_be();
                val.new_dst_port = m.new_dst_port.unwrap_or(0).to_be();
            }

            if let Some(m) = &rule.modification.ip_mod {
                val.ip_mod_enable = 1;
                if let Some(ip) = m.new_src_ip {
                    val.new_src_ip = u32::from(Ipv4Addr::from(ip)).to_be();
                }
                if let Some(ip) = m.new_dst_ip {
                    val.new_dst_ip = u32::from(Ipv4Addr::from(ip)).to_be();
                }
            }

            pkt_mod_rules.insert(key, val, 0)?;
        }
    }

    // Process new style forward_rules
    for rule in &config.network.forward_rules {
        let target_ip: Ipv4Addr = rule.target_host.parse().unwrap_or(Ipv4Addr::UNSPECIFIED);

        // Handle allowed sources
        let sources = if rule.allowed_sources.is_empty() {
            vec!["0.0.0.0/0".to_string()]
        } else {
            rule.allowed_sources.clone()
        };

        for source in sources {
            let (allowed_ip, allowed_mask) = parse_cidr(&source)?;

            for port in rule.expand_ports() {
                let key = PktModKey {
                    protocol: match rule.protocol.as_str() {
                        "tcp" => 6,
                        "udp" => 17,
                        _ => 6,
                    },
                    direction: 1, // Ingress
                    padding: [0; 2],
                    dst_ip: 0,   // Any local IP
                    src_port: 0, // Any source port
                    dst_port: port.to_be(),
                };

                let val = PktModValue {
                    tcp_flags_enable: 0,
                    tcp_set_ecn_echo: 0,
                    tcp_set_cwr: 0,
                    tcp_set_reserved: 0,
                    tcp_flags_mask: 0,
                    tcp_flags_value: 0,
                    reserved_bits_mask: 0,
                    reserved_bits_value: 0,
                    port_mod_enable: 1,
                    new_src_port: 0,
                    new_dst_port: rule.target_port.to_be(),
                    ip_mod_enable: 1,
                    new_src_ip: 0,
                    new_dst_ip: u32::from(target_ip).to_be(),
                    allowed_ip,
                    allowed_mask,
                    padding: [0; 3],
                };

                // Note: Multiple sources for the same port will overwrite in this hash map
                // because the key is only (proto, dir, dst_ip, src_port, dst_port).
                // To support multiple sources, we would need to include src_ip in the key.
                pkt_mod_rules.insert(key, val, 0)?;
            }
        }
    }

    Ok(())
}

struct TcCleanupState {
    clsact_existed: AtomicBool,
    tc_attached: AtomicBool,
}

impl TcCleanupState {
    fn new() -> Self {
        Self {
            clsact_existed: AtomicBool::new(false),
            tc_attached: AtomicBool::new(false),
        }
    }
}

fn check_clsact_exists(interface: &str) -> bool {
    let output = Command::new("tc")
        .args(["qdisc", "show", "dev", interface])
        .output();
    
    if let Ok(output) = output {
        let stdout = String::from_utf8_lossy(&output.stdout);
        stdout.contains("clsact")
    } else {
        false
    }
}

fn setup_clsact(interface: &str, cleanup_state: &Arc<TcCleanupState>) -> anyhow::Result<()> {
    // Check if clsact already exists
    let existed = check_clsact_exists(interface);
    cleanup_state.clsact_existed.store(existed, Ordering::SeqCst);

    if existed {
        info!("clsact qdisc already exists on {}, will preserve on exit", interface);
    } else {
        info!("Adding clsact qdisc to {}...", interface);
        let status = Command::new("tc")
            .args(["qdisc", "add", "dev", interface, "clsact"])
            .status()?;
        
        if !status.success() {
            return Err(anyhow::anyhow!("Failed to add clsact qdisc to {}", interface));
        }
        info!("Successfully added clsact qdisc to {}", interface);
    }
    Ok(())
}

fn cleanup_network(interface: &str, engine: &str, enabled: bool, cleanup_state: &Arc<TcCleanupState>) {
    if !enabled {
        return;
    }

    let tc_attached = cleanup_state.tc_attached.load(Ordering::SeqCst);
    let clsact_existed = cleanup_state.clsact_existed.load(Ordering::SeqCst);

    if engine.to_lowercase() == "xdp" {
        info!("Detaching XDP from {}...", interface);
        let _ = Command::new("ip")
            .args(["link", "set", "dev", interface, "xdp", "off"])
            .status();
    }

    if tc_attached && !clsact_existed {
        info!("Removing clsact qdisc from {} (was added by agent)...", interface);
        let _ = Command::new("tc")
            .args(["qdisc", "del", "dev", interface, "clsact"])
            .status();
    } else if tc_attached {
        info!("Keeping clsact qdisc on {} (existed before agent started)", interface);
    }
}

fn read_sysctl(path: &str) -> Option<String> {
    fs::read_to_string(path).ok().map(|s| s.trim().to_string())
}

fn write_sysctl(path: &str, value: &str) -> anyhow::Result<()> {
    fs::write(path, value)?;
    Ok(())
}

fn setup_sysctl(interface: &str) -> anyhow::Result<SysctlState> {
    let accept_local_iface = format!("/proc/sys/net/ipv4/conf/{}/accept_local", interface);
    let accept_local_all = "/proc/sys/net/ipv4/conf/all/accept_local";
    let ip_forward_path = "/proc/sys/net/ipv4/ip_forward";

    let accept_local_iface_original = read_sysctl(&accept_local_iface);
    let accept_local_all_original = read_sysctl(accept_local_all);
    let ip_forward_original = read_sysctl(ip_forward_path);

    info!("Setting up sysctl for packet forwarding...");

    // Set accept_local for all
    if let Some(ref orig) = accept_local_all_original {
        if orig != "1" {
            write_sysctl(accept_local_all, "1")?;
            info!("Set net.ipv4.conf.all.accept_local=1 (was {})", orig);
        }
    }

    // Set accept_local for interface
    if let Some(ref orig) = accept_local_iface_original {
        if orig != "1" {
            write_sysctl(&accept_local_iface, "1")?;
            info!("Set net.ipv4.conf.{}.accept_local=1 (was {})", interface, orig);
        }
    }

    // Set ip_forward
    if let Some(ref orig) = ip_forward_original {
        if orig != "1" {
            write_sysctl(ip_forward_path, "1")?;
            info!("Set net.ipv4.ip_forward=1 (was {})", orig);
        }
    }

    Ok(SysctlState {
        accept_local_iface_original,
        accept_local_all_original,
        ip_forward_original,
        interface: interface.to_string(),
    })
}

fn restore_sysctl(state: &SysctlState) {
    info!("Restoring sysctl settings...");

    let accept_local_iface = format!("/proc/sys/net/ipv4/conf/{}/accept_local", state.interface);
    let accept_local_all = "/proc/sys/net/ipv4/conf/all/accept_local";
    let ip_forward_path = "/proc/sys/net/ipv4/ip_forward";

    if let Some(ref orig) = state.accept_local_all_original {
        if let Err(e) = write_sysctl(accept_local_all, orig) {
            warn!("Failed to restore accept_local all: {}", e);
        } else {
            info!("Restored net.ipv4.conf.all.accept_local={}", orig);
        }
    }

    if let Some(ref orig) = state.accept_local_iface_original {
        if let Err(e) = write_sysctl(&accept_local_iface, orig) {
            warn!("Failed to restore accept_local ({}): {}", state.interface, e);
        } else {
            info!("Restored net.ipv4.conf.{}.accept_local={}", state.interface, orig);
        }
    }

    if let Some(ref orig) = state.ip_forward_original {
        if let Err(e) = write_sysctl(ip_forward_path, orig) {
            warn!("Failed to restore ip_forward: {}", e);
        } else {
            info!("Restored net.ipv4.ip_forward={}", orig);
        }
    }
}

fn attach_hooks(
    bpf: &mut Bpf,
    config: &UnifiedConfig,
    cgroup_path: &PathBuf,
    tc_cleanup: &Arc<TcCleanupState>,
) -> anyhow::Result<()> {
    info!("Loading BTF from /sys/kernel/btf/vmlinux... (this may take a few seconds)");
    let btf = Btf::from_sys_fs()?;
    info!("BTF loaded successfully.");

    // LSM hooks
    if let Some(prog) = bpf.program_mut("enforce_file_open") {
        let lsm: &mut Lsm = prog.try_into()?;
        lsm.load("file_open", &btf).map_err(|e| {
            warn!("Failed to load file_open: {}. This might be due to kernel version or sleepable LSM support.", e);
            e
        })?;
        lsm.attach()?;
        info!("Attached LSM: file_open");
    }

    if let Some(prog) = bpf.program_mut("enforce_bprm_check_security") {
        let lsm: &mut Lsm = prog.try_into()?;
        lsm.load("bprm_check_security", &btf).map_err(|e| {
            warn!("Failed to load bprm_check_security: {}. This might be due to kernel version or sleepable LSM support.", e);
            e
        })?;
        lsm.attach()?;
        info!("Attached LSM: bprm_check_security");
    }

    if let Some(prog) = bpf.program_mut("enforce_inode_create") {
        let lsm: &mut Lsm = prog.try_into()?;
        lsm.load("inode_create", &btf).map_err(|e| {
            warn!("Failed to load inode_create: {}. This might be due to kernel version or sleepable LSM support.", e);
            e
        })?;
        lsm.attach()?;
        info!("Attached LSM: inode_create");
    }

    if let Some(prog) = bpf.program_mut("enforce_inode_unlink") {
        let lsm: &mut Lsm = prog.try_into()?;
        lsm.load("inode_unlink", &btf).map_err(|e| {
            warn!("Failed to load inode_unlink: {}. This might be due to kernel version or sleepable LSM support.", e);
            e
        })?;
        lsm.attach()?;
        info!("Attached LSM: inode_unlink");
    }

    // Network hooks
    if config.network.enabled {
        match config.network.engine.to_lowercase().as_str() {
            "xdp" => {
                let program: &mut Xdp = bpf.program_mut("xdp_packet_filter").unwrap().try_into()?;
                program.load()?;
                program.attach(&config.network.interface, XdpFlags::default())?;
                info!("Attached XDP to {}", config.network.interface);
                
                // Setup clsact for TC (also needed for XDP mode)
                setup_clsact(&config.network.interface, tc_cleanup)?;
                tc_cleanup.tc_attached.store(true, Ordering::SeqCst);
                
                // Also attach TC for reverse handling
                let prog: &mut SchedClassifier =
                    bpf.program_mut("tc_packet_filter").unwrap().try_into()?;
                prog.load()?;
                prog.attach(&config.network.interface, TcAttachType::Egress)?;
                info!(
                    "Attached TC Egress to {} for reverse",
                    config.network.interface
                );
            }
            "tc" => {
                // Setup clsact qdisc first
                setup_clsact(&config.network.interface, tc_cleanup)?;
                tc_cleanup.tc_attached.store(true, Ordering::SeqCst);
                
                let prog: &mut SchedClassifier =
                    bpf.program_mut("tc_packet_filter").unwrap().try_into()?;
                prog.load()?;
                prog.attach(&config.network.interface, TcAttachType::Ingress)?;
                info!("Attached TC Ingress to {}", config.network.interface);
                prog.attach(&config.network.interface, TcAttachType::Egress)?;
                info!("Attached TC Egress to {}", config.network.interface);
            }
            _ => warn!(
                "Unknown network engine: {}, skipping network hooks",
                config.network.engine
            ),
        }
    }

    // Cgroup hooks
    if let Some(prog) = bpf.program_mut("enforce_connect4") {
        let cgroup_fd = fs::File::open(cgroup_path)?;
        let program: &mut CgroupSockAddr = prog.try_into()?;
        program.load()?;
        program.attach(cgroup_fd)?;
        info!("Attached Cgroup Connect hook to {}", cgroup_path.display());
    }

    Ok(())
}

fn handle_event(event: &UnifiedEvent) {
    match event.get_type() {
        Some(EventType::File) => {
            if let Some(data) = event.monitor() {
                info!(
                    "[FILE] PID={} UID={} Comm={} Path={} Blocked={}",
                    data.pid,
                    data.uid,
                    String::from_utf8_lossy(&data.comm).trim_matches(char::from(0)),
                    String::from_utf8_lossy(&data.path).trim_matches(char::from(0)),
                    data.blocked != 0
                );
            }
        }
        Some(EventType::Process) => {
            if let Some(data) = event.monitor() {
                info!(
                    "[PROC] PID={} UID={} Comm={} Path={} Blocked={}",
                    data.pid,
                    data.uid,
                    String::from_utf8_lossy(&data.comm).trim_matches(char::from(0)),
                    String::from_utf8_lossy(&data.path).trim_matches(char::from(0)),
                    data.blocked != 0
                );
            }
        }
        Some(EventType::Network) => {
            if let Some(data) = event.network() {
                info!(
                    "[NET] Proto={} {}:{} -> {}:{} FlagsSet=0x{:02x}",
                    data.protocol,
                    Ipv4Addr::from(data.src_ip),
                    data.src_port,
                    Ipv4Addr::from(data.dst_ip),
                    data.dst_port,
                    data.tcp_flags_set
                );
            }
        }
        Some(EventType::Debug) => {
            info!("[DEBUG] {}", event.msg_str());
        }
        None => warn!("Unknown event type: {}", event.event_type),
    }
}
