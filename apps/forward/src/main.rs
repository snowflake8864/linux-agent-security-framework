use aya::{
    maps::{HashMap, RingBuf},
    programs::{CgroupSockAddr, Xdp, XdpFlags},
    Bpf, Pod,
};
use clap::Parser;
use serde::{Deserialize, Serialize};
use std::fs;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::process::Command;
use std::sync::mpsc;

// Event structure (must match BPF side)
#[repr(C)]
struct ForwardEvent {
    event_type: u8,
    data: ForwardEventData,
}

#[repr(C)]
union ForwardEventData {
    pub details: ForwardEventDetails,
    pub tcp_tuple: TcpTuple,
    pub msg: [u8; 64],
}

#[repr(C)]
#[derive(Copy, Clone)]
struct ForwardEventDetails {
    pub src_ip: u32,
    pub orig_dst_ip: u32,
    pub orig_dst_port: u16,
    pub new_dst_ip: u32,
    pub new_dst_port: u16,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct TcpTuple {
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
}

// Forward rule structure (must match BPF side)
#[repr(C)]
#[derive(Copy, Clone)]
struct ForwardRule {
    target_ip: u32,    // Network byte order
    target_port: u16,  // Network byte order
    allowed_ip: u32,   // Network byte order
    allowed_mask: u32, // Network byte order
}

unsafe impl Pod for ForwardRule {}

#[derive(Clone)]
struct SysctlState {
    accept_local_iface_original: Option<String>,
    accept_local_all_original: Option<String>,
    ip_forward_original: Option<String>,
    interface: String,
}

#[derive(Parser, Debug)]
#[command(name = "forward")]
#[command(about = "eBPF-based TCP/UDP port forwarding tool", long_about = None)]
struct Args {
    /// Configuration file with forwarding rules (JSON)
    #[arg(short, long)]
    config: PathBuf,

    /// Path to BPF object file
    #[arg(short, long, default_value = "../../bpf/forward.bpf.o")]
    bpf_obj: String,

    /// Cgroup path to attach to (default: root cgroup)
    #[arg(long, default_value = "/sys/fs/cgroup")]
    cgroup: PathBuf,

    /// Network interface for XDP (remote/ingress redirection)
    #[arg(short, long)]
    interface: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Config {
    forward_rules: Vec<ForwardRuleConfig>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ForwardRuleConfig {
    listen_port: Vec<serde_json::Value>, // Can be number or string like "1000-1010"
    target_host: String,
    target_port: u16,
    allowed_sources: Vec<String>, // CIDR or IP
}

impl ForwardRuleConfig {
    // Expand listen_port to individual ports
    fn expand_ports(&self) -> Vec<u16> {
        let mut ports = Vec::new();
        for port_val in &self.listen_port {
            if let Some(port) = port_val.as_u64() {
                ports.push(port as u16);
            } else if let Some(range) = port_val.as_str() {
                if let Some((start, end)) = parse_port_range(range) {
                    for p in start..=end {
                        ports.push(p);
                    }
                }
            }
        }
        ports
    }
}

fn parse_port_range(range: &str) -> Option<(u16, u16)> {
    let parts: Vec<&str> = range.split('-').collect();
    if parts.len() == 2 {
        if let (Ok(start), Ok(end)) = (parts[0].parse::<u16>(), parts[1].parse::<u16>()) {
            if start <= end {
                return Some((start, end));
            }
        }
    }
    None
}

fn parse_cidr(cidr: &str) -> Result<(u32, u32), Box<dyn std::error::Error>> {
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
    } else {
        let ip: Ipv4Addr = cidr.parse()?;
        Ok((u32::from(ip).to_be(), u32::MAX.to_be()))
    }
}

fn format_ip(ip: u32) -> String {
    let bytes = ip.to_le_bytes();
    format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3])
}

fn read_sysctl(path: &str) -> Option<String> {
    fs::read_to_string(path).ok().map(|s| s.trim().to_string())
}

fn write_sysctl(path: &str, value: &str) -> Result<(), Box<dyn std::error::Error>> {
    fs::write(path, value)?;
    Ok(())
}

fn setup_sysctl(interface: &str) -> Result<SysctlState, Box<dyn std::error::Error>> {
    let accept_local_iface = format!("/proc/sys/net/ipv4/conf/{}/accept_local", interface);
    let accept_local_all = "/proc/sys/net/ipv4/conf/all/accept_local";
    let ip_forward_path = "/proc/sys/net/ipv4/ip_forward";

    let accept_local_iface_original = read_sysctl(&accept_local_iface);
    let accept_local_all_original = read_sysctl(accept_local_all);
    let ip_forward_original = read_sysctl(ip_forward_path);

    println!("📋 Setting up sysctl for packet forwarding...");

    // Set accept_local for all
    if let Some(ref orig) = accept_local_all_original {
        if orig != "1" {
            write_sysctl(accept_local_all, "1")?;
            println!("Set net.ipv4.conf.all.accept_local=1 (was {})", orig);
        }
    }

    // Set accept_local for interface
    if let Some(ref orig) = accept_local_iface_original {
        if orig != "1" {
            write_sysctl(&accept_local_iface, "1")?;
            println!(
                "Set net.ipv4.conf.{}.accept_local=1 (was {})",
                interface, orig
            );
        }
    }

    // Set ip_forward
    if let Some(ref orig) = ip_forward_original {
        if orig != "1" {
            write_sysctl(ip_forward_path, "1")?;
            println!("Set net.ipv4.ip_forward=1 (was {})", orig);
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
    println!("📋 Restoring sysctl settings...");

    let accept_local_iface = format!("/proc/sys/net/ipv4/conf/{}/accept_local", state.interface);
    let accept_local_all = "/proc/sys/net/ipv4/conf/all/accept_local";
    let ip_forward_path = "/proc/sys/net/ipv4/ip_forward";

    if let Some(ref orig) = state.accept_local_all_original {
        if let Err(e) = write_sysctl(accept_local_all, orig) {
            eprintln!("Failed to restore accept_local all: {}", e);
        } else {
            println!("Restored net.ipv4.conf.all.accept_local={}", orig);
        }
    }

    if let Some(ref orig) = state.accept_local_iface_original {
        if let Err(e) = write_sysctl(&accept_local_iface, orig) {
            eprintln!(
                "Failed to restore accept_local ({}): {}",
                state.interface, e
            );
        } else {
            println!(
                "Restored net.ipv4.conf.{}.accept_local={}",
                state.interface, orig
            );
        }
    }

    if let Some(ref orig) = state.ip_forward_original {
        if let Err(e) = write_sysctl(ip_forward_path, orig) {
            eprintln!("Failed to restore ip_forward: {}", e);
        } else {
            println!("Restored net.ipv4.ip_forward={}", orig);
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // Load config
    println!(
        "📋 Loading forwarding rules from: {}",
        args.config.display()
    );
    let config_str = fs::read_to_string(&args.config)?;
    let config: Config = serde_json::from_str(&config_str)?;

    // Load BPF
    let mut bpf = Bpf::load_file(&args.bpf_obj)?;

    // Setup system configuration
    let sysctl_state = if let Some(ref iface) = args.interface {
        Some(setup_sysctl(iface)?)
    } else {
        None
    };

    // Populate forward_rules map
    println!("📝 Populating BPF maps with forwarding rules...");
    let mut forward_map: HashMap<_, u16, ForwardRule> =
        HashMap::try_from(bpf.map_mut("forward_rules").unwrap())?;

    for rule_config in &config.forward_rules {
        let target_ip: Ipv4Addr = rule_config.target_host.parse()?;
        let target_ip_be = u32::from(target_ip).to_be();
        let target_port_be = rule_config.target_port.to_be();

        for source in &rule_config.allowed_sources {
            let (allowed_ip, allowed_mask) = parse_cidr(source)?;

            let rule = ForwardRule {
                target_ip: target_ip_be,
                target_port: target_port_be,
                allowed_ip,
                allowed_mask,
            };

            for port in rule_config.expand_ports() {
                let port_be = port.to_be();
                forward_map.insert(port_be, rule, 0)?;
                println!(
                    "   - Forward port {} to {}:{} (allowed: {})",
                    port, rule_config.target_host, rule_config.target_port, source
                );
            }
        }
    }

    // Attach to cgroup
    println!(
        "🔌 Attaching cgroup/connect hook to cgroup: {}",
        args.cgroup.display()
    );
    let cgroup_fd = fs::File::open(&args.cgroup)?;
    let program: &mut CgroupSockAddr = bpf.program_mut("forward_connect").unwrap().try_into()?;
    program.load()?;
    program.attach(cgroup_fd)?;

    // Attach XDP if interface is provided
    if let Some(iface) = &args.interface {
        println!("🔌 Attaching XDP hook to interface: {}", iface);
        let xdp_program: &mut Xdp = bpf.program_mut("xdp_forward").unwrap().try_into()?;
        xdp_program.load()?;
        xdp_program.attach(iface, XdpFlags::default())?;
    }

    // Event handling
    let mut ringbuf: RingBuf<_> = RingBuf::try_from(bpf.map_mut("forward_events").unwrap())?;

    // Signal handling
    let (tx, rx) = mpsc::channel();
    let mut signals = signal_hook::iterator::Signals::new(&[
        signal_hook::consts::SIGINT,
        signal_hook::consts::SIGTERM,
    ])?;
    let handle = signals.handle();

    let tx_clone = tx.clone();
    let sysctl_state_clone = sysctl_state.clone();
    std::thread::spawn(move || {
        for sig in signals.forever() {
            eprintln!(
                "\n⚠️  Received signal {}. Initiating graceful shutdown...",
                sig
            );
            if let Some(ref sysctl) = sysctl_state_clone {
                restore_sysctl(sysctl);
            }
            let _ = tx_clone.send(());
            break;
        }
    });

    println!("⏳ Running... (Ctrl+C to exit)\n");
    loop {
        if rx.try_recv().is_ok() {
            break;
        }

        while let Some(data) = ringbuf.next() {
            let ptr = data.as_ptr() as *const ForwardEvent;
            let event = unsafe { &*ptr };

            match event.event_type {
                1 | 2 | 3 => {
                    let details = unsafe { event.data.details };
                    let orig_ip = format_ip(details.orig_dst_ip);
                    let new_ip = format_ip(details.new_dst_ip);
                    let orig_port = u16::from_be(details.orig_dst_port);
                    let new_port = u16::from_be(details.new_dst_port);
                    let src_ip = format_ip(details.src_ip);

                    let action = match event.event_type {
                        1 => "ATTEMPT",
                        2 => "SUCCESS",
                        3 => "XDP_ENTRY",
                        _ => "UNKNOWN",
                    };

                    if event.event_type == 3 {
                        println!(
                            "[{}] SRC {} -> DST {}:{}",
                            action, src_ip, orig_ip, orig_port
                        );
                    } else {
                        println!(
                            "[{}] {}:{} -> {}:{} (SRC: {})",
                            action, orig_ip, orig_port, new_ip, new_port, src_ip
                        );
                    }
                }
                4 => {
                    let msg_bytes = unsafe { &event.data.msg };
                    let msg = std::str::from_utf8(msg_bytes)
                        .unwrap_or("Invalid UTF-8")
                        .trim_matches(char::from(0));
                    println!("[DEBUG] {}", msg);
                }
                5 => {
                    let tuple = unsafe { event.data.tcp_tuple };
                    let src_ip = format_ip(tuple.src_ip);
                    let dst_ip = format_ip(tuple.dst_ip);
                    let src_port = u16::from_be(tuple.src_port);
                    let dst_port = u16::from_be(tuple.dst_port);
                    println!(
                        "[TCP_TUPLE] {}:{} -> {}:{} (proto {})",
                        src_ip, src_port, dst_ip, dst_port, tuple.protocol
                    );
                }
                6 => {
                    let details = unsafe { event.data.details };
                    let orig_ip = format_ip(details.orig_dst_ip);
                    let new_ip = format_ip(details.new_dst_ip);
                    let orig_port = u16::from_be(details.orig_dst_port);
                    let new_port = u16::from_be(details.new_dst_port);
                    let src_ip = format_ip(details.src_ip);
                    println!(
                        "[REVERSE_SUCCESS] {}:{} -> {}:{} (SRC: {})",
                        orig_ip, orig_port, new_ip, new_port, src_ip
                    );
                }
                _ => println!("[UNKNOWN] type {}", event.event_type),
            }
        }

        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    drop(handle);
    println!("\n✅ Shutdown complete.");
    Ok(())
}
