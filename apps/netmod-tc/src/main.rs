use aya::{
    maps::HashMap,
    programs::{SchedClassifier, TcAttachType},
    Bpf,
};
use ebpf_common::{PktModKey, PktModValue};
use std::fs;

/// Network Packet Modification Tool
///
/// This application allows you to configure eBPF-based packet modification rules
/// for outgoing traffic. Supports:
/// - TCP flag modification (ECN-Echo, CWR, etc.)
/// - Port rewriting (source/destination)
/// - IP address rewriting (source/destination)
///
/// Usage:
///   sudo cargo run -p netmod -- --interface eth0 --config netmod_rules.json
///
/// Example configuration (netmod_rules.json):
/// ```json
/// {
///   "rules": [
///     {
///       "match_rule": {
///         "protocol": "tcp",
///         "src_port": 0,
///         "dst_port": 443,
///         "dst_ip": [0, 0, 0, 0]
///       },
///       "modification": {
///         "tcp_flags": {
///           "set_ecn_echo": true,
///           "set_cwr": false
///         }
///       }
///     },
///     {
///       "match_rule": {
///         "protocol": "tcp",
///         "src_port": 0,
///         "dst_port": 80,
///         "dst_ip": [192, 168, 1, 100]
///       },
///       "modification": {
///         "port_mod": {
///           "new_dst_port": 8080
///         },
///         "ip_mod": {
///           "new_dst_ip": [192, 168, 1, 200]
///         }
///       }
///     }
///   ]
/// }
/// ```
use clap::Parser;
use ebpf_common::{
    Action, IpMod, NetworkRule, PacketMatch, PacketMod, PacketModRule, PortMod, TcpFlagsMod,
};

use serde::{Deserialize, Serialize};

use std::path::PathBuf;
use std::process::Command;
use std::sync::mpsc;

#[derive(Parser, Debug)]
#[command(name = "netmod")]
#[command(about = "eBPF-based network packet modification tool", long_about = None)]
struct Args {
    /// Network interface to attach to (e.g., eth0, lo)
    #[arg(short, long, default_value = "lo")]
    interface: String,

    /// Configuration file with packet modification rules (JSON)
    #[arg(short, long)]
    config: Option<PathBuf>,

    /// Path to BPF object file
    #[arg(short, long, default_value = "../bpf/tc_pkt_mod.bpf.o")]
    bpf_obj: String,

    /// Use built-in example rules instead of config file
    #[arg(short, long)]
    example: bool,

    /// Attach to ingress instead of egress
    #[arg(long)]
    ingress: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct Config {
    rules: Vec<PacketModRule>,
    #[serde(default)]
    blocking_rules: Vec<NetworkRule>,
}

// Packet event structure (must match BPF side - simplified for TC context)
#[repr(C)]
struct PacketEvent {
    event_type: u8,
    protocol: u8,
    tcp_flags_set: u8,
    padding1: u8,
    src_ip: u32,
    dst_ip: u32,
    src_port: u16,
    dst_port: u16,
}

// Debug event structure (must match BPF side)
#[repr(C)]
struct DebugEvent {
    event_type: u8,    // EVENT_DEBUG = 4
    event_subtype: u8, // 0=pkt_info, 1=rule_match, 2=modification
    protocol: u8,
    rule_matched: u8, // 0=no, 1=yes
    src_ip: u32,
    dst_ip: u32,
    src_port: u16,
    dst_port: u16,
    matched_dst_port: u16,
    tcp_flags_enable: u8,
    reserved_bits_mask: u8,
    reserved_bits_value: u8,
    padding: [u8; 1],
}

impl DebugEvent {
    fn format_ip(ip: u32) -> String {
        let bytes = ip.to_le_bytes();
        format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3])
    }

    fn format(&self) -> String {
        let protocol_str = match self.protocol {
            6 => "TCP",
            17 => "UDP",
            1 => "ICMP",
            _ => "?",
        };

        match self.event_subtype {
            0 => {
                // Packet info
                format!(
                    "PKT: {} {}:{} -> {}:{}",
                    protocol_str,
                    Self::format_ip(self.src_ip),
                    u16::from_be(self.src_port),
                    Self::format_ip(self.dst_ip),
                    u16::from_be(self.dst_port)
                )
            }
            1 => {
                // Rule match
                if self.rule_matched == 1 {
                    format!(
                        "MATCH: {} dst_port={} | Rule: tcp_flags_en={} reserved_mask=0x{:02x} reserved_val=0x{:02x}",
                        protocol_str,
                        u16::from_be(self.dst_port),
                        self.tcp_flags_enable,
                        self.reserved_bits_mask,
                        self.reserved_bits_value
                    )
                } else {
                    format!(
                        "NO MATCH: {} dst_port={} (checked {} rules)",
                        protocol_str,
                        u16::from_be(self.dst_port),
                        "all"
                    )
                }
            }
            _ => format!("DEBUG: subtype={}", self.event_subtype),
        }
    }
}

impl PacketEvent {
    fn format_ip(ip: u32) -> String {
        let bytes = ip.to_le_bytes();
        format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3])
    }

    fn format_flags(&self) -> String {
        let mut flags = Vec::new();
        if self.tcp_flags_set & 0x01 != 0 {
            flags.push("ECN-Echo");
        }
        if self.tcp_flags_set & 0x02 != 0 {
            flags.push("CWR");
        }
        if flags.is_empty() {
            "-".to_string()
        } else {
            flags.join("+")
        }
    }
}

/// Clean up eBPF program from interface
fn cleanup_program(interface: &str, is_xdp: bool) {
    if is_xdp {
        // For XDP cleanup
        let _ = Command::new("ip")
            .args(["link", "set", "dev", interface, "xdp", "off"])
            .status();
    } else {
        // For TC cleanup
        let _ = Command::new("tc")
            .args(["qdisc", "del", "dev", interface, "clsact"])
            .status();
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let (rules, blocking_rules) = if args.example {
        println!("📋 Using built-in example rules");
        get_example_rules()
    } else if let Some(config_path) = args.config {
        println!("📋 Loading rules from: {}", config_path.display());
        let config_str = fs::read_to_string(config_path)?;
        let config: Config = serde_json::from_str(&config_str)?;
        (config.rules, config.blocking_rules)
    } else {
        eprintln!("❌ Error: Either --config or --example must be specified");
        std::process::exit(1);
    };

    let mut bpf_handle = Bpf::load_file(&args.bpf_obj)?;

    println!("🔌 Attaching TC hook to interface: {}", args.interface);

    // Populate maps
    println!("📝 Populating BPF maps with rules...");
    let mut block_map: HashMap<_, u16, u8> =
        HashMap::try_from(bpf_handle.map_mut("block_rules").unwrap())?;
    for rule in &blocking_rules {
        if rule.action == Action::Deny {
            block_map.insert(rule.local_port, 1, 0)?;
            println!("   - Blocked port: {}", rule.local_port);
        }
    }

    let mut mod_map: HashMap<_, PktModKey, PktModValue> =
        HashMap::try_from(bpf_handle.map_mut("pkt_mod_rules").unwrap())?;
    for rule in &rules {
        let proto_num = match rule.match_rule.protocol.to_lowercase().as_str() {
            "tcp" => 6,
            "udp" => 17,
            _ => 0,
        };

        let key = PktModKey {
            protocol: proto_num,
            direction: rule.match_rule.direction as u8,
            padding: [0; 2],
            dst_ip: u32::from_be_bytes(rule.match_rule.dst_ip),
            src_port: rule.match_rule.src_port.to_be(),
            dst_port: rule.match_rule.dst_port.to_be(),
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

        if let Some(tcp_mod) = &rule.modification.tcp_flags {
            val.tcp_flags_enable = 1;
            if tcp_mod.set_ecn_echo.unwrap_or(false) {
                val.tcp_set_ecn_echo = 1;
            }
            if tcp_mod.set_cwr.unwrap_or(false) {
                val.tcp_set_cwr = 1;
            }
            if tcp_mod.set_reserved_bits.unwrap_or(false) {
                val.tcp_set_reserved = 1;
            }
            if let Some(m) = tcp_mod.flags_mask {
                val.tcp_flags_mask = m;
            }
            if let Some(v) = tcp_mod.flags_value {
                val.tcp_flags_value = v;
            }
            if let Some(m) = tcp_mod.reserved_bits_mask {
                val.reserved_bits_mask = m;
            }
            if let Some(v) = tcp_mod.reserved_bits_value {
                val.reserved_bits_value = v;
            }
        }

        if let Some(port_mod) = &rule.modification.port_mod {
            val.port_mod_enable = 1;
            val.new_src_port = port_mod.new_src_port.unwrap_or(0).to_be();
            val.new_dst_port = port_mod.new_dst_port.unwrap_or(0).to_be();
        }

        if let Some(ip_mod) = &rule.modification.ip_mod {
            val.ip_mod_enable = 1;
            val.new_src_ip = u32::from_ne_bytes(ip_mod.new_src_ip.unwrap_or([0, 0, 0, 0]));
            val.new_dst_ip = u32::from_ne_bytes(ip_mod.new_dst_ip.unwrap_or([0, 0, 0, 0]));
        }

        mod_map.insert(key, val, 0)?;
        println!("   - Rule: {} -> mod", rule.match_rule.dst_port);
    }

    // Attach TC program
    let program: &mut SchedClassifier = bpf_handle
        .program_mut("tc_pkt_modifier")
        .unwrap()
        .try_into()?;
    program.load()?;
    let attach_type = if args.ingress {
        TcAttachType::Ingress
    } else {
        TcAttachType::Egress
    };
    program.attach(&args.interface, attach_type)?;

    // === SIGNAL HANDLING (SIGINT + SIGTERM) ===
    let (tx, rx) = mpsc::channel();
    let mut signals = signal_hook::iterator::Signals::new(&[
        signal_hook::consts::SIGINT,
        signal_hook::consts::SIGTERM,
        signal_hook::consts::SIGHUP,
    ])?;
    let handle = signals.handle();

    let tx_clone = tx.clone();
    std::thread::spawn(move || {
        for sig in signals.forever() {
            eprintln!(
                "\n⚠️  Received signal {}. Initiating graceful shutdown...",
                sig
            );
            let _ = tx_clone.send(());
            break;
        }
    });

    // Event handling thread - commented out due to aya API issues
    // std::thread::spawn(move || {
    //     while let Some(Ok(data)) = ringbuf.next() {
    //         let ptr = data.as_ptr() as *const PacketEvent;
    //         let event = unsafe { &*ptr };
    //         let protocol_str = match event.protocol {
    //             6 => "TCP",
    //             17 => "UDP",
    //             _ => "UNK",
    //         };
    //         let action = if event.tcp_flags_set & 0x80 != 0 {
    //             "BLOCKED"
    //         } else if event.tcp_flags_set & 0x40 != 0 {
    //             "MODIFIED"
    //         } else {
    //             "PASSED"
    //         };
    //         println!(
    //             "[{}] {} {} src={} dst={} sport={} dport={} action={}",
    //             Local::now().format("%H:%M:%S"),
    //             action,
    //             protocol_str,
    //             event.src_ip,
    //             event.dst_ip,
    //             event.src_port,
    //             event.dst_port,
    //             event.tcp_flags_set
    //         );
    //     }
    // });

    // Main loop - wait for signals
    println!("⏳ Running... (Ctrl+C or 'kill <pid>' to exit)\n");
    loop {
        // Check if signal received
        if rx.try_recv().is_ok() {
            break;
        }
        // Sleep briefly to avoid busy waiting
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    // === CLEAN SHUTDOWN ===
    drop(handle); // stop signal iterator thread

    // 🔥 CRITICAL: Comprehensive cleanup
    println!("\n🧹 Cleaning up resources...");
    cleanup_program(&args.interface, false);

    println!("\n✅ Shutdown complete.");
    Ok(())
}

/// Built-in example rules for testing
fn get_example_rules() -> (Vec<PacketModRule>, Vec<NetworkRule>) {
    let packet_mod_rules = vec![
        PacketModRule {
            match_rule: PacketMatch {
                protocol: "tcp".to_string(),
                direction: ebpf_common::NetDirection::Egress,
                src_port: 0,
                dst_port: 443,
                dst_ip: [0, 0, 0, 0],
            },
            modification: PacketMod {
                tcp_flags: Some(TcpFlagsMod {
                    set_ecn_echo: Some(true),
                    set_cwr: Some(false),
                    set_reserved_bits: None,
                    reserved_bits_mask: None,
                    reserved_bits_value: None,
                    flags_mask: None,
                    flags_value: None,
                }),
                port_mod: None,
                ip_mod: None,
            },
        },
        PacketModRule {
            match_rule: PacketMatch {
                protocol: "tcp".to_string(),
                direction: ebpf_common::NetDirection::Egress,
                src_port: 0,
                dst_port: 80,
                dst_ip: [0, 0, 0, 0],
            },
            modification: PacketMod {
                tcp_flags: None,
                port_mod: Some(PortMod {
                    new_src_port: None,
                    new_dst_port: Some(8080),
                }),
                ip_mod: None,
            },
        },
        PacketModRule {
            match_rule: PacketMatch {
                protocol: "any".to_string(),
                direction: ebpf_common::NetDirection::Any,
                src_port: 0,
                dst_port: 0,
                dst_ip: [1, 1, 1, 1],
            },
            modification: PacketMod {
                tcp_flags: None,
                port_mod: None,
                ip_mod: Some(IpMod {
                    new_src_ip: None,
                    new_dst_ip: Some([8, 8, 8, 8]),
                }),
            },
        },
        PacketModRule {
            match_rule: PacketMatch {
                protocol: "tcp".to_string(),
                direction: ebpf_common::NetDirection::Egress,
                src_port: 0,
                dst_port: 1234,
                dst_ip: [0, 0, 0, 0],
            },
            modification: PacketMod {
                tcp_flags: Some(TcpFlagsMod {
                    set_ecn_echo: Some(false),
                    set_cwr: Some(false),
                    set_reserved_bits: None,
                    reserved_bits_mask: None,
                    reserved_bits_value: None,
                    flags_mask: None,
                    flags_value: None,
                }),
                port_mod: None,
                ip_mod: None,
            },
        },
    ];

    let blocking_rules = vec![
        NetworkRule {
            local_port: 22, // Block SSH
            redirect: None,
            action: Action::Deny,
        },
        NetworkRule {
            local_port: 23, // Block Telnet
            redirect: None,
            action: Action::Deny,
        },
    ];

    (packet_mod_rules, blocking_rules)
}
