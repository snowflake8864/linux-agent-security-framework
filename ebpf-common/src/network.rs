use crate::Action;
#[cfg(feature = "user")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "user")]
use zerocopy;

/// Direction for network traffic.
#[cfg(feature = "user")]
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
#[repr(u8)]
pub enum NetDirection {
    Any = 0,
    Ingress = 1,
    Egress = 2,
}

impl Default for NetDirection {
    fn default() -> Self {
        Self::Any
    }
}

/// High-level network control rule description.
#[cfg(feature = "user")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkRule {
    /// Local listening port.
    pub local_port: u16,
    /// Optional redirect target (IPv4 + port). If `None` and action is
    /// `Redirect`, the framework will treat it as an error.
    pub redirect: Option<NetworkRedirect>,
    pub action: Action,
}

/// Redirect destination for network connections.
#[cfg(feature = "user")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkRedirect {
    pub dst_ipv4: [u8; 4],
    pub dst_port: u16,
}

/// Packet modification rule for outgoing traffic.
/// Supports TCP flag modification, port/IP rewriting.
#[cfg(feature = "user")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketModRule {
    /// Match criteria
    pub match_rule: PacketMatch,
    /// Modification to apply
    pub modification: PacketMod,
}

/// Packet matching criteria.
#[cfg(feature = "user")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketMatch {
    /// Protocol: "tcp", "udp", "icmp", or "any"
    pub protocol: String,
    /// Direction: "ingress", "egress", or "any"
    #[serde(default)]
    pub direction: NetDirection,
    /// Source port to match (0 = any)
    pub src_port: u16,
    /// Destination port to match (0 = any)
    pub dst_port: u16,
    /// Destination IP to match ([0,0,0,0] = any)
    pub dst_ip: [u8; 4],
}

/// Packet modification actions.
#[cfg(feature = "user")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketMod {
    /// TCP flags modification (for TCP only)
    pub tcp_flags: Option<TcpFlagsMod>,
    /// Port modification
    pub port_mod: Option<PortMod>,
    /// IP modification
    pub ip_mod: Option<IpMod>,
}

/// TCP flags modification.
#[cfg(feature = "user")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpFlagsMod {
    /// Set ECN-Echo flag (bit 0 of reserved field)
    pub set_ecn_echo: Option<bool>,
    /// Set CWR flag (bit 1 of reserved field)
    pub set_cwr: Option<bool>,
    /// Set all 4 reserved bits (NS, reserved bits 2-4) - deprecated, use reserved_bits_mask/value instead
    pub set_reserved_bits: Option<bool>,
    /// Reserved bits mask (6 bits: NS + 5 reserved bits in byte 12, lower 4 bits + ECE/CWR handled separately)
    /// Bits: [NS, Res2, Res1, Res0] (4 bits in byte 12)
    /// Example: 0x0F = all 4 bits, 0x01 = only bit 0 (NS)
    pub reserved_bits_mask: Option<u8>,
    /// Reserved bits value (6 bits total, but we control the 4 bits in byte 12)
    /// Example: 0x01 = set tag 000001
    pub reserved_bits_value: Option<u8>,
    /// Modify standard TCP flags (FIN, SYN, RST, PSH, ACK, URG)
    pub flags_mask: Option<u8>,
    pub flags_value: Option<u8>,
}

/// Port modification.
#[cfg(feature = "user")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortMod {
    /// New source port
    pub new_src_port: Option<u16>,
    /// New destination port
    pub new_dst_port: Option<u16>,
}

/// IP address modification.
#[cfg(feature = "user")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpMod {
    /// New source IP
    pub new_src_ip: Option<[u8; 4]>,
    /// New destination IP
    pub new_dst_ip: Option<[u8; 4]>,
}

/// Packet modification key for BPF map.
#[cfg(feature = "user")]
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct PktModKey {
    pub protocol: u8,
    pub direction: u8, // 0=any, 1=ingress, 2=egress
    pub padding: [u8; 2],
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for PktModKey {}

/// Packet modification value for BPF map.
#[cfg(feature = "user")]
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct PktModValue {
    pub tcp_flags_enable: u8,
    pub tcp_set_ecn_echo: u8,
    pub tcp_set_cwr: u8,
    pub tcp_set_reserved: u8,
    pub tcp_flags_mask: u8,
    pub tcp_flags_value: u8,
    pub reserved_bits_mask: u8,
    pub reserved_bits_value: u8,
    pub port_mod_enable: u8,
    pub new_src_port: u16,
    pub new_dst_port: u16,
    pub ip_mod_enable: u8,
    pub new_src_ip: u32,
    pub new_dst_ip: u32,
    pub allowed_ip: u32,   // Network byte order
    pub allowed_mask: u32, // Network byte order
    pub padding: [u8; 3],
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for PktModValue {}
