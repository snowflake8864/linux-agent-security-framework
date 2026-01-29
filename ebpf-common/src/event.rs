/// Event types reported from BPF programs
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventType {
    File = 1,
    Process = 2,
    Network = 3,
    Debug = 4,
}

/// Monitor data for file and process events
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct MonitorData {
    pub pid: u32,
    pub uid: u32,
    pub blocked: u8,
    pub comm: [u8; 16],
    pub path: [u8; 64],
}

/// Network data for packet events
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct NetworkData {
    pub protocol: u8,
    pub tcp_flags_set: u8,
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub padding: [u8; 2], // Alignment
}

/// Rule entry for pattern matching
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RuleEntry {
    pub action: u8,
    pub event_type: u8,
    pub mode: u8,     // 0=Monitor, 1=Protect
    pub ops_mask: u8, // Bitmask for FileOp
    pub padding: [u8; 4],
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for RuleEntry {}

/// Unified data union
#[repr(C)]
#[derive(Copy, Clone)]
pub union UnifiedEventData {
    pub monitor: MonitorData,
    pub network: NetworkData,
    pub msg: [u8; 89],
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for UnifiedEventData {}

impl std::fmt::Debug for UnifiedEventData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UnifiedEventData").finish()
    }
}

/// Unified event structure matching the BPF-side struct unified_event
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct UnifiedEvent {
    pub event_type: u8,
    pub data: UnifiedEventData,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for UnifiedEvent {}

#[cfg(feature = "user")]
impl UnifiedEvent {
    /// Get the event type
    pub fn get_type(&self) -> Option<EventType> {
        match self.event_type {
            1 => Some(EventType::File),
            2 => Some(EventType::Process),
            3 => Some(EventType::Network),
            4 => Some(EventType::Debug),
            _ => None,
        }
    }

    /// Get monitor data safely
    pub fn monitor(&self) -> Option<&MonitorData> {
        match self.get_type()? {
            EventType::File | EventType::Process => Some(unsafe { &self.data.monitor }),
            _ => None,
        }
    }

    /// Get network data safely
    pub fn network(&self) -> Option<&NetworkData> {
        match self.get_type()? {
            EventType::Network => Some(unsafe { &self.data.network }),
            _ => None,
        }
    }

    /// Get debug message safely
    pub fn msg_str(&self) -> String {
        let msg_bytes = unsafe { &self.data.msg };
        let len = msg_bytes.iter().position(|&b| b == 0).unwrap_or(89);
        String::from_utf8_lossy(&msg_bytes[..len]).to_string()
    }
}

/// Event structure matching the BPF-side struct event (Legacy)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Event {
    pub event_type: u8,
    pub pid: u32,
    pub uid: u32,
    pub blocked: u8, // Was this action blocked?
    pub comm: [u8; 16],
    pub path: [u8; 64],
}
