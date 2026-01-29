//! eBPF Security Framework - Kernel Space Probes (Aya-based)
//!
//! This module contains the eBPF programs that run in kernel space using Aya framework.

#![no_std]
#![no_main]

mod file;

use aya_ebpf::{macros::map, maps::HashMap};
use ebpf_common::GlobalConfig;

/// Global configuration map
#[map]
static CONFIG: HashMap<u32, GlobalConfig> = HashMap::with_max_entries(1, 0);

/// Get global configuration
#[inline(always)]
pub fn get_config() -> GlobalConfig {
    unsafe {
        match CONFIG.get(&0) {
            Some(cfg) => *cfg,
            None => GlobalConfig::default(),
        }
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
