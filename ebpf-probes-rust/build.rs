//! Build script for eBPF probes using Aya
//!
//! Ensures proper build configuration for eBPF programs

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src/");
}
