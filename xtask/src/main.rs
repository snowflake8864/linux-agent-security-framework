use std::env;
use std::fs;
use std::path::Path;
use std::process::Command;

fn main() {
    let args: Vec<String> = env::args().collect();

    match args.get(1).map(String::as_str) {
        Some("build-bpf") => {
            let arch = args.get(2).map(String::as_str);
            if let Err(e) = build_bpf(arch) {
                eprintln!("Failed to build BPF object: {e}");
                std::process::exit(1);
            }
        }
        Some("build-all") => {
            let target = args.get(2).map(String::as_str);
            if let Err(e) = build_all(target) {
                eprintln!("Failed to build: {e}");
                std::process::exit(1);
            }
        }
        Some("run-demo") => {
            println!("Running demo: cargo run -p demo");
            let status = Command::new("cargo")
                .args(["run", "-p", "demo"])
                .status()
                .expect("failed to run cargo run -p demo");
            if !status.success() {
                std::process::exit(status.code().unwrap_or(1));
            }
        }
        _ => {
            eprintln!("Usage:");
            eprintln!("  xtask build-bpf [x86|aarch64]    - Build BPF objects");
            eprintln!("  xtask build-all [target]          - Build BPF + Rust binaries");
            eprintln!("  xtask run-demo                    - Run demo program");
            eprintln!("");
            eprintln!("Examples:");
            eprintln!("  xtask build-bpf x86               - Build for x86_64");
            eprintln!("  xtask build-bpf aarch64           - Build for ARM64");
            eprintln!("  xtask build-all                   - Build for host");
            eprintln!("  xtask build-all x86_64-unknown-linux-musl");
            eprintln!("  xtask build-all aarch64-unknown-linux-musl");
        }
    }
}

fn build_bpf(arch: Option<&str>) -> Result<(), Box<dyn std::error::Error>> {
    let out_dir = Path::new("bpf");
    fs::create_dir_all(out_dir)?;

    // Determine target architecture
    let (target_arch, arch_define) = match arch {
        Some("aarch64") | Some("arm64") => ("aarch64", "__TARGET_ARCH_arm64"),
        Some("x86") | Some("x86_64") | None => ("x86_64", "__TARGET_ARCH_x86"),
        Some(other) => {
            return Err(format!("Unsupported architecture: {}", other).into());
        }
    };

    println!("Building BPF for architecture: {}", target_arch);

    // Build agent.bpf.o (main BPF program with LSM hooks)
    let src = "ebpf-probes/bpf/agent.bpf.c";
    let out = out_dir.join("agent.bpf.o");
    println!("Building BPF: {src} -> {}", out.display());

    let status = Command::new("clang")
        .args([
            "-target",
            "bpf",
            "-D",
            arch_define, // Define target architecture
            "-I",
            "ebpf-probes/bpf",
            "-O2",
            "-g",
            "-c",
            src,
            "-o",
            out.to_str().unwrap(),
        ])
        .status()?;

    if !status.success() {
        return Err("clang failed to compile agent.bpf.c".into());
    }

    // Build tc_pkt_mod.bpf.o (standalone TC packet modifier)
    let tc_src = "ebpf-probes/bpf/tc_pkt_mod.bpf.c";
    let tc_out = out_dir.join("tc_pkt_mod.bpf.o");
    println!("Building TC BPF: {tc_src} -> {}", tc_out.display());

    let status = Command::new("clang")
        .args([
            "-target",
            "bpf",
            "-D",
            arch_define,
            "-I",
            "ebpf-probes/bpf",
            "-O2",
            "-g",
            "-c",
            tc_src,
            "-o",
            tc_out.to_str().unwrap(),
        ])
        .status()?;

    if !status.success() {
        return Err("clang failed to compile tc_pkt_mod.bpf.c".into());
    }

    // Build xdp_pkt_mod.bpf.o (XDP packet modifier)
    let xdp_src = "ebpf-probes/bpf/xdp_pkt_mod.bpf.c";
    let xdp_out = out_dir.join("xdp_pkt_mod.bpf.o");
    println!("Building XDP BPF: {xdp_src} -> {}", xdp_out.display());

    let status = Command::new("clang")
        .args([
            "-target",
            "bpf",
            "-D",
            arch_define,
            "-I",
            "ebpf-probes/bpf",
            "-O2",
            "-g",
            "-c",
            xdp_src,
            "-o",
            xdp_out.to_str().unwrap(),
        ])
        .status()?;

    if !status.success() {
        return Err("clang failed to compile xdp_pkt_mod.bpf.c".into());
    }

    // Build forward.bpf.o (cgroup/connect forward program)
    let forward_src = "ebpf-probes/bpf/forward.bpf.c";
    let forward_out = out_dir.join("forward.bpf.o");
    println!(
        "Building Forward BPF: {forward_src} -> {}",
        forward_out.display()
    );

    let status = Command::new("clang")
        .args([
            "-target",
            "bpf",
            "-D",
            arch_define,
            "-I",
            "ebpf-probes/bpf",
            "-O2",
            "-g",
            "-c",
            forward_src,
            "-o",
            forward_out.to_str().unwrap(),
        ])
        .status()?;

    if !status.success() {
        return Err("clang failed to compile forward.bpf.c".into());
    }

    // Build unified_agent.bpf.o
    let unified_src = "ebpf-probes/bpf/unified_agent.bpf.c";
    let unified_out = out_dir.join("unified_agent.bpf.o");
    println!(
        "Building Unified BPF: {unified_src} -> {}",
        unified_out.display()
    );

    let status = Command::new("clang")
        .args([
            "-target",
            "bpf",
            "-D",
            arch_define,
            "-I",
            "ebpf-probes/bpf",
            "-O2",
            "-g",
            "-c",
            unified_src,
            "-o",
            unified_out.to_str().unwrap(),
        ])
        .status()?;

    if !status.success() {
        return Err("clang failed to compile unified_agent.bpf.c".into());
    }

    println!("✓ BPF objects built successfully for {}", target_arch);
    Ok(())
}

fn build_all(target: Option<&str>) -> Result<(), Box<dyn std::error::Error>> {
    // Step 1: Determine target and architecture
    let (rust_target, bpf_arch) = match target {
        Some("aarch64-unknown-linux-musl") => ("aarch64-unknown-linux-musl", Some("aarch64")),
        Some("x86_64-unknown-linux-musl") => ("x86_64-unknown-linux-musl", Some("x86_64")),
        Some("aarch64-unknown-linux-gnu") => ("aarch64-unknown-linux-gnu", Some("aarch64")),
        Some("x86_64-unknown-linux-gnu") => ("x86_64-unknown-linux-gnu", Some("x86_64")),
        None => {
            // Auto-detect host architecture
            let host_arch = env::consts::ARCH;
            match host_arch {
                "x86_64" => ("x86_64-unknown-linux-musl", Some("x86_64")),
                "aarch64" => ("aarch64-unknown-linux-musl", Some("aarch64")),
                _ => return Err(format!("Unsupported host architecture: {}", host_arch).into()),
            }
        }
        Some(other) => return Err(format!("Unsupported target: {}", other).into()),
    };

    println!("\n=== Building for target: {} ===", rust_target);

    // Step 2: Build BPF objects
    println!("\n[1/2] Building BPF objects...");
    build_bpf(bpf_arch)?;

    // Step 3: Build Rust binaries
    println!("\n[2/2] Building Rust binaries...");

    // Check if cargo-zigbuild is available
    let has_zigbuild = Command::new("cargo")
        .args(["zigbuild", "--version"])
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false);

    let cargo_cmd = if rust_target.contains("musl") && has_zigbuild {
        println!("Using cargo-zigbuild for static musl compilation");
        "zigbuild"
    } else {
        println!("Using cargo build");
        "build"
    };

    let status = Command::new("cargo")
        .arg(cargo_cmd)
        .args(["--release", "--target", rust_target])
        .status()?;

    if !status.success() {
        return Err("cargo build failed".into());
    }

    println!("\n✓ Build completed successfully!");
    println!("Binaries located at: target/{}/release/", rust_target);
    println!("BPF objects located at: bpf/");

    Ok(())
}
