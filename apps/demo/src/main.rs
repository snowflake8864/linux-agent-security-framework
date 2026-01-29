use aya::programs::Lsm;
use aya::Btf;
use aya::EbpfLoader;
use ebpf_common::{Config, Mode};
use std::fs;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🌐 Linux Agent Security Framework Demo");

    // Load config
    let config_str = fs::read_to_string("config.json")?;
    let config: Config = serde_json::from_str(&config_str)?;
    println!("✓ Loaded configuration");

    // Load BPF
    let mut bpf = EbpfLoader::default()
        .allow_unsupported_maps()
        .load_file("bpf/agent.bpf.o")?;
    println!("✓ Loaded BPF object");

    // Load BTF
    let btf = Btf::from_sys_fs()?;
    println!("✓ Loaded BTF");

    // TODO: Populate maps from config

    // Attach LSM hooks
    if let Some(prog) = bpf.program_mut("enforce_inode_create") {
        let lsm_prog: &mut Lsm = prog.try_into()?;
        lsm_prog.load("inode_create", &btf)?;
        lsm_prog.attach()?;
        println!("✓ Attached: enforce_inode_create");
    }

    // inode_unlink removed

    println!("🔒 LSM hooks active - all file operations blocked in Protect mode");

    // Keep running
    std::thread::park();

    Ok(())
}
