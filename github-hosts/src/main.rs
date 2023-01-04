use anyhow::Context;
use aya::programs::{Xdp, XdpFlags};
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use clap::Parser;
use log::{info, warn};
use tokio::signal;

use aya::maps::HashMap;
//use github_hosts_common::BackendPorts;

#[derive(Debug, Parser)]
struct Opt {
    //#[clap(short, long, default_value = "lo")]
    #[clap(short, long, default_value = "eth0")]
    iface: String,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();

    env_logger::init();

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/github-hosts"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/github-hosts"
    ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    let program: &mut Xdp = bpf.program_mut("github_hosts").unwrap().try_into()?;
    program.load()?;
    program.attach(&opt.iface, XdpFlags::default())
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    let mut github_hosts: HashMap<_, [u8; 256], [u8; 4]> =
        HashMap::try_from(bpf.map_mut("GITHUB_HOSTS")?)?;

    let mut google = [0; 256];
    unsafe {
        core::ptr::copy_nonoverlapping(b"\x06google\x03com\x00".as_ptr(), google.as_mut_ptr(), 12)
    }
    github_hosts.insert(google, [1, 2, 3, 4], 0)?;
    let mut google = [0; 256];
    unsafe {
        core::ptr::copy_nonoverlapping(b"\x06github\x02io\x00".as_ptr(), google.as_mut_ptr(), 11)
    }
    github_hosts.insert(google, [4, 3, 2, 1], 0)?;

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
