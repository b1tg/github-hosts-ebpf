use anyhow::Context;
use aya::programs::{Xdp, XdpFlags};
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use clap::Parser;
use log::{info, warn};
use tokio::signal;

use std::io::BufRead;

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
        //core::ptr::copy_nonoverlapping(b"\x06github\x02io\x00".as_ptr(), google.as_mut_ptr(), 11)
        core::ptr::copy_nonoverlapping(
            b"\x06github\x12githubassets\x03com\x00".as_ptr(),
            google.as_mut_ptr(),
            25,
        )
    }
    github_hosts.insert(google, [4, 3, 2, 1], 0)?;

    let (k, v) = gen("123.com", "4.4.4.4").unwrap();
    github_hosts.insert(k, v, 0)?;

    let file = std::fs::File::open("github-hosts.txt").unwrap();
    let lines = std::io::BufReader::new(file).lines();

    for line in lines {
        let line = line.unwrap();
        if line.starts_with("#") || line == "" {
            continue;
        }
        let mut line_split = line.split(" ").filter(|x| x != &"");
        let ip = line_split.next().unwrap();
        let host = line_split.next().unwrap();
        println!("add github hosts: {}: {}", host, ip);
        let (k, v) = gen(host, ip).unwrap();
        github_hosts.insert(k, v, 0)?;
    }

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}

// helper function for test
fn to_256(input: &[u8]) -> [u8; 256] {
    if input.len() >= 256 {
        return input[0..256].try_into().unwrap();
    }
    let mut result = [0; 256];
    unsafe {
        core::ptr::copy_nonoverlapping(input.as_ptr(), result.as_mut_ptr(), input.len());
    }
    result
}

#[test]
fn test_gen() {
    to_256(b"\x06github\x0cgithubassets\x03com\x00");
    assert_eq!(
        gen("github.githubassets.com", "185.199.108.154"),
        Some((
            to_256(b"\x06github\x0cgithubassets\x03com\x00"),
            [185, 199, 108, 154]
        ))
    )
}

//185.199.108.154              github.githubassets.com
//140.82.112.22                central.github.com
//185.199.108.133              desktop.githubusercontent.com
//185.199.108.153              assets-cdn.github.com
fn gen(host: &str, ip: &str) -> Option<([u8; 256], [u8; 4])> {
    let mut host_with_len = [0; 256];
    let mut ips = [0; 4];
    let mut i = 0usize;
    let mut host1 = vec![];
    for part in host.split('.') {
        let part_len = part.len();
        host1.push(part_len as u8);
        host1.extend(part.as_bytes());
    }
    host1.push(0);
    unsafe {
        core::ptr::copy_nonoverlapping(host1.as_ptr(), host_with_len.as_mut_ptr(), host1.len());
    }
    if ip.split(".").count() != 4 {
        return None;
    }

    i = 0;
    for part in ip.split(".") {
        if i >= 4 {
            return None;
        }
        ips[i] = part.parse::<u8>().unwrap();
        i += 1;
    }
    return Some((host_with_len, ips));
}
