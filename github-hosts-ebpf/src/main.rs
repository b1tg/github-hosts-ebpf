#![no_std]
#![no_main]

use aya_bpf::{
    bindings::xdp_action,
    macros::xdp,
    macros::map,
    maps::HashMap,
    programs::XdpContext,
};
use aya_log_ebpf::{info, trace};

mod bindings;
use bindings::{ethhdr, iphdr, udphdr};
use core::mem;

// https://www.ietf.org/rfc/rfc1035.txt 4.1.1
#[repr(C)]
#[derive(Copy, Clone)]
pub struct dnshdr {
    pub trans_id: u16,
    pub flags: u16,
    pub qcount: [u8;2],
    pub acount: [u8;2],
    // authority_rrs
    pub nscount: [u8;2],
    // additional_rrs
    pub arcount: [u8;2],
}




const IPPROTO_UDP: u8 = 0x0011;
const ETH_P_IP: u16 = 0x0800;
const ETH_HDR_LEN: usize = mem::size_of::<ethhdr>();
const IP_HDR_LEN: usize = mem::size_of::<iphdr>();
const UDP_HDR_LEN: usize = mem::size_of::<udphdr>();

const DNS_HDR_LEN: usize = mem::size_of::<dnshdr>();

const DNS_HDR_LEN_ALL: usize = ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN+DNS_HDR_LEN;

#[map(name = "GITHUB_HOSTS")]
static mut GITHUB_HOSTS: HashMap<[u8;256], [u8;4]> =
    HashMap::<[u8;256], [u8;4]>::with_max_entries(256, 0);

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Option<*const T> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return None;
    }

    Some((start + offset) as *const T)
}

#[inline(always)]
fn ptr_at_mut<T>(ctx: &XdpContext, offset: usize) -> Option<*mut T> {
    let ptr = ptr_at::<T>(ctx, offset)?;
    Some(ptr as *mut T)
}

#[xdp(name="github_hosts")]
pub fn github_hosts(ctx: XdpContext) -> u32 {
    match try_github_hosts(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_github_hosts(ctx: XdpContext) -> Result<u32, u32> {
    trace!(&ctx, "received a packet");
    let eth = ptr_at::<ethhdr>(&ctx, 0).ok_or(xdp_action::XDP_PASS)?;
    if unsafe { u16::from_be((*eth).h_proto) } != ETH_P_IP {
        return Ok(xdp_action::XDP_PASS);
    }
    let ip = ptr_at::<iphdr>(&ctx, ETH_HDR_LEN).ok_or(xdp_action::XDP_PASS)?;
    if unsafe { (*ip).protocol } != IPPROTO_UDP {
        return Ok(xdp_action::XDP_PASS);
    }
    trace!(&ctx, "received a UDP packet");
    let udp = ptr_at_mut::<udphdr>(&ctx, ETH_HDR_LEN + IP_HDR_LEN).ok_or(xdp_action::XDP_PASS)?;
    unsafe { (*udp).check = 0 };
    let destination_port = unsafe { u16::from_be((*udp).dest) };
    let src_port = unsafe { u16::from_be((*udp).source) };
    if src_port != 53 {
        return Ok(xdp_action::XDP_PASS);
    }
    let udp_len = unsafe { u16::from_be((*udp).len) };
    let ip_dest = unsafe {
        (*ip).__bindgen_anon_1.addrs.daddr
    };
    let ip_src = unsafe {
        (*ip).__bindgen_anon_1.addrs.saddr
    };
    trace!(&ctx, "ip_src: 0x{:x}, ip_dst: 0x{:x}", ip_src, ip_dest);
    trace!(&ctx, "src_port: {}, dest_port: {}", src_port, destination_port);
    let mut data_len:usize = ctx.data_end() - ctx.data();
    trace!(&ctx, "data len: {}", data_len);
    trace!(&ctx, "udp_len: {}", udp_len);
    let dns_hdr = ptr_at_mut::<dnshdr>(&ctx, ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN).ok_or(xdp_action::XDP_PASS)?;
    if unsafe { (*dns_hdr).acount } == [0,0] {
        info!(&ctx, "no answer rrs, skip");
        return Ok(xdp_action::XDP_PASS);
    }
    let mut j = 0;
    let mut num = 0u8;
    let mut q_len = 0;
    let mut query = [0u8;256];
    let mut qi = 0;
    for _ in 0..4 {
        num = unsafe { *(ptr_at::<u8>(&ctx, (j as usize) + ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN+DNS_HDR_LEN).ok_or(xdp_action::XDP_PASS)?)  };
        if num == 0 {
            q_len += 1;
            j += 1;
            break;
        }
        j += 1;
        j += (num as usize);
        q_len += 1;
        q_len += (num as usize);
    }
    let buf_ss = unsafe { ptr_at::<u8>(&ctx, DNS_HDR_LEN_ALL ).ok_or(xdp_action::XDP_PASS)? };
    let buf_ee = unsafe { ptr_at::<u8>(&ctx, DNS_HDR_LEN_ALL+j ).ok_or(xdp_action::XDP_PASS)? };
    let mut i = 0usize;
    // TODO: size limit
    // https://www.rfc-editor.org/rfc/rfc1035 2.3.4. Size limits
    for _ in 0..255 {
        query[i] = unsafe { *(ptr_at::<u8>(&ctx, DNS_HDR_LEN_ALL+i ).ok_or(xdp_action::XDP_PASS)?) };
        i += 1;
        if unsafe { buf_ss.offset(i as _) } >= buf_ee {
            break;
        }
    }
    let ip = match unsafe { GITHUB_HOSTS.get(&query) } {
        Some(backends) => {
            info!(&ctx, "found github hosts");
            backends
        }
        None => {
            info!(&ctx, "not github hosts");
            return Ok(xdp_action::XDP_PASS);
        }
    };
    j += 4;
    let a_num = unsafe { *(ptr_at::<u8>(&ctx, (j as usize) + DNS_HDR_LEN_ALL).ok_or(xdp_action::XDP_PASS)?)  };
    trace!(&ctx, "a_num: 0x{:x}, q_len: {}", a_num, q_len);
    if a_num & 0xc0 == 0xc0 {
        trace!(&ctx, "compressed...");
        j += 2;
    } else {
        j += q_len;
    }
    let a_type = unsafe { *(ptr_at_mut::<u16>(&ctx, (j as usize) + DNS_HDR_LEN_ALL).ok_or(xdp_action::XDP_PASS)?) }; 

    let a_type = u16::from_be(a_type);
    if a_type != 1 {
        info!(&ctx, "not A record answer, skip");
        return Ok(xdp_action::XDP_PASS);
    }

    j += 10;
    let ip0 =  ptr_at_mut::<u8>(&ctx, (j as usize) + DNS_HDR_LEN_ALL).ok_or(xdp_action::XDP_PASS)?;
    let ip1 =  ptr_at_mut::<u8>(&ctx, (j as usize +1) + DNS_HDR_LEN_ALL).ok_or(xdp_action::XDP_PASS)?;
    let ip2 =  ptr_at_mut::<u8>(&ctx, (j as usize +2) + DNS_HDR_LEN_ALL).ok_or(xdp_action::XDP_PASS)?;
    let ip3 =  ptr_at_mut::<u8>(&ctx, (j as usize +3) + DNS_HDR_LEN_ALL).ok_or(xdp_action::XDP_PASS)?;
    info!(&ctx, "old ip: {}.{}.{}.{}", unsafe{*ip0}, unsafe{*ip1}, unsafe{*ip2}, unsafe{*ip3});
    unsafe { *ip0 = ip[0] }
    unsafe { *ip1 = ip[1] }
    unsafe { *ip2 = ip[2] }
    unsafe { *ip3 = ip[3] }
    info!(&ctx, "new ip: {}.{}.{}.{}", unsafe{*ip0}, unsafe{*ip1}, unsafe{*ip2}, unsafe{*ip3});
    return Ok(xdp_action::XDP_PASS);
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
