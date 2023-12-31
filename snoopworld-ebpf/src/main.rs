#![no_std]
#![no_main]

#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
mod vmlinux;

use core::ffi::c_char;
use core::mem::transmute;
use memoffset::offset_of;

use aya_bpf::{
    cty::{c_void, uintptr_t},
    helpers::{
        bpf_probe_read, bpf_probe_read_kernel, bpf_probe_read_kernel_str_bytes,
    },
    macros::kprobe,
    programs::ProbeContext,
    
};
use aya_log_ebpf::{error, info};

use vmlinux::{sock, sockaddr_un, socket, unix_address, unix_sock};

#[kprobe]
pub fn snoopworld(ctx: ProbeContext) -> u32 {
    match unsafe { try_snoopworld(ctx) } {
        Ok(ret) => ret,
        Err(ret) => match ret.try_into() {
            Ok(rt) => rt,
            Err(_) => 1,
        },
    }
}

unsafe fn try_snoopworld(ctx: ProbeContext) -> Result<u32, i64> {
    info!(&ctx, "function unix_stream_sendmsg called");

    let my_socket: *const socket = ctx.arg(0).ok_or(1i64)?;
    let msock = bpf_probe_read_kernel(&((*my_socket).sk)).map_err(|e| {
        error!(&ctx, "my_socket failed: {}", e);
        e as i64
    })?;
    info!(&ctx, "sock",);
    let family = bpf_probe_read_kernel(&(*msock).__sk_common.skc_family).map_err(|e| {
        error!(&ctx, "sock failed {}", e);
        e as i64
    })?;

    if family == 1 {
        info!(&ctx, "family {}", family);
        

    }
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
