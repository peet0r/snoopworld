#![no_std]
#![no_main]

#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
mod vmlinux;

use core::ffi::c_char;

use memoffset::offset_of;

use aya_bpf::{
    cty::c_void,
    helpers::{bpf_probe_read_user_buf, bpf_probe_read_kernel, bpf_get_current_uid_gid},
    macros::kprobe,
    programs::ProbeContext,
};
use aya_log_ebpf::info;

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

    let socket: *const socket = ctx.arg(0).ok_or(1i32)?;
    let us_ptr = bpf_probe_read_kernel(&(*socket).sk).map_err(|e|e)? as *mut unix_address;
    let oops = us_ptr.add(14) as *mut c_char;
    let d = bpf_probe_read_kernel(oops).map_err(|e|e)?;
//    let what = core::str::from_utf8_unchecked(d asu8]);
    //let derp = bpf_probe_read_kernel(&(*us_ptr).len).map_err(|e|e)?;
//let derp = 10;
    //    let offset = offset_of!(unix_address, name) + offset_of!(sockaddr_un, sun_path);
//    let d = us_ptr.add(offset_of!(unix_address, name) + offset_of!(sockaddr_un, sun_path)) as *const c_char; 
//    let us_ptr = bpf_probe_read_kernel(((*socket).sk as *const unix_sock).add((offset_of!(unix_address, name) + offset_of!(sockaddr_un, sun_path))) as *const c_char);
//    let d = bpf_probe_read_kernel((*us_ptr).addr).map_err(|e| e)?;
    //let mut buf = [0u8;30];
    //let buf_ptr = buf.as_mut_ptr() as *mut c_void;
    info!(&ctx, "woah: {}, {}, {}", socket as u64, us_ptr as u64, d);
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
