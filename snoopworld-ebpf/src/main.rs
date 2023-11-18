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
    cty::{c_void, uintptr_t},
    helpers::{bpf_probe_read, bpf_probe_read_kernel, bpf_skc_to_unix_sock},
    macros::kprobe,
    programs::ProbeContext,
};
use aya_log_ebpf::info;

use vmlinux::{sock, sockaddr_un, socket, unix_address, unix_sock};

use crate::vmlinux::sock_common;

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

    let m = bpf_probe_read(&(*my_socket).sk)? as u64;
    let d = m as *const sock;
    let sk = bpf_probe_read(&(*d).__sk_common as *const sock_common)?;

    //let ss = bpf_probe_read(&(*d).addr)?;
    //let g = bpf_probe_read(&(*s).len)?;
    //    let address = bpf_probe_read_kernel(&(*us_ptr).addr)?;
    if sk.skc_family == 1u16 {
        info!(&ctx, "waodh: {} {}", 1, 1 as u64);
    }

    let u = (m - offset_of!(unix_sock, sk) as u64) as *const unix_sock;
    let g = bpf_probe_read(&(*u).addr)?;
    if !g.is_null() {
        let l = (*g).len;
        info!(&ctx, "{}", g as u64);
    }
    // let sk_ptr = bpf_probe_read_kernel(&(*(*my_socket).sk))?;
    // let us_ptr = bpf_probe_read_kernel(&sk_ptr.__sk_common)?;
    // if us_ptr.skc_family == 1{
    //   info!(&ctx, "woah");
    // }
    //let g = (*d).type_;
    // info!(&ctx, "{}", address.len);
    // let addr_len = (*(*((*socket).sk as *const unix_sock)).addr).len;
    //let derp = bpf_probe_read(&(*(*((*socket).sk as *mut unix_sock)).addr)).map_err(|e|e)?;
    //let d = derp.len;
    //let us_ptr = bpf_probe_read_kernel(&(*d).sk).map_err(|e| e)? as *mut unix_sock;
    //if !us_ptr.is_null() {
    //   let us_addr = (*us_ptr).addr;
    //   let address = bpf_probe_read_kernel(us_addr).map_err(|e| {
    //       info!(&ctx, "could not read addr");
    //       1
    //   })?;
    //
    //       info!(&ctx, "woah {}", address.len);
    //   }
    //    let us_addr  = bpf_probe_read_kernel(&(*(*us_ptr).addr).len).map_err(|e|e)?;

    // New
    //  let d = (*us_ptr).addr as i64;
    //  info!(&ctx, "{}", d);
    // End new

    // Ideas to try:
    // - bpf_probe_read() copied straight from bcc impl?

    // THis kinda doesnt work start

    // I think .len == 0 always...
    //   let addr = (*us_ptr).name.as_slice((*us_ptr).len.try_into().unwrap());
    //   let path = addr[1].sun_path;
    //   let path_str = core::str::from_utf8(&path).map_err(|_|1)?;
    //   info!(&ctx, "{}", path_str);
    // end
    // THis kinda works start
    //let s = bpf_probe_read_kernel(&(*us_ptr).addr).map_err(|e| e)?;
    // let oops =
    //    us_ptr as uintptr_t  + offset_of!(unix_address, name) + offset_of!(sockaddr_un, sun_path);

    //let d = bpf_probe_read_kernel(oops as *mut u8).map_err(|e| e)?;
    // info!(&ctx, "woah {}", (*s).len);

    //
    //    END
    // if (*us_ptr).len > 0 {
    //     let buf = [0u8; 108];
    //     let _ = bpf_probe_read_kernel_str(oops as *mut c_void, 1, buf.as_ptr() as *const c_void);
    // }
    // let _ = bpf_probe_read_kernel_buf(oops, &mut buf).map_err(|e|e)?;
    //  let g = core::str::from_utf8(&buf).map_err(|_|1)?;
    //    let what = core::str::from_utf8_unchecked(d asu8]);
    //let derp = bpf_probe_read_kernel(&(*us_ptr).len).map_err(|e|e)?;
    //let derp = 10;
    //    let offset = offset_of!(unix_address, name) + offset_of!(sockaddr_un, sun_path);
    //    let d = us_ptr.add(offset_of!(unix_address, name) + offset_of!(sockaddr_un, sun_path)) as *const c_char;
    //    let us_ptr = bpf_probe_read_kernel(((*socket).sk as *const unix_sock).add((offset_of!(unix_address, name) + offset_of!(sockaddr_un, sun_path))) as *const c_char);
    //    let d = bpf_probe_read_kernel((*us_ptr).addr).map_err(|e| e)?;
    //let mut buf = [0u8;30];
    //let buf_ptr = buf.as_mut_ptr() as *mut c_void;
    // let a = buf.clone();
    // let aa = core::str::from_utf8(&a).map_err(|_|1)?;

    // info!(&ctx, "woah: {}", aa);
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
