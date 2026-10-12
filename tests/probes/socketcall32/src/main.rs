//! 32-bit client that connects to a unix socket through the legacy socketcall multiplexer.
use std::ffi::CString;
fn main() {
    let path = std::env::args().nth(1).expect("socket path");
    unsafe {
        let fd = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0);
        let mut sa: libc::sockaddr_un = std::mem::zeroed();
        sa.sun_family = libc::AF_UNIX as u16;
        let c = CString::new(path.clone()).unwrap();
        std::ptr::copy_nonoverlapping(c.as_ptr(), sa.sun_path.as_mut_ptr(), c.as_bytes().len());
        let len = 2 + c.as_bytes().len() + 1;
        // socketcall(SYS_CONNECT=3, args[] = {fd, &sa, len}) exactly as i386 glibc does.
        let args: [u32; 3] = [fd as u32, &sa as *const _ as u32, len as u32];
        let rc = libc::syscall(102, 3i32, args.as_ptr());
        if rc < 0 {
            let e = *libc::__errno_location();
            println!("socketcall connect {path}: FAILED errno {e}");
            std::process::exit(1);
        }
        let mut buf = [0u8; 32];
        let n = libc::read(fd, buf.as_mut_ptr() as *mut _, 32);
        println!("socketcall connect {path}: ok, server said {:?}", String::from_utf8_lossy(&buf[..n.max(0) as usize]));
    }
}
