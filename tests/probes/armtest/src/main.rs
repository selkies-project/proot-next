//! Static 32-bit ARM probe: exercises the syscalls proot-next translates for AArch32 tracees.
use std::ffi::CString;
fn main() {
    let arg = std::env::args().nth(1).unwrap_or_else(|| "/etc/hostname".into());
    unsafe {
        let mut buf = [0u8; 256];
        let n = libc::readlink(c"/proc/self/exe".as_ptr(), buf.as_mut_ptr() as *mut _, 256);
        println!("readlink /proc/self/exe -> {}", if n > 0 { String::from_utf8_lossy(&buf[..n as usize]).to_string() } else { format!("errno {}", *libc::__errno_location()) });
        let mut cwd = [0u8; 256];
        let p = libc::getcwd(cwd.as_mut_ptr() as *mut _, 256);
        println!("getcwd -> {}", if p.is_null() { "failed".into() } else { String::from_utf8_lossy(&cwd[..cwd.iter().position(|&b| b == 0).unwrap_or(0)]).to_string() });
        let c = CString::new(arg.clone()).unwrap();
        let mut st: libc::stat64 = std::mem::zeroed();
        let rc = libc::stat64(c.as_ptr(), &mut st);
        println!("stat64 {arg} -> rc={rc} size={} mode={:o}", st.st_size, st.st_mode);
        let fd = libc::open(c.as_ptr(), libc::O_RDONLY);
        if fd >= 0 {
            let n = libc::read(fd, buf.as_mut_ptr() as *mut _, 64);
            println!("open+read {arg} -> {} bytes: {:?}", n, String::from_utf8_lossy(&buf[..n.max(0) as usize]).trim_end());
            libc::close(fd);
        } else {
            println!("open {arg} -> errno {}", *libc::__errno_location());
        }
        let d = libc::open(c"/".as_ptr(), libc::O_PATH | libc::O_DIRECTORY);
        println!("O_PATH open / -> fd={d}");
        let rc = libc::chdir(c"/tmp".as_ptr());
        libc::getcwd(cwd.as_mut_ptr() as *mut _, 256);
        println!("chdir /tmp -> rc={rc}, getcwd={}", String::from_utf8_lossy(&cwd[..cwd.iter().position(|&b| b == 0).unwrap_or(0)]));
        let mut u: libc::utsname = std::mem::zeroed();
        libc::uname(&mut u);
        println!("uname machine={} release={}", std::ffi::CStr::from_ptr(u.machine.as_ptr()).to_string_lossy(), std::ffi::CStr::from_ptr(u.release.as_ptr()).to_string_lossy());
    }
}
