//! The exec trampoline for the no-ptrace mode of proot-next.
//!
//! Without ptrace the supervisor cannot point an `execve` at the guest's
//! dynamic loader: registers are read-only from a seccomp notification and
//! the only thing it can change is the path string in the tracee's memory,
//! which may be as short as two bytes.  So the string becomes `e`, a copy of
//! this program in the directory every tracee has as its kernel working
//! directory, and the real exec is described in a record file next to it,
//! named after the process id.  This program reads the record, rebuilds the
//! argument vector and execs the target with the environment it inherited.
//!
//! Record format, NUL-separated fields: the number of leading arguments as
//! decimal text, the path to exec, then that many arguments.  The caller's
//! own `argv[1..]` follows them.  No libc beyond raw syscalls is used so a
//! single static binary serves every guest, whatever its libc.
#![no_std]
#![no_main]

use core::ffi::c_char;

#[link(name = "c", kind = "static")]
unsafe extern "C" {}

/// Largest record accepted; a loader path, `--argv0`, a name and a program path fit many times over.
const RECORD_MAX: usize = 1 << 16;
/// Largest argument vector forwarded, the kernel's own ceiling being far below this.
const ARGV_MAX: usize = 1 << 17;
/// Most leading arguments a record may carry.
const PREFIX_MAX: usize = 64;

static mut RECORD: [u8; RECORD_MAX] = [0; RECORD_MAX];
static mut ARGV: [*const c_char; ARGV_MAX + PREFIX_MAX + 1] = [core::ptr::null(); ARGV_MAX + PREFIX_MAX + 1];

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    unsafe { libc::_exit(126) }
}

/// Writes a short diagnostic to stderr.
fn say(parts: &[&[u8]]) {
    for p in parts {
        unsafe { libc::write(2, p.as_ptr() as *const _, p.len()) };
    }
}

/// Formats a non-negative number as decimal into `buf`, returning the used slice.
fn itoa(mut n: u64, buf: &mut [u8; 20]) -> &[u8] {
    let mut i = buf.len();
    loop {
        i -= 1;
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    &buf[i..]
}

/// Entry point called by musl's startup code with the exec'd argument vector.
///
/// # Arguments
/// * `argc` - Number of entries in `argv`.
/// * `argv` - The caller's original arguments; `argv[0]` is replaced by the record.
/// * `envp` - The caller's environment, passed on unchanged.
#[unsafe(no_mangle)]
pub extern "C" fn main(argc: i32, argv: *const *const c_char, envp: *const *const c_char) -> i32 {
    unsafe {
        let pid = libc::getpid() as u64;
        let mut num = [0u8; 20];
        let digits = itoa(pid, &mut num);
        let mut name = [0u8; 24];
        name[0] = b'r';
        name[1..1 + digits.len()].copy_from_slice(digits);
        let fd = libc::open(name.as_ptr() as *const c_char, libc::O_RDONLY | libc::O_CLOEXEC);
        if fd < 0 {
            say(&[b"proot: exec shim: no record ", &name[..1 + digits.len()], b"\n"]);
            return 126;
        }
        let record = &mut *core::ptr::addr_of_mut!(RECORD);
        let mut len = 0usize;
        loop {
            let n = libc::read(fd, record.as_mut_ptr().add(len) as *mut _, RECORD_MAX - len);
            if n <= 0 {
                break;
            }
            len += n as usize;
            if len == RECORD_MAX {
                break;
            }
        }
        libc::close(fd);
        libc::unlink(name.as_ptr() as *const c_char);
        if len == 0 || len == RECORD_MAX || record[len - 1] != 0 {
            say(&[b"proot: exec shim: bad record\n"]);
            return 126;
        }
        let mut fields: [*const c_char; PREFIX_MAX + 2] = [core::ptr::null(); PREFIX_MAX + 2];
        let mut nfields = 0usize;
        let mut start = 0usize;
        for i in 0..len {
            if record[i] == 0 {
                if nfields == fields.len() {
                    say(&[b"proot: exec shim: record too long\n"]);
                    return 126;
                }
                fields[nfields] = record.as_ptr().add(start) as *const c_char;
                nfields += 1;
                start = i + 1;
            }
        }
        if nfields < 2 {
            say(&[b"proot: exec shim: short record\n"]);
            return 126;
        }
        let mut count = 0usize;
        let mut p = fields[0] as *const u8;
        while *p != 0 {
            count = count * 10 + (*p - b'0') as usize;
            p = p.add(1);
        }
        if count + 2 != nfields {
            say(&[b"proot: exec shim: record count mismatch\n"]);
            return 126;
        }
        let path = fields[1];
        let out = &mut *core::ptr::addr_of_mut!(ARGV);
        let mut n = 0usize;
        for f in &fields[2..2 + count] {
            out[n] = *f;
            n += 1;
        }
        let mut i = 1usize;
        while i < argc.max(0) as usize && n < ARGV_MAX + PREFIX_MAX {
            out[n] = *argv.add(i);
            n += 1;
            i += 1;
        }
        out[n] = core::ptr::null();
        libc::execve(path, out.as_ptr(), envp);
        let e = *libc::__errno_location();
        let mut ebuf = [0u8; 20];
        let edigits = itoa(e as u64, &mut ebuf);
        let plen = libc::strlen(path);
        say(&[
            b"proot: exec shim: cannot execute ",
            core::slice::from_raw_parts(path as *const u8, plen),
            b": errno ",
            edigits,
            b"\n",
        ]);
        if e == libc::ENOENT { 127 } else { 126 }
    }
}
