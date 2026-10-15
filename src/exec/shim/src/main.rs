//! The exec trampoline of proot-next.
//!
//! Without ptrace the supervisor cannot point an `execve` at the guest's
//! dynamic loader: registers are read-only from a seccomp notification and
//! the only thing it can change is the path string in the tracee's memory,
//! which may be as short as two bytes.  So the string becomes `e`, a copy of
//! this program in the directory every tracee has as its kernel working
//! directory, and the real exec is described in a record file next to it,
//! named after the process id.  A nested proot or bwrap launch takes the
//! trampoline in both modes, exec'd by its full path with ptrace, so the
//! record is also looked for next to this program's own executable.
//!
//! The record is a sequence of netstrings (`<length>:<bytes>,`), each a
//! one-byte tag and a value; text values end in a NUL.  `v2` comes first.
//! `A<n>` gives `n` leading arguments (tagged `-`) to put before this
//! program's own `argv[1..]`; `a<n>` gives the complete vector.  `p` is the
//! path to exec, `e<n>` an environment replacing the inherited one, `c` a
//! directory to enter, `s` asks for a new session, `d` to die with the
//! parent, `S` carries a classic BPF program to install, `I` a descriptor
//! to receive `{"child-pid": N}`, `J` one to receive that and later
//! `{"exit-code": N}`, for which this program forks and its parent stays to
//! wait and report.  `W` prints a line on stderr; `E<code>:<text>` and
//! `O<code>:<text>` print on stderr or stdout and exit with the code.
//!
//! No libc beyond raw syscalls is used so a single static binary serves
//! every guest, whatever its libc.
#![no_std]
#![no_main]

use core::ffi::c_char;

#[link(name = "c", kind = "static")]
unsafe extern "C" {}

/// Largest record accepted; an environment and a few BPF programs fit many times over.
const RECORD_MAX: usize = 1 << 20;
/// Largest argument vector forwarded, the kernel's own ceiling being far below this.
const ARGV_MAX: usize = 1 << 17;
/// Largest environment forwarded.
const ENV_MAX: usize = 1 << 15;
/// Most seccomp programs a record may carry.
const PROGRAMS_MAX: usize = 16;
/// Most status descriptors of one kind a record may carry.
const FDS_MAX: usize = 32;

const SECCOMP_SET_MODE_FILTER: libc::c_long = 1;

static mut RECORD: [u8; RECORD_MAX] = [0; RECORD_MAX];
static mut ARGV: [*const c_char; ARGV_MAX + 1] = [core::ptr::null(); ARGV_MAX + 1];
static mut ENVP: [*const c_char; ENV_MAX + 1] = [core::ptr::null(); ENV_MAX + 1];

/// `struct sock_fprog` as the kernel reads it.
#[repr(C)]
struct SockFprog {
    len: u16,
    filter: *const u8,
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    unsafe { libc::_exit(126) }
}

/// Writes a short diagnostic to `fd`.
fn say_to(fd: i32, parts: &[&[u8]]) {
    for p in parts {
        unsafe { libc::write(fd, p.as_ptr() as *const _, p.len()) };
    }
}

/// Writes a short diagnostic to stderr.
fn say(parts: &[&[u8]]) {
    say_to(2, parts);
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

/// Parses leading decimal digits, returning the value and how many bytes it took.
fn atoi(bytes: &[u8]) -> (u64, usize) {
    let mut n = 0u64;
    let mut i = 0;
    while i < bytes.len() && bytes[i].is_ascii_digit() {
        n = n.wrapping_mul(10).wrapping_add((bytes[i] - b'0') as u64);
        i += 1;
    }
    (n, i)
}

/// What the record asked for.
struct Plan {
    path: *const c_char,
    argc: usize,
    complete: bool,
    envc: usize,
    env_given: bool,
    chdir: *const c_char,
    new_session: bool,
    die_with_parent: bool,
    programs: [(*const u8, usize); PROGRAMS_MAX],
    nprograms: usize,
    info: [i32; FDS_MAX],
    ninfo: usize,
    json: [i32; FDS_MAX],
    njson: usize,
    exit: Option<(i32, *const u8, usize, bool)>,
}

/// Which counted list the next `-` fields belong to.
#[derive(Clone, Copy, PartialEq, Eq)]
enum List {
    None,
    Argv,
    Env,
}

/// Writes `{"<key>": <n>}\n` to `fd`.
fn write_json(fd: i32, key: &[u8], n: u64) {
    let mut num = [0u8; 20];
    let digits = itoa(n, &mut num);
    say_to(fd, &[b"{\"", key, b"\": ", digits, b"}\n"]);
}

/// Opens the record for this process: `r<pid>` in the working directory
/// (no ptrace) or next to this program (ptrace).
unsafe fn open_record(pid: u64, name: &mut [u8; 24], name_len: &mut usize) -> i32 {
    unsafe {
        let mut num = [0u8; 20];
        let digits = itoa(pid, &mut num);
        name[0] = b'r';
        name[1..1 + digits.len()].copy_from_slice(digits);
        *name_len = 1 + digits.len();
        let fd = libc::open(name.as_ptr() as *const c_char, libc::O_RDONLY | libc::O_CLOEXEC);
        if fd >= 0 {
            return fd;
        }
        let mut exe = [0u8; 4096];
        let n = libc::readlink(
            b"/proc/self/exe\0".as_ptr() as *const c_char,
            exe.as_mut_ptr() as *mut c_char,
            exe.len() - 32,
        );
        if n <= 0 {
            return -1;
        }
        let mut end = n as usize;
        while end > 0 && exe[end - 1] != b'/' {
            end -= 1;
        }
        exe[end..end + *name_len].copy_from_slice(&name[..*name_len]);
        exe[end + *name_len] = 0;
        let fd = libc::open(exe.as_ptr() as *const c_char, libc::O_RDONLY | libc::O_CLOEXEC);
        if fd >= 0 {
            libc::unlink(exe.as_ptr() as *const c_char);
        }
        fd
    }
}

/// Entry point called by musl's startup code with the exec'd argument vector.
///
/// # Arguments
/// * `argc` - Number of entries in `argv`.
/// * `argv` - The caller's original arguments; `argv[0]` is replaced by the record.
/// * `envp` - The caller's environment, passed on unless the record replaces it.
#[unsafe(no_mangle)]
pub extern "C" fn main(argc: i32, argv: *const *const c_char, envp: *const *const c_char) -> i32 {
    unsafe {
        let pid = libc::getpid() as u64;
        let mut name = [0u8; 24];
        let mut name_len = 0usize;
        let fd = open_record(pid, &mut name, &mut name_len);
        if fd < 0 {
            say(&[b"proot: exec shim: no record ", &name[..name_len], b"\n"]);
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
        if len == 0 || len == RECORD_MAX {
            say(&[b"proot: exec shim: bad record\n"]);
            return 126;
        }
        let out = &mut *core::ptr::addr_of_mut!(ARGV);
        let env_out = &mut *core::ptr::addr_of_mut!(ENVP);
        let mut plan = Plan {
            path: core::ptr::null(),
            argc: 0,
            complete: false,
            envc: 0,
            env_given: false,
            chdir: core::ptr::null(),
            new_session: false,
            die_with_parent: false,
            programs: [(core::ptr::null(), 0); PROGRAMS_MAX],
            nprograms: 0,
            info: [0; FDS_MAX],
            ninfo: 0,
            json: [0; FDS_MAX],
            njson: 0,
            exit: None,
        };
        let mut list = List::None;
        let mut pos = 0usize;
        let mut first = true;
        while pos < len {
            let (flen, used) = atoi(&record[pos..]);
            let flen = flen as usize;
            if used == 0
                || pos + used >= len
                || record[pos + used] != b':'
                || pos + used + 1 + flen >= len
                || record[pos + used + 1 + flen] != b','
                || flen == 0
            {
                say(&[b"proot: exec shim: bad record\n"]);
                return 126;
            }
            let field = &record[pos + used + 1..pos + used + 1 + flen];
            pos += used + 1 + flen + 1;
            let tag = field[0];
            let value = &field[1..];
            let text = value.as_ptr() as *const c_char;
            if first {
                if tag != b'v' || value != b"2\0" {
                    say(&[b"proot: exec shim: unknown record version\n"]);
                    return 126;
                }
                first = false;
                continue;
            }
            match tag {
                b'-' => match list {
                    List::Argv if plan.argc < ARGV_MAX => {
                        out[plan.argc] = text;
                        plan.argc += 1;
                    }
                    List::Env if plan.envc < ENV_MAX => {
                        env_out[plan.envc] = text;
                        plan.envc += 1;
                    }
                    _ => {}
                },
                b'A' | b'a' => {
                    list = List::Argv;
                    plan.complete = tag == b'a';
                }
                b'e' => {
                    list = List::Env;
                    plan.env_given = true;
                }
                b'p' => plan.path = text,
                b'c' => plan.chdir = text,
                b's' => plan.new_session = true,
                b'd' => plan.die_with_parent = true,
                b'S' => {
                    if plan.nprograms < PROGRAMS_MAX {
                        plan.programs[plan.nprograms] = (value.as_ptr(), value.len());
                        plan.nprograms += 1;
                    }
                }
                b'I' | b'J' => {
                    let (n, _) = atoi(value);
                    if tag == b'I' && plan.ninfo < FDS_MAX {
                        plan.info[plan.ninfo] = n as i32;
                        plan.ninfo += 1;
                    } else if tag == b'J' && plan.njson < FDS_MAX {
                        plan.json[plan.njson] = n as i32;
                        plan.njson += 1;
                    }
                }
                b'W' => say(&[&value[..value.len() - 1]]),
                b'E' | b'O' => {
                    let (code, used) = atoi(value);
                    let msg = &value[used + 1..value.len() - 1];
                    plan.exit = Some((code as i32, msg.as_ptr(), msg.len(), tag == b'O'));
                }
                _ => {}
            }
        }
        if let Some((code, msg, mlen, to_stdout)) = plan.exit {
            say_to(
                if to_stdout { 1 } else { 2 },
                &[core::slice::from_raw_parts(msg, mlen)],
            );
            return code;
        }
        if plan.path.is_null() {
            say(&[b"proot: exec shim: short record\n"]);
            return 126;
        }
        if !plan.complete {
            let mut i = 1usize;
            while i < argc.max(0) as usize && plan.argc < ARGV_MAX {
                out[plan.argc] = *argv.add(i);
                plan.argc += 1;
                i += 1;
            }
        }
        out[plan.argc] = core::ptr::null();
        env_out[plan.envc] = core::ptr::null();
        if plan.die_with_parent {
            libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0);
        }
        if plan.njson > 0 {
            let child = libc::fork();
            if child < 0 {
                say(&[b"proot: exec shim: fork failed\n"]);
                return 126;
            }
            if child > 0 {
                for i in 0..plan.ninfo {
                    write_json(plan.info[i], b"child-pid", child as u64);
                    libc::close(plan.info[i]);
                }
                for i in 0..plan.njson {
                    write_json(plan.json[i], b"child-pid", child as u64);
                }
                let mut status = 0;
                loop {
                    let r = libc::waitpid(child, &mut status, 0);
                    if r == child || (r < 0 && *libc::__errno_location() != libc::EINTR) {
                        break;
                    }
                }
                let code = if libc::WIFEXITED(status) {
                    libc::WEXITSTATUS(status)
                } else if libc::WIFSIGNALED(status) {
                    128 + libc::WTERMSIG(status)
                } else {
                    1
                };
                for i in 0..plan.njson {
                    write_json(plan.json[i], b"exit-code", code as u64);
                    libc::close(plan.json[i]);
                }
                return code;
            }
            if plan.die_with_parent {
                libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0);
            }
            for i in 0..plan.njson {
                libc::close(plan.json[i]);
            }
        } else {
            for i in 0..plan.ninfo {
                write_json(plan.info[i], b"child-pid", pid);
                libc::close(plan.info[i]);
            }
        }
        if !plan.chdir.is_null() && libc::chdir(plan.chdir) < 0 {
            libc::chdir(b"/\0".as_ptr() as *const c_char);
        }
        if plan.new_session {
            libc::setsid();
        }
        for i in 0..plan.nprograms {
            let (ptr, bytes) = plan.programs[i];
            let prog = SockFprog {
                len: (bytes / 8) as u16,
                filter: ptr,
            };
            if libc::syscall(
                libc::SYS_seccomp,
                SECCOMP_SET_MODE_FILTER,
                0,
                &prog as *const SockFprog,
            ) < 0
            {
                say(&[b"proot: exec shim: the caller's seccomp program was refused\n"]);
                return 124;
            }
        }
        let env = if plan.env_given { env_out.as_ptr() } else { envp };
        libc::execve(plan.path, out.as_ptr(), env);
        let e = *libc::__errno_location();
        let mut ebuf = [0u8; 20];
        let edigits = itoa(e as u64, &mut ebuf);
        let plen = libc::strlen(plan.path);
        say(&[
            b"proot: exec shim: cannot execute ",
            core::slice::from_raw_parts(plan.path as *const u8, plen),
            b": errno ",
            edigits,
            b"\n",
        ]);
        if e == libc::ENOENT { 127 } else { 126 }
    }
}
