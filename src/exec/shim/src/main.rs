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
//! In the guest-stub restricted mode (x86_64 and aarch64, with an i386 or
//! 32-bit ARM build as `e32`)
//! the record also carries `m`, the number of the mailbox descriptor the
//! supervisor installed, `x`, the path to report as `AT_EXECFN`, `n`, the
//! process name, `k` when the arguments start with this program's own
//! `argv[0]` rather than after it, and `w` when the program is 32-bit: the
//! 64-bit build then execs `e32` with its own vectors, leaving the record
//! for it.
//! The program is then not exec'd but loaded in place (see `loader`), with
//! the `SIGSYS` handler of `stub` armed first, and the supervisor is told
//! the exec happened before anything is translated in its name.  This
//! program's own syscalls up to that point go through the allow gate, which
//! the filter of that mode lets through; elsewhere the gate is an ordinary
//! syscall.
//!
//! No libc beyond raw syscalls is used so a single static binary serves
//! every guest, whatever its libc.
#![no_std]
#![no_main]

use core::ffi::c_char;

#[cfg(any(
    target_arch = "x86_64",
    target_arch = "x86",
    target_arch = "aarch64",
    target_arch = "arm"
))]
#[allow(dead_code)]
mod layout;
#[cfg(any(
    target_arch = "x86_64",
    target_arch = "x86",
    target_arch = "aarch64",
    target_arch = "arm"
))]
mod loader;
#[cfg(any(
    target_arch = "x86_64",
    target_arch = "x86",
    target_arch = "aarch64",
    target_arch = "arm"
))]
mod stub;

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

/// `seccomp(2)` operation installing a filter.
const SECCOMP_SET_MODE_FILTER: libc::c_long = 1;

/// The record as read, which the plan's pointers point into.
static mut RECORD: [u8; RECORD_MAX] = [0; RECORD_MAX];
/// Whether the gate page is mapped, making [`sc`] go through the allow gate.
#[cfg(any(
    target_arch = "x86_64",
    target_arch = "x86",
    target_arch = "aarch64",
    target_arch = "arm"
))]
static mut GATES: bool = false;
/// Storage for the argument vector handed to `execve`, written through its own address.
static mut ARGV: core::mem::MaybeUninit<[*const c_char; ARGV_MAX + 1]> = core::mem::MaybeUninit::zeroed();
/// Storage for a replacement environment handed to `execve`, written through its own address.
static mut ENVP: core::mem::MaybeUninit<[*const c_char; ENV_MAX + 1]> = core::mem::MaybeUninit::zeroed();

/// `struct sock_fprog` as the kernel reads it.
#[repr(C)]
struct SockFprog {
    /// Number of instructions.
    len: u16,
    /// The instructions.
    filter: *const u8,
}

/// The unwinding personality the ARM EHABI tables of `compiler_builtins`
/// name; never called, since panics abort.
#[cfg(target_arch = "arm")]
#[unsafe(no_mangle)]
pub extern "C" fn rust_eh_personality() {}

/// Exits with 126, the status of a program that could not be run.
///
/// # Arguments
/// * `_` - The panic, unused.
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    unsafe { libc::_exit(126) }
}

/// Makes a syscall through the allow gate when it is mapped, directly otherwise.
///
/// # Arguments
/// * `nr` - Syscall number.
/// * `a` - Its six arguments.
///
/// # Returns
/// The raw result, a negative errno on failure.
fn sc(nr: libc::c_long, a: [usize; 6]) -> isize {
    #[cfg(any(
        target_arch = "x86_64",
        target_arch = "x86",
        target_arch = "aarch64",
        target_arch = "arm"
    ))]
    if unsafe { GATES } {
        return stub::sys(nr as isize, a);
    }
    let r = unsafe { libc::syscall(nr, a[0], a[1], a[2], a[3], a[4], a[5]) };
    if r < 0 {
        -(unsafe { *libc::__errno_location() } as isize)
    } else {
        r as isize
    }
}

/// `open` through [`sc`].
///
/// # Arguments
/// * `path` - The file, NUL-terminated.
/// * `flags` - `O_*` flags.
///
/// # Returns
/// The descriptor, or a negative errno.
fn open(path: *const c_char, flags: i32) -> i32 {
    sc(
        libc::SYS_openat,
        [libc::AT_FDCWD as usize, path as usize, flags as usize, 0, 0, 0],
    ) as i32
}

/// `unlink` through [`sc`].
///
/// # Arguments
/// * `path` - The file, NUL-terminated.
fn unlink(path: *const c_char) {
    sc(
        libc::SYS_unlinkat,
        [libc::AT_FDCWD as usize, path as usize, 0, 0, 0, 0],
    );
}

/// Writes a short diagnostic.
///
/// # Arguments
/// * `fd` - Where to.
/// * `parts` - The pieces, written in order.
fn say_to(fd: i32, parts: &[&[u8]]) {
    for p in parts {
        unsafe { libc::write(fd, p.as_ptr() as *const _, p.len()) };
    }
}

/// Writes a short diagnostic to stderr.
///
/// # Arguments
/// * `parts` - The pieces, written in order.
fn say(parts: &[&[u8]]) {
    say_to(2, parts);
}

/// Formats a non-negative number as decimal.
///
/// # Arguments
/// * `n` - The number.
/// * `buf` - Room for the digits.
///
/// # Returns
/// The used end of `buf`.
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

/// Parses leading decimal digits.
///
/// # Arguments
/// * `bytes` - Text starting with the number.
///
/// # Returns
/// The value and how many bytes it took.
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
    /// `p`: the program to exec.
    path: *const c_char,
    /// Number of arguments from the record.
    argc: usize,
    /// `a` rather than `A`: the record's arguments are the whole vector.
    complete: bool,
    /// Number of environment entries from the record.
    envc: usize,
    /// `e`: the record's environment replaces the inherited one.
    env_given: bool,
    /// `c`: the directory to enter, or null.
    chdir: *const c_char,
    /// `s`: start a new session.
    new_session: bool,
    /// `d`: die with the parent.
    die_with_parent: bool,
    /// `S`: seccomp programs to install, as address and length.
    programs: [(*const u8, usize); PROGRAMS_MAX],
    /// Number of `programs` used.
    nprograms: usize,
    /// `I`: descriptors to receive the child's pid.
    info: [i32; FDS_MAX],
    /// Number of `info` used.
    ninfo: usize,
    /// `J`: descriptors to receive the child's pid and exit code.
    json: [i32; FDS_MAX],
    /// Number of `json` used.
    njson: usize,
    /// `E` or `O`: the exit code, the message's address and length, and
    /// whether it goes to stdout.
    exit: Option<(i32, *const u8, usize, bool)>,
    /// `m`: the mailbox descriptor, or -1 outside the guest-stub mode.
    mailbox: i32,
    /// `x`: the path to report as `AT_EXECFN`, or null.
    execfn: *const c_char,
    /// `n`: the process name, or null.
    comm: *const c_char,
    /// `k`: the arguments start with this program's own `argv[0]`.
    keep_argv0: bool,
    /// `w`: the program is 32-bit.
    narrow: bool,
    /// More arguments or environment entries than fit.
    overflow: bool,
}

/// Which counted list the next `-` fields belong to.
#[derive(Clone, Copy, PartialEq, Eq)]
enum List {
    /// No list is open.
    None,
    /// The arguments of `A` or `a`.
    Argv,
    /// The environment of `e`.
    Env,
}

/// Writes `{"<key>": <n>}\n`.
///
/// # Arguments
/// * `fd` - Where to.
/// * `key` - The key.
/// * `n` - The value.
fn write_json(fd: i32, key: &[u8], n: u64) {
    let mut num = [0u8; 20];
    let digits = itoa(n, &mut num);
    say_to(fd, &[b"{\"", key, b"\": ", digits, b"}\n"]);
}

/// Opens the record for this process: `r<pid>` in the working directory
/// (no ptrace) or next to this program (ptrace).  One found next to this
/// program is unlinked once open.
///
/// # Arguments
/// * `pid` - This process's id.
/// * `name` - Receives the record's file name.
/// * `name_len` - Receives the name's length.
///
/// # Returns
/// The record's descriptor, or -1 when there is none.
fn open_record(pid: u64, name: &mut [u8; 24], name_len: &mut usize) -> i32 {
    let mut num = [0u8; 20];
    let digits = itoa(pid, &mut num);
    name[0] = b'r';
    name[1..1 + digits.len()].copy_from_slice(digits);
    *name_len = 1 + digits.len();
    let fd = open(name.as_ptr() as *const c_char, libc::O_RDONLY | libc::O_CLOEXEC);
    if fd >= 0 {
        return fd;
    }
    let mut exe = [0u8; 4096];
    let n = sc(
        libc::SYS_readlinkat,
        [
            libc::AT_FDCWD as usize,
            c"/proc/self/exe".as_ptr() as usize,
            exe.as_mut_ptr() as usize,
            exe.len() - 32,
            0,
            0,
        ],
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
    let fd = open(exe.as_ptr() as *const c_char, libc::O_RDONLY | libc::O_CLOEXEC);
    if fd >= 0 {
        unlink(exe.as_ptr() as *const c_char);
    }
    fd
}

/// Entry point called by musl's startup code with the exec'd argument vector.
///
/// The program is exec'd, except in the guest-stub restricted mode, where
/// the record names a mailbox: then the stub is armed and the program loaded
/// in place so the stub survives.
///
/// # Arguments
/// * `argc` - Number of entries in `argv`.
/// * `argv` - The caller's original arguments; `argv[0]` is replaced by the record.
/// * `envp` - The caller's environment, passed on unless the record replaces it.
///
/// # Returns
/// An exit status, when the program was not run or for the parent that
/// stays to report the child's exit.
#[unsafe(no_mangle)]
extern "C" fn main(argc: i32, argv: *const *const c_char, envp: *const *const c_char) -> i32 {
    unsafe {
        #[cfg(any(
            target_arch = "x86_64",
            target_arch = "x86",
            target_arch = "aarch64",
            target_arch = "arm"
        ))]
        {
            GATES = stub::map_gates();
        }
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
        if len == 0 || len == RECORD_MAX {
            unlink(name.as_ptr() as *const c_char);
            say(&[b"proot: exec shim: bad record\n"]);
            return 126;
        }
        let out = core::ptr::addr_of_mut!(ARGV).cast::<*const c_char>();
        let env_out = core::ptr::addr_of_mut!(ENVP).cast::<*const c_char>();
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
            mailbox: -1,
            execfn: core::ptr::null(),
            comm: core::ptr::null(),
            keep_argv0: false,
            narrow: false,
            overflow: false,
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
                        out.add(plan.argc).write(text);
                        plan.argc += 1;
                    }
                    List::Env if plan.envc < ENV_MAX => {
                        env_out.add(plan.envc).write(text);
                        plan.envc += 1;
                    }
                    List::Argv | List::Env => plan.overflow = true,
                    List::None => {}
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
                b'm' => plan.mailbox = atoi(value).0 as i32,
                b'x' => plan.execfn = text,
                b'n' => plan.comm = text,
                b'k' => plan.keep_argv0 = true,
                b'w' => plan.narrow = true,
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
        if !(plan.narrow && cfg!(target_pointer_width = "64")) {
            unlink(name.as_ptr() as *const c_char);
        }
        #[cfg(target_pointer_width = "64")]
        if plan.narrow {
            let e = sc(
                libc::SYS_execve,
                [
                    layout::SHIM32_PATH.as_ptr() as usize,
                    argv as usize,
                    envp as usize,
                    0,
                    0,
                    0,
                ],
            );
            unlink(name.as_ptr() as *const c_char);
            return cannot(layout::SHIM32_NAME.as_bytes(), b"execute", -e as i32);
        }
        #[cfg(any(
            target_arch = "x86_64",
            target_arch = "x86",
            target_arch = "aarch64",
            target_arch = "arm"
        ))]
        if plan.mailbox >= 0 {
            if !GATES {
                say(&[b"proot: exec shim: cannot map the syscall gates\n"]);
                return 126;
            }
            if let Err(e) = stub::install(plan.mailbox) {
                let mut ebuf = [0u8; 20];
                say(&[
                    b"proot: exec shim: cannot map the mailbox: errno ",
                    itoa(e as u64, &mut ebuf),
                    b"\n",
                ]);
                return 126;
            }
            stub::hello();
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
            let mut i = if plan.keep_argv0 { 0 } else { 1 };
            while i < argc.max(0) as usize {
                if plan.argc == ARGV_MAX {
                    plan.overflow = true;
                    break;
                }
                out.add(plan.argc).write(*argv.add(i));
                plan.argc += 1;
                i += 1;
            }
        }
        if plan.overflow {
            say(&[b"proot: exec shim: argument list too long\n"]);
            return 126;
        }
        out.add(plan.argc).write(core::ptr::null());
        env_out.add(plan.envc).write(core::ptr::null());
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
            libc::chdir(c"/".as_ptr());
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
        let env = if plan.env_given {
            env_out.cast_const()
        } else {
            envp
        };
        let path = core::slice::from_raw_parts(plan.path.cast::<u8>(), libc::strlen(plan.path));
        #[cfg(any(
            target_arch = "x86_64",
            target_arch = "x86",
            target_arch = "aarch64",
            target_arch = "arm"
        ))]
        if plan.mailbox >= 0 {
            if !plan.comm.is_null() {
                libc::prctl(libc::PR_SET_NAME, plan.comm, 0, 0, 0);
            }
            let fd = open(plan.path, libc::O_RDONLY | libc::O_CLOEXEC);
            if fd < 0 {
                return cannot(path, b"execute", -fd);
            }
            let f = loader::run(fd, plan.argc, out.cast_const(), env, envp, plan.execfn);
            let mut ebuf = [0u8; 20];
            say(&[
                b"proot: exec shim: cannot load ",
                path,
                b": ",
                f.what,
                b" (errno ",
                itoa(f.errno as u64, &mut ebuf),
                b")\n",
            ]);
            return if f.errno == libc::ENOENT { 127 } else { 126 };
        }
        libc::execve(plan.path, out.cast_const(), env);
        cannot(path, b"execute", *libc::__errno_location())
    }
}

/// Reports a program that could not be run.
///
/// # Arguments
/// * `path` - The program.
/// * `what` - The verb that failed.
/// * `e` - The errno.
///
/// # Returns
/// The exit status a shell gives: 127 for a missing program, else 126.
fn cannot(path: &[u8], what: &[u8], e: i32) -> i32 {
    let mut ebuf = [0u8; 20];
    say(&[
        b"proot: exec shim: cannot ",
        what,
        b" ",
        path,
        b": errno ",
        itoa(e as u64, &mut ebuf),
        b"\n",
    ]);
    if e == libc::ENOENT { 127 } else { 126 }
}
