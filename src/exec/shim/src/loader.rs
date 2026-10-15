//! The exec shim's ELF loader, used in the guest-stub restricted mode, for
//! the programs of each build's own ABI: ELF64 x86_64 or aarch64, ELF32
//! i386 or ARM.
//!
//! `execve` would reset the stub's `SIGSYS` handler and drop the mailbox, so
//! the shim maps the program into its own process the way the kernel's
//! `binfmt_elf` would and jumps to it.  A position-independent program is
//! placed where `mmap` finds room, a fixed-address one where it asks to be,
//! refusing rather than replacing anything already mapped there (the shim
//! itself is position independent and lies elsewhere).  The program's
//! interpreter is opened through an ordinary, trapped `open`, so the
//! supervisor translates it as it would the kernel's own lookup, and loaded
//! the same way.
//!
//! The new stack is built below the shim's own frames, on the main thread
//! stack: `argc`, the argument and environment pointers, which point at the
//! strings the kernel or the record already hold, and the auxiliary vector,
//! which is the shim's own with the entries that describe the program
//! replaced.  The vDSO, `AT_RANDOM`, the ids and the hardware capabilities
//! therefore stay what the kernel gave.

use crate::stub::{failed, sys};
use core::ffi::c_char;

/// The page size the kernel uses, from the shim's auxiliary vector.
///
/// # Returns
/// `AT_PAGESZ`, at least 4096.
fn page() -> usize {
    (unsafe { libc::getauxval(libc::AT_PAGESZ) } as usize).max(4096)
}
/// Most program headers accepted.
const PHNUM_MAX: usize = 64;
/// Longest interpreter path, terminating NUL included.
const INTERP_MAX: usize = 4096;
/// Most auxiliary vector entries carried over.
const AUXV_MAX: usize = 64;
/// Distance kept between the shim's frames and the program's stack.
const STACK_GAP: usize = 16 * 1024;

/// Program header type of a loadable segment.
const PT_LOAD: u32 = 1;
/// Program header type naming the interpreter.
const PT_INTERP: u32 = 3;
/// Program header type locating the program headers themselves.
const PT_PHDR: u32 = 6;
/// Segment flag: executable.
const PF_X: u32 = 1;
/// Segment flag: writable.
const PF_W: u32 = 2;
/// Segment flag: readable.
const PF_R: u32 = 4;
/// ELF type of a fixed-address executable.
const ET_EXEC: u16 = 2;
/// ELF type of a position-independent executable or shared object.
const ET_DYN: u16 = 3;

/// Auxiliary vector terminator.
const AT_NULL: usize = 0;
/// Auxiliary vector: the program headers in memory.
const AT_PHDR: usize = 3;
/// Auxiliary vector: size of one program header.
const AT_PHENT: usize = 4;
/// Auxiliary vector: number of program headers.
const AT_PHNUM: usize = 5;
/// Auxiliary vector: the interpreter's load bias.
const AT_BASE: usize = 7;
/// Auxiliary vector: the program's entry point.
const AT_ENTRY: usize = 9;
/// Auxiliary vector: the path the exec named.
const AT_EXECFN: usize = 31;

/// The ELF class this build loads.
#[cfg(target_pointer_width = "64")]
mod class {
    /// `EI_CLASS` of the files this build loads.
    pub const ELFCLASS: u8 = 2;
    /// `e_machine` of the files this build loads: `EM_X86_64` or `EM_AARCH64`.
    pub const MACHINE: u16 = if cfg!(target_arch = "aarch64") { 183 } else { 62 };
    /// Size of the ELF header.
    pub const EHDR_SIZE: usize = 64;
    /// Size of a program header.
    pub const PHDR_SIZE: usize = 56;
    /// Offset of `e_entry`.
    pub const E_ENTRY: usize = 24;
    /// Offset of `e_phoff`.
    pub const E_PHOFF: usize = 32;
    /// Offset of `e_phentsize`.
    pub const E_PHENTSIZE: usize = 54;
    /// Offset of `e_phnum`.
    pub const E_PHNUM: usize = 56;
    /// Offset of `p_type`.
    pub const P_TYPE: usize = 0;
    /// Offset of `p_flags`.
    pub const P_FLAGS: usize = 4;
    /// Offset of `p_offset`.
    pub const P_OFFSET: usize = 8;
    /// Offset of `p_vaddr`.
    pub const P_VADDR: usize = 16;
    /// Offset of `p_filesz`.
    pub const P_FILESZ: usize = 32;
    /// Offset of `p_memsz`.
    pub const P_MEMSZ: usize = 40;
    /// Offset of `p_align`.
    pub const P_ALIGN: usize = 48;
    /// What the loader says of a file of the other class.
    pub const OTHER_CLASS: &[u8] = b"not a 64-bit program";
}

/// The ELF class this build loads.
#[cfg(target_pointer_width = "32")]
mod class {
    /// `EI_CLASS` of the files this build loads.
    pub const ELFCLASS: u8 = 1;
    /// `e_machine` of the files this build loads: `EM_386` or `EM_ARM`.
    pub const MACHINE: u16 = if cfg!(target_arch = "arm") { 40 } else { 3 };
    /// Size of the ELF header.
    pub const EHDR_SIZE: usize = 52;
    /// Size of a program header.
    pub const PHDR_SIZE: usize = 32;
    /// Offset of `e_entry`.
    pub const E_ENTRY: usize = 24;
    /// Offset of `e_phoff`.
    pub const E_PHOFF: usize = 28;
    /// Offset of `e_phentsize`.
    pub const E_PHENTSIZE: usize = 42;
    /// Offset of `e_phnum`.
    pub const E_PHNUM: usize = 44;
    /// Offset of `p_type`.
    pub const P_TYPE: usize = 0;
    /// Offset of `p_flags`.
    pub const P_FLAGS: usize = 24;
    /// Offset of `p_offset`.
    pub const P_OFFSET: usize = 4;
    /// Offset of `p_vaddr`.
    pub const P_VADDR: usize = 8;
    /// Offset of `p_filesz`.
    pub const P_FILESZ: usize = 16;
    /// Offset of `p_memsz`.
    pub const P_MEMSZ: usize = 20;
    /// Offset of `p_align`.
    pub const P_ALIGN: usize = 28;
    /// What the loader says of a file of the other class.
    pub const OTHER_CLASS: &[u8] = b"not a 32-bit program";
}

use class::*;

/// Why a program could not be loaded: an errno and what was being done.
pub struct Failure {
    /// The errno to report.
    pub errno: i32,
    /// The step that failed.
    pub what: &'static [u8],
}

/// Builds a [`Failure`].
///
/// # Arguments
/// * `errno` - The errno to report.
/// * `what` - The message naming the reason.
///
/// # Returns
/// The failure.
fn fail(errno: i32, what: &'static [u8]) -> Failure {
    Failure { errno, what }
}

/// The fields of one program header the loader uses.
#[derive(Clone, Copy, Default)]
struct Phdr {
    /// `p_type`.
    kind: u32,
    /// `p_flags`.
    flags: u32,
    /// `p_offset`: where the segment starts in the file.
    offset: usize,
    /// `p_vaddr`: where it starts in memory, before the load bias.
    vaddr: usize,
    /// `p_filesz`: bytes from the file.
    filesz: usize,
    /// `p_memsz`: bytes in memory, the rest zero.
    memsz: usize,
    /// `p_align`.
    align: usize,
}

/// An ELF file's headers.
struct Headers {
    /// `e_type`: [`ET_EXEC`] or [`ET_DYN`].
    kind: u16,
    /// `e_entry`, before the load bias.
    entry: usize,
    /// `e_phoff`: where the program headers start in the file.
    phoff: usize,
    /// The program headers, the first `phnum` of them used.
    ph: [Phdr; PHNUM_MAX],
    /// Number of program headers.
    phnum: usize,
}

/// A mapped ELF image.
struct Image {
    /// Load bias: what was added to every virtual address.
    base: usize,
    /// Entry point in memory.
    entry: usize,
    /// Program headers in memory, 0 when the file maps none.
    phdr: usize,
    /// Number of program headers.
    phnum: usize,
}

/// Reads exactly `buf.len()` bytes at `off`.  The offset fits a word on
/// every ABI; on i386 the next argument is its high half, zero, and ARM
/// EABI passes it in an even register pair after a padding argument.
///
/// # Arguments
/// * `fd` - The file.
/// * `buf` - Where to read to; its length is how much.
/// * `off` - Offset in the file.
///
/// # Errors
/// The errno of a failed read; `ENOEXEC` for a short one.
fn pread(fd: i32, buf: &mut [u8], off: usize) -> Result<(), i32> {
    let (fd, at, len) = (fd as usize, buf.as_mut_ptr() as usize, buf.len());
    let args = if cfg!(target_arch = "arm") {
        [fd, at, len, 0, off, 0]
    } else {
        [fd, at, len, off, 0, 0]
    };
    let n = sys(libc::SYS_pread64 as isize, args);
    if n < 0 {
        Err(-n as i32)
    } else if n as usize != buf.len() {
        Err(libc::ENOEXEC)
    } else {
        Ok(())
    }
}

/// A little-endian `u16` of a header buffer.
///
/// # Arguments
/// * `b` - The buffer.
/// * `at` - Offset of the field.
///
/// # Returns
/// The field's value.
fn u16_at(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}

/// A little-endian `u32` of a header buffer.
///
/// # Arguments
/// * `b` - The buffer.
/// * `at` - Offset of the field.
///
/// # Returns
/// The field's value.
fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

/// A little-endian word of this build's class from a header buffer.
///
/// # Arguments
/// * `b` - The buffer.
/// * `at` - Offset of the field.
///
/// # Returns
/// The field's value.
fn word_at(b: &[u8], at: usize) -> usize {
    const W: usize = core::mem::size_of::<usize>();
    let mut v = [0u8; W];
    v.copy_from_slice(&b[at..at + W]);
    usize::from_le_bytes(v)
}

/// Reads and checks the ELF and program headers of a file.
///
/// # Arguments
/// * `fd` - The file.
///
/// # Returns
/// Its headers.
///
/// # Errors
/// `ENOEXEC` for anything but a little-endian ELF executable or shared
/// object of this build's class and machine, with a message naming the
/// reason.
fn headers(fd: i32) -> Result<Headers, Failure> {
    let mut e = [0u8; EHDR_SIZE];
    pread(fd, &mut e, 0).map_err(|n| fail(n, b"cannot read the ELF header"))?;
    if e[..4] != *b"\x7fELF" {
        return Err(fail(libc::ENOEXEC, b"not an ELF file"));
    }
    if e[4] != ELFCLASS {
        return Err(fail(libc::ENOEXEC, OTHER_CLASS));
    }
    if e[5] != 1 || u16_at(&e, 18) != MACHINE {
        return Err(fail(libc::ENOEXEC, b"not a program for this machine"));
    }
    let kind = u16_at(&e, 16);
    if kind != ET_EXEC && kind != ET_DYN {
        return Err(fail(libc::ENOEXEC, b"not an executable"));
    }
    let phoff = word_at(&e, E_PHOFF);
    let phentsize = u16_at(&e, E_PHENTSIZE) as usize;
    let phnum = u16_at(&e, E_PHNUM) as usize;
    if phentsize != PHDR_SIZE || phnum == 0 || phnum > PHNUM_MAX {
        return Err(fail(libc::ENOEXEC, b"unsupported program headers"));
    }
    let mut raw = [0u8; PHDR_SIZE * PHNUM_MAX];
    pread(fd, &mut raw[..phnum * PHDR_SIZE], phoff)
        .map_err(|n| fail(n, b"cannot read the program headers"))?;
    let mut ph = [Phdr::default(); PHNUM_MAX];
    for (i, p) in ph.iter_mut().enumerate().take(phnum) {
        let b = &raw[i * PHDR_SIZE..(i + 1) * PHDR_SIZE];
        *p = Phdr {
            kind: u32_at(b, P_TYPE),
            flags: u32_at(b, P_FLAGS),
            offset: word_at(b, P_OFFSET),
            vaddr: word_at(b, P_VADDR),
            filesz: word_at(b, P_FILESZ),
            memsz: word_at(b, P_MEMSZ),
            align: word_at(b, P_ALIGN),
        };
    }
    Ok(Headers {
        kind,
        entry: word_at(&e, E_ENTRY),
        phoff,
        ph,
        phnum,
    })
}

/// Rounds down to a page.
///
/// # Arguments
/// * `v` - An address or length.
///
/// # Returns
/// `v` rounded down to a page boundary.
fn page_down(v: usize) -> usize {
    v & !(page() - 1)
}

/// Rounds up to a page.
///
/// # Arguments
/// * `v` - An address or length.
///
/// # Returns
/// `v` rounded up to a page boundary.
fn page_up(v: usize) -> usize {
    (v + page() - 1) & !(page() - 1)
}

/// `mmap` through the allow gate, with a page-aligned byte offset.
///
/// # Arguments
/// * `addr` - Address hint, or the fixed address.
/// * `len` - Length in bytes.
/// * `prot` - `PROT_*` flags.
/// * `flags` - `MAP_*` flags.
/// * `fd` - The file, or -1.
/// * `off` - Offset in the file, page-aligned.
///
/// # Returns
/// The mapping's address.
///
/// # Errors
/// The errno the kernel returned.
fn mmap(addr: usize, len: usize, prot: i32, flags: i32, fd: i32, off: usize) -> Result<usize, i32> {
    #[cfg(target_pointer_width = "64")]
    let (nr, off) = (libc::SYS_mmap as isize, off);
    #[cfg(target_pointer_width = "32")]
    let (nr, off) = (libc::SYS_mmap2 as isize, off / 4096);
    let r = sys(nr, [addr, len, prot as usize, flags as usize, fd as usize, off]);
    if failed(r) { Err(-r as i32) } else { Ok(r as usize) }
}

/// `munmap` through the allow gate.
///
/// # Arguments
/// * `addr` - Start of the range.
/// * `len` - Length in bytes.
fn munmap(addr: usize, len: usize) {
    sys(libc::SYS_munmap as isize, [addr, len, 0, 0, 0, 0]);
}

/// `close` through the allow gate.
///
/// # Arguments
/// * `fd` - The descriptor.
fn close(fd: i32) {
    sys(libc::SYS_close as isize, [fd as usize, 0, 0, 0, 0, 0]);
}

/// Maps every `PT_LOAD` segment of a file.
///
/// The whole span is reserved first, so segments keep their distances and
/// nothing else lands between them; the reservation of a position-independent
/// file is aligned to its largest segment alignment, as the kernel does.  A
/// segment with a bss has the rest of its last file page zeroed, to the end
/// of the page and not only of the segment, as the kernel does too: glibc's
/// dynamic loader allocates its first objects from that tail and takes them
/// to be zero.
///
/// # Arguments
/// * `fd` - The file.
/// * `h` - Its headers.
///
/// # Returns
/// Where the image landed.
///
/// # Errors
/// The errno of a mapping that failed; `EEXIST` when a fixed-address program
/// collides with something already mapped.
fn map(fd: i32, h: &Headers) -> Result<Image, Failure> {
    let loads = || {
        h.ph[..h.phnum]
            .iter()
            .filter(|p| p.kind == PT_LOAD && p.memsz > 0)
    };
    let lo = loads().map(|p| page_down(p.vaddr)).min();
    let hi = loads().map(|p| page_up(p.vaddr + p.memsz)).max();
    let (Some(lo), Some(hi)) = (lo, hi) else {
        return Err(fail(libc::ENOEXEC, b"no loadable segment"));
    };
    let span = hi - lo;
    let anon = libc::MAP_PRIVATE | libc::MAP_ANONYMOUS;
    let base = if h.kind == ET_DYN {
        let align = loads()
            .map(|p| p.align)
            .filter(|a| a.is_power_of_two())
            .max()
            .unwrap_or(page())
            .max(page());
        let slack = align - page();
        let at = mmap(
            0,
            span + slack,
            libc::PROT_NONE,
            anon | libc::MAP_NORESERVE,
            -1,
            0,
        )
        .map_err(|e| fail(e, b"cannot reserve address space"))?;
        let start = (at + align - 1) & !(align - 1);
        if start > at {
            munmap(at, start - at);
        }
        if at + span + slack > start + span {
            munmap(start + span, at + span + slack - start - span);
        }
        start - lo
    } else {
        let at = mmap(
            lo,
            span,
            libc::PROT_NONE,
            anon | libc::MAP_NORESERVE | libc::MAP_FIXED_NOREPLACE,
            -1,
            0,
        )
        .map_err(|e| fail(e, b"its fixed addresses are already in use"))?;
        if at != lo {
            munmap(at, span);
            return Err(fail(libc::EEXIST, b"its fixed addresses are already in use"));
        }
        0
    };
    for p in loads() {
        let prot = (if p.flags & PF_R != 0 { libc::PROT_READ } else { 0 })
            | (if p.flags & PF_W != 0 { libc::PROT_WRITE } else { 0 })
            | (if p.flags & PF_X != 0 { libc::PROT_EXEC } else { 0 });
        let start = base + p.vaddr;
        let page = page_down(start);
        let file_end = start + p.filesz;
        let mem_end = start + p.memsz;
        let partial = p.memsz > p.filesz && p.filesz > 0 && file_end != page_up(file_end);
        if p.filesz > 0 {
            mmap(
                page,
                page_up(file_end) - page,
                prot | if partial { libc::PROT_WRITE } else { 0 },
                libc::MAP_PRIVATE | libc::MAP_FIXED,
                fd,
                p.offset - (start - page),
            )
            .map_err(|e| fail(e, b"cannot map a segment"))?;
        }
        if partial {
            for a in file_end..page_up(file_end) {
                unsafe { (a as *mut u8).write_volatile(0) };
            }
            if prot & libc::PROT_WRITE == 0 {
                sys(
                    libc::SYS_mprotect as isize,
                    [page, page_up(file_end) - page, prot as usize, 0, 0, 0],
                );
            }
        }
        let anon_start = if p.filesz > 0 { page_up(file_end) } else { page };
        let anon_end = page_up(mem_end);
        if anon_end > anon_start {
            mmap(
                anon_start,
                anon_end - anon_start,
                prot,
                anon | libc::MAP_FIXED,
                -1,
                0,
            )
            .map_err(|e| fail(e, b"cannot map the bss"))?;
        }
    }
    let ph = &h.ph[..h.phnum];
    let phdr = match ph.iter().find(|p| p.kind == PT_PHDR) {
        Some(p) => base + p.vaddr,
        None => ph
            .iter()
            .find(|p| p.kind == PT_LOAD && p.offset <= h.phoff && h.phoff < p.offset + p.filesz)
            .map(|p| base + p.vaddr + (h.phoff - p.offset))
            .unwrap_or(0),
    };
    Ok(Image {
        base,
        entry: base + h.entry,
        phdr,
        phnum: h.phnum,
    })
}

/// Loads the program open on `fd` and its interpreter, then starts it.
///
/// # Arguments
/// * `fd` - The program, opened by the caller; closed here.
/// * `argc` - Number of arguments.
/// * `argv` - The argument vector, `argc` pointers then NULL.
/// * `envp` - The environment, NULL-terminated.
/// * `kernel_envp` - The environment the kernel gave the shim, after which
///   its auxiliary vector lies.
/// * `execfn` - The path to report as `AT_EXECFN`, or NULL to keep the shim's.
///
/// # Returns
/// Only on failure, with the reason.
pub fn run(
    fd: i32,
    argc: usize,
    argv: *const *const c_char,
    envp: *const *const c_char,
    kernel_envp: *const *const c_char,
    execfn: *const c_char,
) -> Failure {
    let prog = match headers(fd).and_then(|h| map(fd, &h).map(|img| (img, h))) {
        Ok(v) => v,
        Err(f) => {
            close(fd);
            return f;
        }
    };
    let (img, h) = prog;
    let mut interp = [0u8; INTERP_MAX];
    let interp_hdr = h.ph[..h.phnum].iter().find(|p| p.kind == PT_INTERP).copied();
    if let Some(p) = interp_hdr {
        let n = p.filesz;
        if n == 0 || n > INTERP_MAX || pread(fd, &mut interp[..n], p.offset).is_err() || interp[n - 1] != 0 {
            close(fd);
            return fail(libc::ENOEXEC, b"bad interpreter path");
        }
    }
    close(fd);
    let (start, base) = if interp_hdr.is_some() {
        let ifd = unsafe { libc::open(interp.as_ptr() as *const c_char, libc::O_RDONLY | libc::O_CLOEXEC) };
        if ifd < 0 {
            return fail(
                unsafe { *libc::__errno_location() },
                b"cannot open its interpreter",
            );
        }
        let loaded = headers(ifd).and_then(|ih| map(ifd, &ih));
        close(ifd);
        match loaded {
            Ok(i) => (i.entry, i.base),
            Err(f) => return f,
        }
    } else {
        (img.entry, 0)
    };
    let mut aux = [(0usize, 0usize); AUXV_MAX];
    let mut naux = 0;
    unsafe {
        let mut p = kernel_envp;
        while !(*p).is_null() {
            p = p.add(1);
        }
        let mut a = p.add(1) as *const usize;
        while *a != AT_NULL && naux < AUXV_MAX - 6 {
            let (k, v) = (*a, *a.add(1));
            let replaced = matches!(k, AT_PHDR | AT_PHENT | AT_PHNUM | AT_BASE | AT_ENTRY)
                || (k == AT_EXECFN && !execfn.is_null());
            if !replaced {
                aux[naux] = (k, v);
                naux += 1;
            }
            a = a.add(2);
        }
    }
    for entry in [
        (AT_PHDR, img.phdr),
        (AT_PHENT, PHDR_SIZE),
        (AT_PHNUM, img.phnum),
        (AT_BASE, base),
        (AT_ENTRY, img.entry),
    ] {
        aux[naux] = entry;
        naux += 1;
    }
    if !execfn.is_null() {
        aux[naux] = (AT_EXECFN, execfn as usize);
        naux += 1;
    }
    unsafe { enter(start, argc, argv, envp, &aux[..naux]) }
}

/// Builds the initial stack and jumps to `entry`.
///
/// # Arguments
/// * `entry` - Where to start: the interpreter's entry, or the program's.
/// * `argc` - Number of arguments.
/// * `argv` - The argument pointers.
/// * `envp` - The environment pointers, NULL-terminated.
/// * `aux` - The auxiliary vector, without its terminator.
///
/// # Safety
/// Everything the pointers name must stay mapped; nothing of the shim's
/// stack below the current frame survives.
unsafe fn enter(
    entry: usize,
    argc: usize,
    argv: *const *const c_char,
    envp: *const *const c_char,
    aux: &[(usize, usize)],
) -> ! {
    let mut envc = 0;
    while !unsafe { *envp.add(envc) }.is_null() {
        envc += 1;
    }
    let words = 1 + argc + 1 + envc + 1 + 2 * (aux.len() + 1);
    let sp = stack_pointer();
    let top = (sp - STACK_GAP - words * core::mem::size_of::<usize>()) & !15;
    let w = top as *mut usize;
    let mut i = 0;
    unsafe {
        w.add(i).write(argc);
        i += 1;
        for k in 0..argc {
            w.add(i).write(*argv.add(k) as usize);
            i += 1;
        }
        w.add(i).write(0);
        i += 1;
        for k in 0..envc {
            w.add(i).write(*envp.add(k) as usize);
            i += 1;
        }
        w.add(i).write(0);
        i += 1;
        for &(k, v) in aux {
            w.add(i).write(k);
            w.add(i + 1).write(v);
            i += 2;
        }
        w.add(i).write(AT_NULL);
        w.add(i + 1).write(0);
        jump(top, entry)
    }
}

/// The current stack pointer.
///
/// # Returns
/// The caller's stack pointer.
#[inline(always)]
fn stack_pointer() -> usize {
    let sp: usize;
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::asm!("mov {}, rsp", out(reg) sp, options(nomem, nostack))
    };
    #[cfg(target_arch = "x86")]
    unsafe {
        core::arch::asm!("mov {}, esp", out(reg) sp, options(nomem, nostack))
    };
    #[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
    unsafe {
        core::arch::asm!("mov {}, sp", out(reg) sp, options(nomem, nostack))
    };
    sp
}

/// Switches to the stack at `top` and jumps to `entry` with the registers
/// the ELF entry convention wants: the frame pointer, the link register on
/// ARM, and the termination function to register (`rdx`, `edx`, `x0`,
/// `r0`) zero.  On 32-bit ARM `bx` enters a Thumb entry point in Thumb.
///
/// # Arguments
/// * `top` - The initial stack, `argc` first.
/// * `entry` - Where to start.
///
/// # Safety
/// `top` must hold a complete initial stack.
#[inline(always)]
unsafe fn jump(top: usize, entry: usize) -> ! {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::asm!(
            "mov rsp, rsi",
            "xor ebp, ebp",
            "xor edx, edx",
            "jmp rdi",
            in("rsi") top,
            in("rdi") entry,
            options(noreturn),
        )
    }
    #[cfg(target_arch = "x86")]
    unsafe {
        core::arch::asm!(
            "mov esp, ecx",
            "xor ebp, ebp",
            "xor edx, edx",
            "jmp eax",
            in("ecx") top,
            in("eax") entry,
            options(noreturn),
        )
    }
    #[cfg(target_arch = "aarch64")]
    unsafe {
        core::arch::asm!(
            "mov sp, x9",
            "mov x29, xzr",
            "mov x30, xzr",
            "mov x0, xzr",
            "br x10",
            in("x9") top,
            in("x10") entry,
            options(noreturn),
        )
    }
    #[cfg(target_arch = "arm")]
    unsafe {
        core::arch::asm!(
            "mov sp, r1",
            "mov r0, #0",
            "mov lr, #0",
            "bx r2",
            in("r1") top,
            in("r2") entry,
            options(noreturn),
        )
    }
}
