//! Handlers for syscalls that take a ptrace stop: the path (or socket
//! address) is rewritten in the tracee's memory and the syscall proceeds.

use crate::exec::{self, shim};
use crate::fs::Fs;
use crate::fs::translate::translate_path;
use crate::note;
use crate::state::Ctx;
use crate::sys::Result;
use crate::syscall::nr::*;
use crate::tracee::regs::Regs;

/// Dispatches a seccomp-trace stop to the right handler.
///
/// On error the syscall number is replaced so the kernel returns `ENOSYS`;
/// precise errnos need an exit stop we do not take.  A process running the
/// exec trampoline (a nested launch) has its syscalls passed through, and
/// its exec of the real target completes the pending exec.
///
/// # Arguments
/// * `ctx` - Shared supervisor state.
/// * `regs` - Registers at the stop; edits are committed by the caller.
pub fn handle(ctx: &Ctx, regs: &mut Regs) {
    let pid = regs.pid();
    if let Some(pending) = ctx.procs.shim_pending(ctx.tgid(pid)) {
        let tgid = ctx.tgid(pid);
        if shim::running(pid as u32) {
            let is_exec = matches!(
                regs.abi().to_canonical(regs.sysnum()),
                Some((EXECVE, _)) | Some((EXECVEAT, _))
            );
            if is_exec {
                ctx.procs.shim_leave(tgid);
                exec::finish_pending(ctx, tgid, pending);
            }
            return;
        }
        ctx.procs.shim_leave(tgid);
    }
    let view = ctx.view(pid);
    let fs = &view.fs;
    if regs.abi().socketcall_nr() == Some(regs.sysnum()) {
        if let Err(e) = rewrite_socketcall(ctx, fs, regs) {
            note!(
                ctx,
                1,
                "pid {} socketcall: {}",
                regs.pid(),
                crate::sys::strerror(e)
            );
            regs.fail(e);
        }
        return;
    }
    // Handlers think in x86_64 terms; other ABIs report their own numbers.
    let Some((nr, _)) = regs.abi().to_canonical(regs.sysnum()) else {
        return;
    };
    let r = match nr {
        EXECVE | EXECVEAT => crate::exec::handle_execve(ctx, regs),
        CHDIR | CHROOT => rewrite_path_arg(ctx, fs, regs, 0, true),
        CONNECT | BIND => rewrite_sockaddr(ctx, fs, regs, nr == CONNECT),
        // Only O_PATH opens arrive here (the filter inspects the flags): their
        // descriptors cannot be injected, so the filename is rewritten in place.
        OPEN => {
            let deref = regs.abi().open_flags_to_host(regs.arg(1) as i64) & libc::O_NOFOLLOW as i64 == 0;
            rewrite_path_arg_at(ctx, fs, regs, None, 0, deref)
        }
        OPENAT => {
            let deref = regs.abi().open_flags_to_host(regs.arg(2) as i64) & libc::O_NOFOLLOW as i64 == 0;
            rewrite_path_arg_at(ctx, fs, regs, Some(0), 1, deref)
        }
        INOTIFY_ADD_WATCH => rewrite_path_arg(ctx, fs, regs, 1, true),
        _ => Ok(()),
    };
    if let Err(e) = r {
        note!(
            ctx,
            1,
            "pid {} {}: {}",
            regs.pid(),
            name(nr),
            crate::sys::strerror(e)
        );
        regs.fail(e);
    }
}

/// Writes `bytes` plus a NUL onto the tracee's stack and returns the address.
///
/// # Arguments
/// * `ctx` - Shared supervisor state.
/// * `regs` - Registers to allocate the stack slot from.
/// * `bytes` - String contents, without NUL.
pub fn push_cstr(ctx: &Ctx, regs: &mut Regs, bytes: &[u8]) -> Result<u64> {
    let mut buf = bytes.to_vec();
    buf.push(0);
    let addr = regs.alloc_stack(buf.len() as u64);
    ctx.mem.write(regs.pid() as u32, addr, &buf)?;
    Ok(addr)
}

/// Translates a `dirfd`-relative path argument and points it at the host path.
///
/// After the rewrite the path is absolute, so the `dirfd` argument (if any) is
/// set to `AT_FDCWD`.
///
/// # Arguments
/// * `ctx` - Shared supervisor state.
/// * `fs` - The tracee's filesystem view.
/// * `regs` - Registers at the stop.
/// * `dirfd_index` - Argument index of the directory descriptor, if the syscall has one.
/// * `path_index` - Argument index holding the path pointer.
/// * `deref_final` - Follow a trailing symlink.
pub fn rewrite_path_arg_at(
    ctx: &Ctx,
    fs: &Fs,
    regs: &mut Regs,
    dirfd_index: Option<usize>,
    path_index: usize,
    deref_final: bool,
) -> Result<()> {
    let pid = regs.pid() as u32;
    let dirfd = dirfd_index.map(|i| regs.arg(i) as i32).unwrap_or(libc::AT_FDCWD);
    let path = ctx.mem.read_cstr(pid, regs.arg(path_index))?;
    if path.is_empty() {
        return Ok(()); // AT_EMPTY_PATH: the descriptor itself, nothing to translate
    }
    let host = translate_path(fs, pid, dirfd, &path, deref_final)?;
    if host != path {
        let addr = push_cstr(ctx, regs, &host)?;
        regs.set_arg(path_index, addr);
        if let Some(i) = dirfd_index {
            regs.set_arg(i, libc::AT_FDCWD as u64);
        }
    }
    Ok(())
}

/// Translates the path in argument `index` and points it at the host path.
///
/// # Arguments
/// * `ctx` - Shared supervisor state.
/// * `fs` - The tracee's filesystem view.
/// * `regs` - Registers at the stop.
/// * `index` - Argument index holding the path pointer.
/// * `deref_final` - Follow a trailing symlink.
pub fn rewrite_path_arg(ctx: &Ctx, fs: &Fs, regs: &mut Regs, index: usize, deref_final: bool) -> Result<()> {
    let pid = regs.pid() as u32;
    let path = ctx.mem.read_cstr(pid, regs.arg(index))?;
    let host = translate_path(fs, pid, libc::AT_FDCWD, &path, deref_final)?;
    if host != path {
        let addr = push_cstr(ctx, regs, &host)?;
        regs.set_arg(index, addr);
    }
    Ok(())
}

/// Translates the `sun_path` of an `AF_UNIX` address in `connect`/`bind`.
///
/// Abstract sockets and other families are left alone.  A translated path
/// that does not fit in `sun_path` makes the syscall fail with `ENOSYS`.
///
/// # Arguments
/// * `ctx` - Shared supervisor state.
/// * `fs` - The tracee's filesystem view.
/// * `regs` - Registers at the stop (fd, addr, len).
/// * `deref_final` - Follow a trailing symlink (`connect`), or not (`bind`).
fn rewrite_sockaddr(ctx: &Ctx, fs: &Fs, regs: &mut Regs, deref_final: bool) -> Result<()> {
    if let Some((addr, len)) =
        translate_sockaddr(ctx, fs, regs, regs.arg(1), regs.arg(2) as usize, deref_final)?
    {
        regs.set_arg(1, addr);
        regs.set_arg(2, len);
    }
    Ok(())
}

/// Translates an `AF_UNIX` address in tracee memory, returning a rewritten copy.
///
/// # Arguments
/// * `ctx` - Shared supervisor state.
/// * `fs` - The tracee's filesystem view.
/// * `regs` - Registers at the stop, for scratch space.
/// * `addr` - Address of the `sockaddr` in the tracee.
/// * `len` - Its length.
/// * `deref_final` - Follow a trailing symlink in `sun_path`.
///
/// # Returns
/// `Some((new_addr, new_len))` when the path needed translating, else `None`.
fn translate_sockaddr(
    ctx: &Ctx,
    fs: &Fs,
    regs: &mut Regs,
    addr: u64,
    len: usize,
    deref_final: bool,
) -> Result<Option<(u64, u64)>> {
    let pid = regs.pid() as u32;
    if addr == 0 || len <= 2 || len > 110 {
        return Ok(None);
    }
    let mut sa = vec![0u8; len];
    ctx.mem.read(pid, addr, &mut sa)?;
    if u16::from_ne_bytes([sa[0], sa[1]]) != libc::AF_UNIX as u16 || sa[2] == 0 {
        return Ok(None);
    }
    let end = sa[2..].iter().position(|&b| b == 0).map(|p| p + 2).unwrap_or(len);
    let path = &sa[2..end];
    let host = translate_path(fs, pid, libc::AT_FDCWD, path, deref_final)?;
    if host == path {
        return Ok(None);
    }
    if host.len() >= 108 {
        return Err(libc::ENAMETOOLONG);
    }
    let mut new = vec![0u8; 2 + host.len() + 1];
    new[0..2].copy_from_slice(&(libc::AF_UNIX as u16).to_ne_bytes());
    new[2..2 + host.len()].copy_from_slice(&host);
    let slot = regs.alloc_stack(new.len() as u64);
    ctx.mem.write(pid, slot, &new)?;
    Ok(Some((slot, new.len() as u64)))
}

/// Translates `bind`/`connect` issued through the i386 `socketcall` multiplexer.
///
/// `socketcall(call, args)` takes its arguments as an array of 32-bit words in
/// tracee memory.  The filter only routes calls 2 and 3 here.  A rewritten
/// address gets a fresh argument array in scratch space.
///
/// # Arguments
/// * `ctx` - Shared supervisor state.
/// * `fs` - The tracee's filesystem view.
/// * `regs` - Registers at the stop (call, args pointer).
fn rewrite_socketcall(ctx: &Ctx, fs: &Fs, regs: &mut Regs) -> Result<()> {
    let pid = regs.pid() as u32;
    let call = regs.arg(0);
    let args_ptr = regs.arg(1);
    let mut raw = [0u8; 12];
    ctx.mem.read(pid, args_ptr, &mut raw)?;
    let word = |i: usize| u32::from_ne_bytes(raw[i * 4..i * 4 + 4].try_into().unwrap()) as u64;
    let (fd, addr, len) = (word(0), word(1), word(2) as usize);
    let deref_final = call == 3;
    if let Some((new_addr, new_len)) = translate_sockaddr(ctx, fs, regs, addr, len, deref_final)? {
        let mut new_args = [0u8; 12];
        new_args[0..4].copy_from_slice(&(fd as u32).to_ne_bytes());
        new_args[4..8].copy_from_slice(&(new_addr as u32).to_ne_bytes());
        new_args[8..12].copy_from_slice(&(new_len as u32).to_ne_bytes());
        let slot = regs.alloc_stack(12);
        ctx.mem.write(pid, slot, &new_args)?;
        regs.set_arg(1, slot);
    }
    Ok(())
}
