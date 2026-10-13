//! Reading and writing tracee memory from the supervisor.
//!
//! `process_vm_readv`/`process_vm_writev` are used when the container allows
//! them; otherwise `/proc/<pid>/mem` is opened per access (the descriptor is
//! not cached because it would silently read the old address space after an
//! `execve`).

use crate::sys::{PATH_MAX, Result, errno};
use std::ffi::CString;
use std::sync::atomic::{AtomicU8, Ordering};

const MODE_UNPROBED: u8 = 0;
#[allow(dead_code)]
const MODE_PROCESS_VM: u8 = 1;
const MODE_PROC_MEM: u8 = 2;

/// Tracee memory accessor.  Cheap to copy; the probe result is global.
#[derive(Clone, Copy, Debug, Default)]
pub struct Mem;

static MODE: AtomicU8 = AtomicU8::new(MODE_UNPROBED);

impl Mem {
    /// Reads `buf.len()` bytes at `addr` in `pid`'s address space.
    ///
    /// # Arguments
    /// * `pid` - Tracee thread id.
    /// * `addr` - Virtual address in the tracee.
    /// * `buf` - Destination; a short read returns fewer bytes.
    ///
    /// # Returns
    /// Bytes read.
    ///
    /// # Errors
    /// `EFAULT` for unmapped memory, `ESRCH` when the tracee is gone.
    pub fn read(&self, pid: u32, addr: u64, buf: &mut [u8]) -> Result<usize> {
        match self.mode() {
            MODE_PROC_MEM => {
                let fd = open_mem(pid)?;
                let n = unsafe { libc::pread64(fd, buf.as_mut_ptr() as *mut _, buf.len(), addr as i64) };
                unsafe { libc::close(fd) };
                if n < 0 { Err(errno()) } else { Ok(n as usize) }
            }
            _ => {
                let local = libc::iovec {
                    iov_base: buf.as_mut_ptr() as *mut _,
                    iov_len: buf.len(),
                };
                let remote = libc::iovec {
                    iov_base: addr as *mut _,
                    iov_len: buf.len(),
                };
                let n = unsafe { libc::process_vm_readv(pid as i32, &local, 1, &remote, 1, 0) };
                if n < 0 {
                    let e = errno();
                    if (e == libc::EPERM || e == libc::ENOSYS) && self.demote() {
                        return self.read(pid, addr, buf);
                    }
                    Err(e)
                } else {
                    Ok(n as usize)
                }
            }
        }
    }

    /// Writes `buf` at `addr` in `pid`'s address space.
    ///
    /// # Arguments
    /// * `pid` - Tracee thread id.
    /// * `addr` - Virtual address in the tracee.
    /// * `buf` - Bytes to write; a short write is an error.
    pub fn write(&self, pid: u32, addr: u64, buf: &[u8]) -> Result<()> {
        let n = match self.mode() {
            MODE_PROC_MEM => {
                let fd = open_mem(pid)?;
                let n = unsafe { libc::pwrite64(fd, buf.as_ptr() as *const _, buf.len(), addr as i64) };
                unsafe { libc::close(fd) };
                n
            }
            _ => {
                let local = libc::iovec {
                    iov_base: buf.as_ptr() as *mut _,
                    iov_len: buf.len(),
                };
                let remote = libc::iovec {
                    iov_base: addr as *mut _,
                    iov_len: buf.len(),
                };
                let n = unsafe { libc::process_vm_writev(pid as i32, &local, 1, &remote, 1, 0) };
                if n < 0 {
                    let e = errno();
                    if (e == libc::EPERM || e == libc::ENOSYS) && self.demote() {
                        return self.write(pid, addr, buf);
                    }
                }
                n
            }
        };
        if n < 0 {
            Err(errno())
        } else if n as usize != buf.len() {
            Err(libc::EFAULT)
        } else {
            Ok(())
        }
    }

    /// Writes `buf` at `addr` through `/proc/<pid>/mem`, whatever the page's protection.
    ///
    /// `process_vm_writev` honours the mapping's permissions, so a string in
    /// `.rodata` cannot be changed that way; `/proc/<pid>/mem` writes behave
    /// like a debugger's and copy the page privately.  Used for the in-place
    /// argument rewrites of the no-ptrace mode.
    ///
    /// # Arguments
    /// * `pid` - Tracee thread id.
    /// * `addr` - Virtual address in the tracee.
    /// * `buf` - Bytes to write; a short write is an error.
    pub fn write_force(&self, pid: u32, addr: u64, buf: &[u8]) -> Result<()> {
        let fd = open_mem(pid)?;
        let n = unsafe { libc::pwrite64(fd, buf.as_ptr() as *const _, buf.len(), addr as i64) };
        unsafe { libc::close(fd) };
        if n < 0 {
            Err(errno())
        } else if n as usize != buf.len() {
            Err(libc::EFAULT)
        } else {
            Ok(())
        }
    }

    /// Reads a NUL-terminated string of at most `PATH_MAX - 1` bytes.
    ///
    /// Reads stop at page boundaries so a short string next to an unmapped
    /// page does not fault.
    ///
    /// # Arguments
    /// * `pid` - Tracee thread id.
    /// * `addr` - Address of the first byte.
    ///
    /// # Returns
    /// The bytes before the NUL.
    ///
    /// # Errors
    /// `ENAMETOOLONG` when no NUL is found within `PATH_MAX`, `EFAULT` otherwise.
    pub fn read_cstr(&self, pid: u32, addr: u64) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(256);
        let mut cur = addr;
        let mut chunk = [0u8; 4096];
        while out.len() < PATH_MAX {
            let to_page = (4096 - (cur & 4095) as usize).min(PATH_MAX - out.len());
            let n = self.read(pid, cur, &mut chunk[..to_page])?;
            if n == 0 {
                return Err(libc::EFAULT);
            }
            if let Some(z) = chunk[..n].iter().position(|&b| b == 0) {
                out.extend_from_slice(&chunk[..z]);
                return Ok(out);
            }
            out.extend_from_slice(&chunk[..n]);
            cur += n as u64;
        }
        Err(libc::ENAMETOOLONG)
    }

    /// Reads a NUL-terminated array of 8-byte pointers (argv/envp style).
    #[allow(dead_code)]
    ///
    /// # Arguments
    /// * `pid` - Tracee thread id.
    /// * `addr` - Address of the first pointer.
    /// * `max` - Give up (with `E2BIG`) after this many entries.
    pub fn read_ptr_array(&self, pid: u32, addr: u64, max: usize) -> Result<Vec<u64>> {
        self.read_ptr_array_sized(pid, addr, max, 8)
    }

    /// Reads a NUL-terminated pointer array whose entries are `width` bytes (4 or 8).
    ///
    /// # Arguments
    /// * `pid` - Tracee thread id.
    /// * `addr` - Address of the first pointer.
    /// * `max` - Give up (with `E2BIG`) after this many entries.
    /// * `width` - Pointer size of the tracee's ABI.
    pub fn read_ptr_array_sized(&self, pid: u32, addr: u64, max: usize, width: usize) -> Result<Vec<u64>> {
        let mut out = Vec::new();
        let mut cur = addr;
        let mut buf = [0u8; 8 * 64];
        loop {
            let n = self.read(pid, cur, &mut buf)?;
            if n < width {
                return Err(libc::EFAULT);
            }
            let whole = n - n % width;
            for w in buf[..whole].chunks_exact(width) {
                let p = if width == 8 {
                    u64::from_ne_bytes(w.try_into().unwrap())
                } else {
                    u32::from_ne_bytes(w.try_into().unwrap()) as u64
                };
                if p == 0 {
                    return Ok(out);
                }
                out.push(p);
                if out.len() > max {
                    return Err(libc::E2BIG);
                }
            }
            cur += whole as u64;
        }
    }

    fn mode(&self) -> u8 {
        MODE.load(Ordering::Relaxed)
    }

    /// Switches to `/proc/<pid>/mem` once; returns false if already there.
    fn demote(&self) -> bool {
        MODE.swap(MODE_PROC_MEM, Ordering::Relaxed) != MODE_PROC_MEM
    }
}

fn open_mem(pid: u32) -> Result<i32> {
    let p = CString::new(format!("/proc/{pid}/mem")).unwrap();
    let fd = unsafe { libc::open(p.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
    if fd < 0 { Err(errno()) } else { Ok(fd) }
}
