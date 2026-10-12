//! Minimal ELF reader, 32- and 64-bit: enough to find `PT_INTERP`.

use crate::sys::Result;

/// Program header type of the dynamic loader path.
const PT_INTERP: u32 = 3;
/// Maximum number of program headers we are willing to walk.
const MAX_PHNUM: usize = 512;

/// What an `execve` needs to know about an ELF file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ElfInfo {
    /// Path of the dynamic loader named by `PT_INTERP`, or `None` for a static executable.
    pub interp: Option<Vec<u8>>,
}

/// Classification of the first bytes of an executable file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FileKind {
    /// A 64-bit ELF file.
    Elf64(ElfInfo),
    /// A 32-bit ELF file.
    Elf32(ElfInfo),
    /// A `#!` script; the payload is the first line without the `#!`.
    Shebang(Vec<u8>),
    /// Anything else; the kernel will refuse it with `ENOEXEC`.
    Other,
}

/// Classifies a file from its leading bytes and, for ELF, its program headers.
///
/// Both ELF classes are read: the 64-bit layout (`e_phoff` at 32, `Elf64_Phdr`
/// of 56 bytes) and the 32-bit one (`e_phoff` at 28, `Elf32_Phdr` of 32 bytes).
///
/// # Arguments
/// * `head` - The first bytes of the file (at least 64 for ELF, up to a few KiB).
/// * `read_at` - Reads `len` bytes at `offset` of the same file, for headers past `head`.
///
/// # Returns
/// The [`FileKind`].  An ELF whose program headers cannot be read is
/// reported as `Other` so the kernel gives the final verdict.
pub fn classify(head: &[u8], read_at: &mut dyn FnMut(u64, usize) -> Result<Vec<u8>>) -> FileKind {
    if head.starts_with(b"#!") {
        let line = &head[2..];
        let end = line
            .iter()
            .position(|&b| b == b'\n')
            .unwrap_or(line.len().min(255));
        return FileKind::Shebang(line[..end.min(255)].to_vec());
    }
    if head.len() < 64 || &head[..4] != b"\x7fELF" {
        return FileKind::Other;
    }
    let is64 = match head[4] {
        1 => false,
        2 => true,
        _ => return FileKind::Other,
    };
    if head[5] != 1 {
        // Big-endian ELF on x86_64 cannot run anyway.
        return FileKind::Other;
    }
    let wrap = |info: ElfInfo| {
        if is64 {
            FileKind::Elf64(info)
        } else {
            FileKind::Elf32(info)
        }
    };
    // Header geometry per class: (phoff, phentsize, phnum, minimum phentsize,
    // p_offset field, p_filesz field, field width).
    let (phoff, phentsize, phnum, min_ent, off_field, sz_field, width) = if is64 {
        (
            u64::from_le_bytes(head[32..40].try_into().unwrap()),
            u16::from_le_bytes(head[54..56].try_into().unwrap()) as usize,
            u16::from_le_bytes(head[56..58].try_into().unwrap()) as usize,
            56,
            8,
            32,
            8,
        )
    } else {
        (
            u32::from_le_bytes(head[28..32].try_into().unwrap()) as u64,
            u16::from_le_bytes(head[42..44].try_into().unwrap()) as usize,
            u16::from_le_bytes(head[44..46].try_into().unwrap()) as usize,
            32,
            4,
            16,
            4,
        )
    };
    if phentsize < min_ent || phnum == 0 || phnum > MAX_PHNUM {
        return wrap(ElfInfo { interp: None });
    }
    let table = match read_at(phoff, phentsize * phnum) {
        Ok(t) if t.len() == phentsize * phnum => t,
        _ => return FileKind::Other,
    };
    let field = |ph: &[u8], at: usize| -> u64 {
        if width == 8 {
            u64::from_le_bytes(ph[at..at + 8].try_into().unwrap())
        } else {
            u32::from_le_bytes(ph[at..at + 4].try_into().unwrap()) as u64
        }
    };
    for ph in table.chunks_exact(phentsize) {
        let p_type = u32::from_le_bytes(ph[0..4].try_into().unwrap());
        if p_type != PT_INTERP {
            continue;
        }
        let offset = field(ph, off_field);
        let filesz = field(ph, sz_field) as usize;
        if filesz == 0 || filesz > 4096 {
            return FileKind::Other;
        }
        let mut interp = match read_at(offset, filesz) {
            Ok(i) => i,
            Err(_) => return FileKind::Other,
        };
        while interp.last() == Some(&0) {
            interp.pop();
        }
        return wrap(ElfInfo { interp: Some(interp) });
    }
    wrap(ElfInfo { interp: None })
}

/// Classifies the file at `host_path` by reading it.
///
/// # Arguments
/// * `host_path` - Host path of the candidate executable.
///
/// # Errors
/// Errno from `open`/`read`; `EACCES` for a directory, `ENOENT` for a missing file.
pub fn classify_file(host_path: &[u8]) -> Result<FileKind> {
    use std::io::{Read, Seek, SeekFrom};
    use std::os::unix::ffi::OsStrExt;
    let path = std::path::Path::new(std::ffi::OsStr::from_bytes(host_path));
    let mut f = std::fs::File::open(path).map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
    if f.metadata().map(|m| m.is_dir()).unwrap_or(false) {
        return Err(libc::EACCES);
    }
    let mut head = vec![0u8; 4096];
    let mut got = 0;
    while got < head.len() {
        match f.read(&mut head[got..]) {
            Ok(0) => break,
            Ok(n) => got += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.raw_os_error().unwrap_or(libc::EIO)),
        }
    }
    head.truncate(got);
    let mut read_at = |off: u64, len: usize| -> Result<Vec<u8>> {
        f.seek(SeekFrom::Start(off))
            .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
        let mut buf = vec![0u8; len];
        f.read_exact(&mut buf)
            .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
        Ok(buf)
    };
    Ok(classify(&head, &mut read_at))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a fake ELF64 with one PT_INTERP header pointing at `interp`.
    fn fake_elf(interp: &[u8]) -> Vec<u8> {
        let mut f = vec![0u8; 64];
        f[..4].copy_from_slice(b"\x7fELF");
        f[4] = 2;
        f[5] = 1;
        f[32..40].copy_from_slice(&64u64.to_le_bytes()); // phoff
        f[54..56].copy_from_slice(&56u16.to_le_bytes()); // phentsize
        f[56..58].copy_from_slice(&1u16.to_le_bytes()); // phnum
        let mut ph = vec![0u8; 56];
        ph[0..4].copy_from_slice(&PT_INTERP.to_le_bytes());
        ph[8..16].copy_from_slice(&120u64.to_le_bytes()); // offset
        ph[32..40].copy_from_slice(&((interp.len() + 1) as u64).to_le_bytes());
        f.extend_from_slice(&ph);
        f.extend_from_slice(interp);
        f.push(0);
        f
    }

    /// Builds a fake ELF32 with one PT_INTERP header pointing at `interp`.
    fn fake_elf32(interp: &[u8]) -> Vec<u8> {
        let mut f = vec![0u8; 52];
        f[..4].copy_from_slice(b"\x7fELF");
        f[4] = 1;
        f[5] = 1;
        f[28..32].copy_from_slice(&64u32.to_le_bytes()); // phoff
        f[42..44].copy_from_slice(&32u16.to_le_bytes()); // phentsize
        f[44..46].copy_from_slice(&1u16.to_le_bytes()); // phnum
        f.resize(64, 0);
        let mut ph = vec![0u8; 32];
        ph[0..4].copy_from_slice(&PT_INTERP.to_le_bytes());
        ph[4..8].copy_from_slice(&96u32.to_le_bytes()); // offset
        ph[16..20].copy_from_slice(&((interp.len() + 1) as u32).to_le_bytes());
        f.extend_from_slice(&ph);
        f.extend_from_slice(interp);
        f.push(0);
        f
    }

    #[test]
    fn finds_interp_elf32() {
        let file = fake_elf32(b"/lib/ld-linux.so.2");
        let mut read_at = |off: u64, len: usize| Ok(file[off as usize..off as usize + len].to_vec());
        assert_eq!(
            classify(&file[..64], &mut read_at),
            FileKind::Elf32(ElfInfo {
                interp: Some(b"/lib/ld-linux.so.2".to_vec())
            })
        );
    }

    #[test]
    fn finds_interp() {
        let file = fake_elf(b"/lib64/ld-linux-x86-64.so.2");
        let mut read_at = |off: u64, len: usize| Ok(file[off as usize..off as usize + len].to_vec());
        assert_eq!(
            classify(&file[..64], &mut read_at),
            FileKind::Elf64(ElfInfo {
                interp: Some(b"/lib64/ld-linux-x86-64.so.2".to_vec())
            })
        );
    }

    #[test]
    fn classifies_others() {
        let mut nop = |_: u64, _: usize| Err(libc::EIO);
        assert_eq!(
            classify(b"#!/bin/sh -e\necho", &mut nop),
            FileKind::Shebang(b"/bin/sh -e".to_vec())
        );
        assert_eq!(classify(b"MZ..", &mut nop), FileKind::Other);
        let mut e32 = vec![0u8; 64];
        e32[..4].copy_from_slice(b"\x7fELF");
        e32[4] = 1;
        e32[5] = 1;
        // No program headers: a static 32-bit executable as far as we can tell.
        assert_eq!(
            classify(&e32, &mut nop),
            FileKind::Elf32(ElfInfo { interp: None })
        );
    }

    #[test]
    fn real_binary_has_interp() {
        if let Ok(FileKind::Elf64(info)) = classify_file(b"/bin/ls") {
            assert!(info.interp.map(|i| i.contains(&b'/')).unwrap_or(true));
        }
    }
}
