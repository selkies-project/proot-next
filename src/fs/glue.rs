//! Mount points for bindings, created where the guest would list them.
//!
//! A binding answers every lookup of its guest path, but a directory listing
//! comes from the kernel, which only sees what is on disk under the guest
//! path's parent.  A file bound into a directory of the rootfs, such as an
//! NVIDIA vendor file in `/usr/share/glvnd/egl_vendor.d`, is then found by
//! name and missing from the listing that libglvnd, the Vulkan loader and the
//! OpenCL ICD loader take their drivers from.  bubblewrap and the kernel's
//! mounts create the mount point; PRoot creates an empty placeholder and
//! removes it on exit.  This does the same, with PRoot's
//! `PROOT_DONT_POLLUTE_ROOTFS` to opt out.
//!
//! A placeholder is only created through real directories: a symlink along
//! the way stops the walk, so nothing is written outside the directory a
//! component lexically names.  A component under a read-only binding is
//! never created, as bubblewrap cannot create one there either.
//!
//! Each placeholder carries the `user.proot-next.placeholder` extended
//! attribute.  One left behind by a supervisor that was killed is found by
//! it on the next launch and removed with that launch's own, while a file
//! the rootfs shipped is never mistaken for one.  On a filesystem without
//! user attributes an orphan stays until removed by hand, as with PRoot.

use super::binding::{Fs, is_prefix, join_prefix, rest_after};
use crate::config::Binding;
use std::ffi::OsStr;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::DirBuilderExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;

/// Environment variable that turns placeholder creation off, as in PRoot.
pub const DONT_POLLUTE_VAR: &str = "PROOT_DONT_POLLUTE_ROOTFS";

/// Extended attribute marking a placeholder.
const MARK: &std::ffi::CStr = c"user.proot-next.placeholder";

/// One mount point created by [`create`], removed again by [`remove`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Placeholder {
    /// Host path of the created file or directory.
    pub path: PathBuf,
    /// Whether it is a directory rather than an empty regular file.
    pub dir: bool,
}

/// Creates the missing mount points of every binding of a view.
///
/// For each binding whose host side exists, the guest path is walked from
/// `/` through the view without that binding (and without the bindings
/// nested under it), and every missing component is created: directories
/// along the way, then an empty file or a directory for the binding itself,
/// following the type of its host side.
///
/// # Arguments
/// * `fs` - The view whose bindings need mount points.
///
/// # Returns
/// The placeholders created or adopted, in creation order; empty when
/// `PROOT_DONT_POLLUTE_ROOTFS` is set or the view is the identity.
pub fn create(fs: &Fs) -> Vec<Placeholder> {
    if fs.identity || std::env::var_os(DONT_POLLUTE_VAR).is_some() {
        return Vec::new();
    }
    let mut created = Vec::new();
    for binding in &fs.bindings {
        create_for(fs, binding, &mut created);
    }
    created
}

/// Removes placeholders created by [`create`], newest first.
///
/// A file is only removed while it is still empty, and a directory only
/// while it is empty, so anything written there in the meantime is kept.
///
/// # Arguments
/// * `placeholders` - The list [`create`] returned.
pub fn remove(placeholders: &[Placeholder]) {
    for p in placeholders.iter().rev() {
        if p.dir {
            let _ = fs::remove_dir(&p.path);
        } else if fs::symlink_metadata(&p.path).is_ok_and(|m| m.is_file() && m.len() == 0) {
            let _ = fs::remove_file(&p.path);
        }
    }
}

fn create_for(fs: &Fs, binding: &Binding, created: &mut Vec<Placeholder>) {
    if binding.guest == b"/" {
        return;
    }
    let Ok(target) = fs::metadata(OsStr::from_bytes(&binding.host)) else {
        return;
    };
    let mut guest = Vec::with_capacity(binding.guest.len());
    let components: Vec<&[u8]> = binding
        .guest
        .split(|&c| c == b'/')
        .filter(|c| !c.is_empty())
        .collect();
    for (i, component) in components.iter().enumerate() {
        guest.push(b'/');
        guest.extend_from_slice(component);
        let last = i + 1 == components.len();
        let (host, read_only) = underlying(fs, binding, &guest);
        let path = PathBuf::from(OsStr::from_bytes(&host));
        match fs::symlink_metadata(&path) {
            Ok(m) if !m.is_dir() && !m.is_file() => return,
            Ok(m) => {
                if marked(&path) && !created.iter().any(|p: &Placeholder| p.path == path) {
                    created.push(Placeholder {
                        path,
                        dir: m.is_dir(),
                    });
                }
                if m.is_dir() {
                    continue;
                }
                return;
            }
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => return,
            Err(_) => {}
        }
        if read_only {
            return;
        }
        let dir = !last || target.is_dir();
        let made = if dir {
            fs::DirBuilder::new().mode(0o755).create(&path).is_ok()
        } else {
            fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o644)
                .open(&path)
                .is_ok()
        };
        if !made {
            return;
        }
        mark(&path);
        created.push(Placeholder { path, dir });
    }
}

fn mark(path: &std::path::Path) {
    if let Ok(c) = std::ffi::CString::new(path.as_os_str().as_bytes()) {
        unsafe { libc::lsetxattr(c.as_ptr(), MARK.as_ptr(), std::ptr::null(), 0, 0) };
    }
}

fn marked(path: &std::path::Path) -> bool {
    let Ok(c) = std::ffi::CString::new(path.as_os_str().as_bytes()) else {
        return false;
    };
    unsafe { libc::lgetxattr(c.as_ptr(), MARK.as_ptr(), std::ptr::null_mut(), 0) >= 0 }
}

/// The host path `guest` names in the view without `binding` and the
/// bindings under it, and whether that path is under a read-only binding.
fn underlying(fs: &Fs, binding: &Binding, guest: &[u8]) -> (Vec<u8>, bool) {
    match fs
        .bindings
        .iter()
        .find(|b| is_prefix(&b.guest, guest) && !is_prefix(&binding.guest, &b.guest))
    {
        Some(b) => (join_prefix(&b.host, rest_after(&b.guest, guest)), b.read_only),
        None => (join_prefix(&fs.root, rest_after(b"/", guest)), false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    fn scratch(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("proot-glue-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn bytes(p: &std::path::Path) -> Vec<u8> {
        p.as_os_str().as_bytes().to_vec()
    }

    fn view(root: &std::path::Path, bindings: &[(&std::path::Path, &str, bool)]) -> Fs {
        let config = Config {
            root: bytes(root),
            bindings: bindings
                .iter()
                .map(|(host, guest, read_only)| Binding {
                    host: bytes(host),
                    guest: guest.as_bytes().to_vec(),
                    read_only: *read_only,
                })
                .collect(),
            ..Config::default()
        };
        Fs::new(&config)
    }

    #[test]
    fn creates_file_and_directory_mount_points_and_removes_them() {
        let d = scratch("basic");
        let root = d.join("root");
        fs::create_dir_all(root.join("etc/vk")).unwrap();
        fs::write(d.join("icd.json"), b"{}").unwrap();
        fs::create_dir(d.join("srcdir")).unwrap();
        let fs_view = view(
            &root,
            &[
                (&d.join("icd.json"), "/etc/vk/icd.json", true),
                (&d.join("srcdir"), "/opt/a/b", false),
            ],
        );
        let made = create(&fs_view);
        assert!(root.join("etc/vk/icd.json").is_file());
        assert!(root.join("opt/a/b").is_dir());
        assert_eq!(made.len(), 4);
        remove(&made);
        assert!(!root.join("etc/vk/icd.json").exists());
        assert!(!root.join("opt").exists());
        assert!(root.join("etc/vk").is_dir());
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn leaves_existing_paths_symlinks_and_read_only_parents_alone() {
        let d = scratch("guards");
        let root = d.join("root");
        let outside = d.join("outside");
        fs::create_dir_all(root.join("etc")).unwrap();
        fs::create_dir_all(&outside).unwrap();
        fs::write(root.join("etc/hosts"), b"real").unwrap();
        std::os::unix::fs::symlink(&outside, root.join("link")).unwrap();
        fs::write(d.join("f"), b"x").unwrap();
        let ro = d.join("ro");
        fs::create_dir(&ro).unwrap();
        let fs_view = view(
            &root,
            &[
                (&d.join("f"), "/etc/hosts", false),
                (&d.join("f"), "/link/escape", false),
                (&ro, "/ro", true),
                (&d.join("f"), "/ro/inner", false),
                (&d.join("missing"), "/etc/missing", false),
            ],
        );
        let made = create(&fs_view);
        assert_eq!(
            made,
            vec![Placeholder {
                path: root.join("ro"),
                dir: true
            }]
        );
        assert!(!outside.join("escape").exists());
        assert!(!ro.join("inner").exists());
        assert!(!root.join("etc/missing").exists());
        assert_eq!(fs::read(root.join("etc/hosts")).unwrap(), b"real");
        remove(&made);
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn adopts_an_orphan_left_by_a_killed_supervisor() {
        let d = scratch("orphan");
        let root = d.join("root");
        fs::create_dir_all(root.join("etc")).unwrap();
        fs::write(d.join("f"), b"x").unwrap();
        fs::write(root.join("etc/shipped"), b"").unwrap();
        let fs_view = view(
            &root,
            &[
                (&d.join("f"), "/etc/new", false),
                (&d.join("f"), "/etc/shipped", false),
            ],
        );
        let first = create(&fs_view);
        if first.is_empty() || !marked(&root.join("etc/new")) {
            eprintln!("skipping: no user extended attributes on {}", d.display());
            let _ = fs::remove_dir_all(&d);
            return;
        }
        let second = create(&fs_view);
        assert_eq!(second, first);
        remove(&second);
        assert!(!root.join("etc/new").exists());
        assert!(root.join("etc/shipped").exists());
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn keeps_a_placeholder_that_was_written_to() {
        let d = scratch("written");
        let p = d.join("file");
        fs::write(&p, b"data").unwrap();
        remove(&[Placeholder {
            path: p.clone(),
            dir: false,
        }]);
        assert!(p.exists());
        let _ = fs::remove_dir_all(&d);
    }
}
