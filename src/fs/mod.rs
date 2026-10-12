//! Guest filesystem view: the root, the bindings, and path translation.
//!
//! * [`binding`] holds the prefix tables for both directions.
//! * [`canon`] walks a guest path component by component, resolving symlinks
//!   inside the guest namespace (the port of PRoot's `canon.c`).
//! * [`translate`] turns a tracee's `(dirfd, path)` pair into a host path and
//!   back.

pub mod binding;
pub mod canon;
pub mod translate;

pub use binding::Fs;
