//! Seccomp: the BPF filter the tracee installs, and the listener pool that
//! answers user notifications.

pub mod filter;
pub mod notify;
