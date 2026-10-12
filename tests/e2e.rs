//! End-to-end tests: the built `proot` binary driving real programs.
//!
//! Every case here is a failure that was first seen in a real application
//! (Brave, Steam's webhelper, Half-Life, libudev) and then reduced.  They
//! need ptrace and seccomp user notification on the running kernel, which
//! CI's Linux runners provide.  Cases that need a rootfs read
//! `PROOT_TEST_ROOTFS`; cases that need a 32-bit probe read
//! `tests/probes/bin/`; both skip with a message when absent.

use std::io::Write;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

fn proot() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_proot"))
}

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Runs `proot` with `args`, returning its output; panics on a spawn failure.
fn run(args: &[&str]) -> Output {
    Command::new(proot())
        .args(args)
        .stdin(Stdio::null())
        .output()
        .expect("spawn proot")
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).trim().to_string()
}

fn tmpdir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("proot-e2e-{}-{}", name, std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn probe(name: &str) -> Option<PathBuf> {
    let p = repo().join("tests/probes/bin").join(name);
    if p.exists() {
        Some(p)
    } else {
        eprintln!("skipping: {} not built (tests/probes/build.sh)", p.display());
        None
    }
}

fn rootfs() -> Option<PathBuf> {
    match std::env::var_os("PROOT_TEST_ROOTFS") {
        Some(p) => Some(PathBuf::from(p)),
        None => {
            eprintln!("skipping: PROOT_TEST_ROOTFS not set");
            None
        }
    }
}

#[test]
fn smoke_script_passes() {
    let script = repo().join("scripts/smoke.sh");
    let mut cmd = Command::new(&script);
    cmd.arg(proot());
    if let Some(r) = std::env::var_os("PROOT_TEST_ROOTFS") {
        cmd.arg(r);
    }
    let o = cmd.output().expect("run smoke.sh");
    assert!(
        o.status.success(),
        "smoke.sh failed:\n{}",
        String::from_utf8_lossy(&o.stdout)
    );
}

#[test]
fn tracer_is_hidden_from_proc_status() {
    let o = run(&["-r", "/", "/bin/sh", "-c", "grep TracerPid /proc/self/status"]);
    assert_eq!(stdout(&o), "TracerPid:\t0");
}

#[test]
fn proc_fd_links_reopen_the_object() {
    // Chromium makes read-only shared memory handles by re-opening /proc/self/fd/N on a memfd.
    let script = "import os, fcntl\n\
                  fd = os.memfd_create('t'); os.write(fd, b'hi')\n\
                  ro = os.open(f'/proc/self/fd/{fd}', os.O_RDONLY)\n\
                  print(fcntl.fcntl(ro, fcntl.F_GETFL) & os.O_ACCMODE, os.pread(ro, 2, 0).decode())";
    // A binding makes translation non-identity, which is where the walk used to go wrong.
    let o = run(&["-r", "/", "-b", "/tmp:/pn-x", "python3", "-c", script]);
    assert_eq!(stdout(&o), "0 hi", "{}", String::from_utf8_lossy(&o.stderr));
}

#[test]
fn process_substitution_through_dev_fd() {
    let o = run(&["-r", "/", "/bin/bash", "-c", "cat <(echo via-dev-fd)"]);
    assert_eq!(stdout(&o), "via-dev-fd");
}

#[test]
fn opath_opens_resolve_inside_the_guest() {
    // libudev opens directories with O_PATH; such descriptors cannot be injected and go via ptrace.
    let script = "import os\n\
                  fd = os.open('/', os.O_PATH | os.O_DIRECTORY)\n\
                  print(os.readlink(f'/proc/self/fd/{fd}'))";
    let o = run(&["-r", "/", "-b", "/tmp:/pn-x", "python3", "-c", script]);
    assert_eq!(stdout(&o), "/", "{}", String::from_utf8_lossy(&o.stderr));
}

#[test]
fn unix_connect_is_translated_through_a_binding() {
    let d = tmpdir("sock");
    let sock = d.join("sock");
    let listener = UnixListener::bind(&sock).unwrap();
    let server = std::thread::spawn(move || {
        let (mut c, _) = listener.accept().unwrap();
        c.write_all(b"hello").unwrap();
    });
    let script = "import socket\n\
                  s = socket.socket(socket.AF_UNIX); s.connect('/pn-sock/sock'); print(s.recv(16).decode())";
    let o = run(&[
        "-r",
        "/",
        "-b",
        &format!("{}:/pn-sock", d.display()),
        "python3",
        "-c",
        script,
    ]);
    assert_eq!(stdout(&o), "hello", "{}", String::from_utf8_lossy(&o.stderr));
    server.join().unwrap();
}

#[test]
#[cfg(target_arch = "x86_64")]
fn i386_socketcall_connect_is_translated() {
    let Some(client) = probe("socketcall32") else {
        return;
    };
    let d = tmpdir("sc32");
    let sock = d.join("sock");
    let listener = UnixListener::bind(&sock).unwrap();
    let server = std::thread::spawn(move || {
        let (mut c, _) = listener.accept().unwrap();
        c.write_all(b"hello-from-host").unwrap();
    });
    let o = run(&[
        "-r",
        "/",
        "-b",
        &format!("{}:/pn-sock", d.display()),
        client.to_str().unwrap(),
        "/pn-sock/sock",
    ]);
    assert!(
        stdout(&o).contains("ok, server said \"hello-from-host\""),
        "{}",
        stdout(&o)
    );
    server.join().unwrap();
}

#[test]
#[cfg(target_arch = "aarch64")]
fn arm32_probe_runs() {
    let Some(p) = probe("armtest") else { return };
    // A kernel or CPU without AArch32 support cannot run the probe at all; that is not our bug.
    if Command::new(&p)
        .arg("/etc/hostname")
        .output()
        .map(|o| !o.status.success())
        .unwrap_or(true)
    {
        eprintln!("skipping: this host cannot run 32-bit ARM binaries");
        return;
    }
    let o = run(&[
        "-r",
        "/",
        "-b",
        "/tmp:/pn-x",
        "-k",
        "4.4.0-fake",
        p.to_str().unwrap(),
        "/etc/hostname",
    ]);
    let out = stdout(&o);
    assert!(
        out.contains("readlink /proc/self/exe -> ") && out.contains("armtest"),
        "{out}\n{}",
        String::from_utf8_lossy(&o.stderr)
    );
    assert!(out.contains("stat64 /etc/hostname -> rc=0"), "{out}");
    assert!(out.contains("open+read /etc/hostname -> "), "{out}");
    assert!(
        out.contains("O_PATH open / -> fd=3") || out.contains("O_PATH open / -> fd="),
        "{out}"
    );
    assert!(out.contains("chdir /tmp -> rc=0, getcwd=/tmp"), "{out}");
    assert!(out.contains("release=4.4.0-fake"), "{out}");
}

#[test]
#[cfg(target_arch = "x86_64")]
fn breakpoint_is_resumed_like_a_debugger_would() {
    // Valve's assert macro executes int3 when it believes a debugger is attached.
    // This test re-runs itself under proot as the probe (see `int3_probe`).
    let me = std::env::current_exe().unwrap();
    let o = Command::new(proot())
        .args([
            "-r",
            "/",
            me.to_str().unwrap(),
            "--exact",
            "int3_probe",
            "--nocapture",
        ])
        .env("PROOT_E2E_INT3", "1")
        .output()
        .unwrap();
    assert!(
        o.status.success(),
        "probe died: {:?}\n{}",
        o.status,
        String::from_utf8_lossy(&o.stderr)
    );
    assert!(String::from_utf8_lossy(&o.stdout).contains("survived int3"));
}

/// Executes `int3` when asked to by [`breakpoint_is_resumed_like_a_debugger_would`]; a no-op otherwise.
#[test]
#[cfg(target_arch = "x86_64")]
fn int3_probe() {
    if std::env::var_os("PROOT_E2E_INT3").is_none() {
        return;
    }
    unsafe { std::arch::asm!("int3") };
    println!("survived int3");
}

#[test]
fn supervisor_exits_with_its_last_tracee() {
    let start = Instant::now();
    let mut child = Command::new(proot())
        .args(["-r", "/", "/bin/sleep", "0.2"])
        .spawn()
        .unwrap();
    let status = child.wait().unwrap();
    assert!(status.success());
    assert!(
        start.elapsed() < Duration::from_secs(3),
        "supervisor lingered after its tracee"
    );
}

#[test]
fn non_tracee_child_does_not_pin_the_supervisor() {
    // A helper holding our stderr open (as a logging wrapper once did) must not keep us alive.
    let o = Command::new("/bin/bash")
        .args([
            "-c",
            &format!(
                "exec 2> >(sleep 3); timeout 10 {} -r / /bin/true; echo rc=$?",
                proot().display()
            ),
        ])
        .output()
        .unwrap();
    assert!(String::from_utf8_lossy(&o.stdout).contains("rc=0"));
}

#[test]
fn programs_keep_their_name() {
    let o = run(&[
        "-r",
        "/",
        "-b",
        "/tmp:/pn-x",
        "/bin/bash",
        "-c",
        "sleep 1 & cat /proc/$!/comm; wait",
    ]);
    assert_eq!(stdout(&o), "sleep");
}

#[test]
fn bwrap_mode_builds_a_container() {
    let d = tmpdir("bwrap");
    let bwrap = d.join("bwrap");
    std::os::unix::fs::symlink(proot(), &bwrap).unwrap();
    let script = d.join("t.sh");
    std::fs::write(&script, "#!/bin/sh\nls /; echo FOO=$FOO; hostname; touch /usr/x 2>/dev/null || echo ro-ok; touch /tmp/ok && echo tmp-ok\n").unwrap();
    let o = Command::new(&bwrap)
        .args([
            "--ro-bind",
            "/usr",
            "/usr",
            "--symlink",
            "usr/lib",
            "/lib",
            "--symlink",
            "usr/lib64",
            "/lib64",
            "--symlink",
            "usr/bin",
            "/bin",
            "--ro-bind",
            "/etc",
            "/etc",
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--tmpfs",
            "/tmp",
            "--ro-bind",
            script.to_str().unwrap(),
            "/t.sh",
            "--chdir",
            "/",
            "--setenv",
            "FOO",
            "bar",
            "--hostname",
            "sandbox",
            "--unshare-all",
            "--die-with-parent",
            "--",
            "/bin/sh",
            "/t.sh",
        ])
        .output()
        .unwrap();
    let out = stdout(&o);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    for needle in ["FOO=bar", "sandbox", "ro-ok", "tmp-ok", "t.sh"] {
        assert!(out.contains(needle), "missing {needle} in:\n{out}");
    }
    // The version string is what pressure-vessel parses; the probe is what steam-runtime-check-requirements runs.
    assert!(stdout(&Command::new(&bwrap).arg("--version").output().unwrap()).starts_with("bubblewrap 0.9.0"));
    assert!(
        Command::new(&bwrap)
            .args(["--bind", "/", "/", "true"])
            .status()
            .unwrap()
            .success()
    );
}

#[test]
fn rootfs_runs_shell_scripts_and_reports_guest_paths() {
    let Some(r) = rootfs() else { return };
    let r = r.to_str().unwrap();
    let o = run(&[
        "-R",
        r,
        "/bin/sh",
        "-c",
        "cd /usr/share && /bin/pwd; readlink /proc/self/exe; cat /etc/os-release | head -1",
    ]);
    let out = stdout(&o);
    assert!(out.starts_with("/usr/share\n"), "{out}");
    assert!(
        out.contains("/usr/bin/readlink") || out.contains("coreutils"),
        "{out}"
    );
    assert!(out.contains("NAME="), "{out}");
}

#[test]
fn fake_root_identity_and_privilege_drop() {
    let script = r#"import os
assert os.getresuid() == (0, 0, 0) and os.getegid() == 0
open('/tmp/pn-own', 'w').close(); os.chown('/tmp/pn-own', 0, 0)
assert os.stat('/tmp/pn-own').st_uid == 0; os.unlink('/tmp/pn-own')
assert 'Uid:\t0\t0\t0\t0' in open('/proc/self/status').read()
os.setgroups([65534]); os.setresgid(65534, 65534, 65534); os.setresuid(65534, 65534, 65534)
assert os.getresuid() == (65534, 65534, 65534) and os.getgroups() == [65534]
try:
    os.setuid(0); print('regained root')
except PermissionError:
    print('dropped for good')
"#;
    let o = run(&["-0", "-r", "/", "python3", "-c", script]);
    assert_eq!(
        stdout(&o),
        "dropped for good",
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
}

#[test]
fn fake_root_installs_a_package_with_apt() {
    // The proot-apps base images wrap dpkg to pass --force-not-root when $EUID != 0; under -0 the
    // wrapper takes the real path, and apt's http method drops to _apt and checks the drop took.
    let Some(r) = rootfs() else { return };
    let o = Command::new(proot())
        .args(["-S", r.to_str().unwrap(), "-w", "/", "/bin/sh", "-c",
               "apt-get update -qq && apt-get install -y -qq --no-install-recommends hello >/dev/null 2>&1 && hello"])
        .output()
        .unwrap();
    assert_eq!(
        stdout(&o),
        "Hello, world!",
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
}

#[test]
fn gamepad_discovery_through_libudev() {
    // Compiles tests/probes/gpprobe.c when libudev headers are present; skips otherwise.
    if !Path::new("/usr/include/libudev.h").exists() {
        eprintln!("skipping: libudev.h not installed");
        return;
    }
    let d = tmpdir("gp");
    let bin = d.join("gpprobe");
    let cc = Command::new("cc")
        .args(["-O1", "-o"])
        .arg(&bin)
        .arg(repo().join("tests/probes/gpprobe.c"))
        .arg("-ludev")
        .status()
        .unwrap();
    assert!(cc.success(), "compiling gpprobe.c");
    let o = Command::new(proot())
        .args(["-r", "/", "-b", "/tmp:/pn-x", bin.to_str().unwrap()])
        .output()
        .unwrap();
    let out = stdout(&o);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    assert!(
        out.contains("input devices=") && out.contains("udev monitor: ok"),
        "{out}"
    );
}

#[test]
fn fatal_signal_report_names_the_module() {
    let o = run(&["-v", "1", "-r", "/", "/bin/sh", "-c", "kill -SEGV $$"]);
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(
        err.contains("fatal signal 11") && err.contains("mappings"),
        "{err}"
    );
}
