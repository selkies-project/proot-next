//! End-to-end tests: the built `proot` binary driving real programs.
//!
//! Every case here is a failure that was first seen in a real application
//! (Brave, Steam's webhelper, Half-Life, libudev) and then reduced.  They
//! need ptrace and seccomp user notification on the running kernel, which
//! CI's Linux runners provide.  Cases that need a rootfs read
//! `PROOT_TEST_ROOTFS`; cases that need a 32-bit probe read
//! `tests/probes/bin/`; both skip with a message when absent.
//!
//! The whole suite also runs with `PROOT_NO_PTRACE=1` in the environment,
//! which the binary inherits: everything then goes through the no-ptrace
//! mode, except the cases that are about the tracer itself, which skip.
//! The `no_ptrace_*` cases force that mode themselves.

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

/// Runs `proot` with `args` in the no-ptrace mode.
fn run_no_ptrace(args: &[&str]) -> Output {
    Command::new(proot())
        .env("PROOT_NO_PTRACE", "1")
        .args(args)
        .stdin(Stdio::null())
        .output()
        .expect("spawn proot")
}

/// Whether the suite runs in the no-ptrace mode, where tracer-only cases skip.
fn no_ptrace_suite() -> bool {
    if std::env::var_os("PROOT_NO_PTRACE").is_some_and(|v| v != "0") {
        eprintln!("skipping: needs the ptrace tier");
        return true;
    }
    false
}

/// Makes a file executable.
fn chmod_x(p: &Path) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o755)).unwrap();
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
        "/usr:/pn-x",
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
    if no_ptrace_suite() {
        return;
    }
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
        "sleep 2 & p=$!; for i in 1 2 3 4 5 6 7 8 9 10; do c=$(cat /proc/$p/comm); [ \"$c\" = sleep ] && break; sleep 0.1; done; echo $c; wait",
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
    if no_ptrace_suite() {
        return;
    }
    let o = run(&["-v", "1", "-r", "/", "/bin/sh", "-c", "kill -SEGV $$"]);
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(
        err.contains("fatal signal 11") && err.contains("mappings"),
        "{err}"
    );
}

#[test]
fn signals_landing_on_queued_notifications_do_not_stop_the_pool() {
    // A child exiting sends SIGCHLD to a shell that often has a notification queued;
    // the listener then reports ENOENT, which must not be taken for the end of the pool.
    let mut child = Command::new(proot())
        .args([
            "-r",
            "/",
            "/bin/sh",
            "-c",
            "i=0; while [ $i -lt 300 ]; do echo hi | cat > /dev/null; i=$((i+1)); done; echo done-$i",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let start = Instant::now();
    while child.try_wait().unwrap().is_none() {
        assert!(
            start.elapsed() < Duration::from_secs(60),
            "the supervisor stopped answering"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    let o = child.wait_with_output().unwrap();
    assert_eq!(stdout(&o), "done-300");
}

#[test]
fn namespaces_are_refused_inside_the_guest() {
    // A sandbox helper (bubblewrap for glycin, Firefox's content sandbox) must see the EPERM a
    // default container gives it and fall back, since a tracee in its own mount namespace could
    // not be served from the supervisor's.  Plain forks, through clone or clone3, keep working.
    let script = "import os\n\
                  try:\n    os.unshare(os.CLONE_NEWUSER); print('unshared')\n\
                  except PermissionError: print('refused')\n\
                  try:\n    os.unshare(os.CLONE_NEWNS); print('unshared')\n\
                  except PermissionError: print('refused')\n\
                  pid = os.fork()\n\
                  if pid == 0: os._exit(3)\n\
                  print(os.waitstatus_to_exitcode(os.waitpid(pid, 0)[1]))";
    let o = run(&["-r", "/", "python3", "-c", script]);
    assert_eq!(
        stdout(&o),
        "refused\nrefused\n3",
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
    if Path::new("/usr/bin/bwrap").exists() {
        let o = run(&[
            "-r",
            "/",
            "/usr/bin/bwrap",
            "--unshare-all",
            "--ro-bind",
            "/",
            "/",
            "/bin/true",
        ]);
        let err = String::from_utf8_lossy(&o.stderr);
        assert!(err.contains("No permissions to create a new namespace"), "{err}");
    }
}

#[test]
fn nested_bwrap_mode_fails_like_bubblewrap_without_namespaces() {
    // Images put the bwrap symlink on the guest's PATH, so GTK's glycin may pick it instead of the
    // rootfs's bubblewrap; a nested proot-next must then fail with the words glycin recognizes.
    let d = tmpdir("nested");
    let bwrap = d.join("bwrap");
    std::os::unix::fs::symlink(proot(), &bwrap).unwrap();
    let o = run(&[
        "-r",
        "/",
        bwrap.to_str().unwrap(),
        "--ro-bind",
        "/",
        "/",
        "/bin/true",
    ]);
    let err = String::from_utf8_lossy(&o.stderr);
    assert_eq!(o.status.code(), Some(1), "{err}");
    assert!(
        err.starts_with("bwrap: No permissions to create a new namespace"),
        "{err}"
    );
}

#[test]
fn cmdline_and_comm_read_as_the_kernel_would_give_them() {
    // ps, pgrep -f and programs reading their own command line must not see the loader the
    // exec was retargeted at, and a script's comm is the script's name, not its interpreter's.
    let d = tmpdir("cmdline");
    std::fs::write(
        d.join("tool.sh"),
        "#!/bin/sh\necho \"$(cat /proc/$$/comm) $(tr '\\0' ' ' < /proc/$$/cmdline)\"\n",
    )
    .unwrap();
    chmod_x(&d.join("tool.sh"));
    std::os::unix::fs::symlink("tool.sh", d.join("tool")).unwrap();
    let bind = format!("{}:/pn-c", d.display());
    let o = run(&[
        "-r",
        "/",
        "-b",
        &bind,
        "/bin/sh",
        "-c",
        "tr '\\0' ' ' < /proc/self/cmdline; echo; /pn-c/tool one two",
    ]);
    assert_eq!(
        stdout(&o),
        "/bin/sh -c tr '\\0' ' ' < /proc/self/cmdline; echo; /pn-c/tool one two \ntool /bin/sh /pn-c/tool one two",
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
}

#[test]
fn origin_rpath_resolves_through_a_symlinked_program() {
    // Electron apps find their bundled libraries through an $ORIGIN rpath and are started
    // through a symlink in /usr/bin; the loader must see the resolved program path.
    if Command::new("cc").arg("--version").output().is_err() {
        eprintln!("skipping: no C compiler for the $ORIGIN probe");
        return;
    }
    let d = tmpdir("origin");
    std::fs::create_dir_all(d.join("lib")).unwrap();
    std::fs::create_dir_all(d.join("bin")).unwrap();
    std::fs::write(d.join("lib.c"), "int answer(void) { return 42; }\n").unwrap();
    std::fs::write(
        d.join("prog.c"),
        "#include <stdio.h>\nint answer(void);\nint main(void) { printf(\"answer %d\\n\", answer()); return 0; }\n",
    )
    .unwrap();
    let cc = |args: &[&str]| {
        let o = Command::new("cc").current_dir(&d).args(args).output().unwrap();
        assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    };
    cc(&["-shared", "-fPIC", "-o", "lib/libpnorigin.so", "lib.c"]);
    cc(&[
        "-o",
        "lib/prog",
        "prog.c",
        "-Llib",
        "-lpnorigin",
        "-Wl,-rpath,$ORIGIN",
    ]);
    std::os::unix::fs::symlink("../lib/prog", d.join("bin/prog")).unwrap();
    let o = run(&[
        "-r",
        "/",
        "-b",
        &format!("{}:/pn-o", d.display()),
        "/pn-o/bin/prog",
    ]);
    assert_eq!(stdout(&o), "answer 42", "{}", String::from_utf8_lossy(&o.stderr));
}

#[test]
fn no_ptrace_execs_through_the_trampoline() {
    // Dynamic programs, scripts, argv[0] and /proc/self/exe all go through the exec shim.
    let d = tmpdir("np-exec");
    std::fs::write(
        d.join("s.sh"),
        "#!/bin/sh\necho script $1 $(readlink /proc/self/exe)\n",
    )
    .unwrap();
    chmod_x(&d.join("s.sh"));
    let bind = format!("{}:/pn-e", d.display());
    let o = run_no_ptrace(&[
        "-r",
        "/",
        "-b",
        &bind,
        "/bin/sh",
        "-c",
        "/pn-e/s.sh one; sh -c 'echo $0'; cat /proc/self/comm",
    ]);
    let out = stdout(&o);
    assert!(
        out.starts_with("script one /"),
        "{out}\n{}",
        String::from_utf8_lossy(&o.stderr)
    );
    assert!(out.ends_with("\nsh\ncat"), "{out}");
    // A script without #! is refused with ENOEXEC so the shell runs it itself.
    std::fs::write(d.join("plain"), "echo plain-ok\n").unwrap();
    chmod_x(&d.join("plain"));
    let o = run_no_ptrace(&[
        "-r",
        "/",
        "-b",
        &bind,
        "/bin/bash",
        "-c",
        "/pn-e/plain; /pn-e/missing; echo rc=$?",
    ]);
    assert_eq!(
        stdout(&o),
        "plain-ok\nrc=127",
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
}

#[test]
fn no_ptrace_working_directory_is_virtual() {
    let d = tmpdir("np-cwd");
    std::fs::create_dir(d.join("sub")).unwrap();
    std::fs::write(d.join("sub/f"), "data").unwrap();
    let script = "import os\n\
                  os.chdir('/pn-c/sub'); print(os.getcwd(), open('f').read(), os.readlink('/proc/self/cwd'))\n\
                  os.chdir('..'); print(os.getcwd())\n\
                  fd = os.open('/pn-c/sub', os.O_RDONLY); os.fchdir(fd); print(os.getcwd())\n\
                  try:\n    os.chdir('/pn-c/sub/f')\n\
                  except NotADirectoryError: print('notdir')";
    let o = run_no_ptrace(&[
        "-r",
        "/",
        "-b",
        &format!("{}:/pn-c", d.display()),
        "python3",
        "-c",
        script,
    ]);
    assert_eq!(
        stdout(&o),
        "/pn-c/sub data /pn-c/sub\n/pn-c\n/pn-c/sub\nnotdir",
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
}

#[test]
fn no_ptrace_orphans_inherit_the_working_directory() {
    // A daemon forks twice and the middle process exits before the grandchild makes a syscall.
    let d = tmpdir("np-orphan");
    let script = "import os, time\n\
                  os.chdir('/pn-o')\n\
                  r, w = os.pipe()\n\
                  if os.fork() == 0:\n\
                  \x20   if os.fork() == 0:\n\
                  \x20       time.sleep(0.3); os.write(w, os.getcwd().encode()); os._exit(0)\n\
                  \x20   os._exit(0)\n\
                  os.close(w); print(os.read(r, 64).decode())";
    let o = run_no_ptrace(&[
        "-r",
        "/",
        "-b",
        &format!("{}:/pn-o", d.display()),
        "python3",
        "-c",
        script,
    ]);
    assert_eq!(stdout(&o), "/pn-o", "{}", String::from_utf8_lossy(&o.stderr));
}

#[test]
fn no_ptrace_unix_sockets_bind_and_connect_through_bindings() {
    let d = tmpdir("np-sock");
    let script = "import socket, os\n\
                  srv = socket.socket(socket.AF_UNIX); srv.bind('/pn-s/sock'); srv.listen(1)\n\
                  print(os.path.exists('/pn-s/sock'), flush=True)\n\
                  if os.fork() == 0:\n\
                  \x20   c = socket.socket(socket.AF_UNIX); c.setblocking(False)\n\
                  \x20   try: c.connect('/pn-s/sock')\n\
                  \x20   except BlockingIOError: pass\n\
                  \x20   c.setblocking(True); c.send(b'hi'); print(c.recv(8).decode(), flush=True); os._exit(0)\n\
                  a, _ = srv.accept(); a.send(a.recv(8) + b'-back'); os.wait()";
    let o = run_no_ptrace(&[
        "-r",
        "/",
        "-b",
        &format!("{}:/pn-s", d.display()),
        "python3",
        "-c",
        script,
    ]);
    assert_eq!(
        stdout(&o),
        "True\nhi-back",
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
    assert!(d.join("sock").exists());
}

#[test]
fn no_ptrace_inotify_and_opath_keep_the_callers_buffer() {
    use std::os::unix::fs::PermissionsExt;
    let d = tmpdir("np-inotify");
    std::fs::create_dir(d.join("dir")).unwrap();
    std::fs::write(d.join("secret"), "xyz").unwrap();
    std::fs::set_permissions(d.join("secret"), std::fs::Permissions::from_mode(0o000)).unwrap();
    let script = "import ctypes, os\n\
                  libc = ctypes.CDLL(None, use_errno=True)\n\
                  fd = libc.inotify_init1(0); buf = ctypes.create_string_buffer(b'/pn-i/dir')\n\
                  assert libc.inotify_add_watch(fd, buf, 0x100) >= 0, os.strerror(ctypes.get_errno())\n\
                  open('/pn-i/dir/new', 'w').close(); ev = os.read(fd, 256)\n\
                  print(buf.value.decode(), ev[16:].rstrip(b'\\0').decode())\n\
                  p = os.open('/pn-i/secret', os.O_PATH); print(os.fstat(p).st_size)";
    let o = run_no_ptrace(&[
        "-r",
        "/",
        "-b",
        &format!("{}:/pn-i", d.display()),
        "python3",
        "-c",
        script,
    ]);
    assert_eq!(
        stdout(&o),
        "/pn-i/dir new\n3",
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
}

#[test]
fn no_ptrace_spawn_and_fexecve() {
    // posix_spawn shares the parent's memory until the exec; fexecve names no path at all.
    let d = tmpdir("np-spawn");
    std::fs::write(d.join("h.sh"), "#!/bin/sh\necho hello $1\n").unwrap();
    chmod_x(&d.join("h.sh"));
    let script = "import os, ctypes\n\
                  p = '/pn-p/h.sh'\n\
                  for i in range(2):\n\
                  \x20   os.waitpid(os.posix_spawn(p, [p, str(i)], os.environ), 0)\n\
                  print(p, flush=True)\n\
                  if os.fork() == 0:\n\
                  \x20   libc = ctypes.CDLL(None, use_errno=True)\n\
                  \x20   argv = (ctypes.c_char_p * 3)(b'h', b'fd', None)\n\
                  \x20   libc.execveat(os.open(p, os.O_RDONLY), b'', argv, None, 0x1000)\n\
                  \x20   print('execveat failed', os.strerror(ctypes.get_errno()), flush=True); os._exit(1)\n\
                  os.wait()";
    let o = run_no_ptrace(&[
        "-r",
        "/",
        "-b",
        &format!("{}:/pn-p", d.display()),
        "python3",
        "-c",
        script,
    ]);
    assert_eq!(
        stdout(&o),
        "hello 0\nhello 1\n/pn-p/h.sh\nhello fd",
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
}
