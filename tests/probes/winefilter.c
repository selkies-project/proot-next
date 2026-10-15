/*
 * Installs the seccomp filter Proton's Wine installs for games that make
 * Windows syscalls directly (install_bpf in dlls/ntdll/unix/signal_x86_64.c
 * of Valve's Wine, as Proton Experimental ships it): a syscall whose
 * instruction pointer's high word is
 * 0x7000 or lower is trapped as a Windows program's, unless it comes from
 * the preloader's page at 0x7d400000; anything higher, where native
 * libraries live, is allowed.
 * Then opens and reads a file through libc, which runs from above.  Under
 * the guest stub that open is served through the stub's gates, which must
 * lie in the allowed range too.
 *
 *   winefilter FILE    prints "wine filter ok" or what went wrong, exit 0 or 1
 *
 * x86_64 only: the address split is Wine's x86_64 one.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <ucontext.h>
#include <unistd.h>

static volatile unsigned long trapped_ip;

static void sigsys(int sig, siginfo_t *si, void *uc) {
    (void)sig;
    (void)uc;
    trapped_ip = (unsigned long)si->si_call_addr;
#if defined(__x86_64__)
    ((ucontext_t *)uc)->uc_mcontext.gregs[REG_RAX] = -ENOSYS;
#endif
}

int main(int argc, char **argv) {
    if (argc != 2)
        return 2;
    struct sigaction sa = {0};
    sa.sa_sigaction = sigsys;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGSYS, &sa, NULL);
    struct sock_filter f[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, instruction_pointer) + 4),
        BPF_JUMP(BPF_JMP | BPF_JGT | BPF_K, 0x7000, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, instruction_pointer)),
        BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, 0x7d400000, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),
        BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, 0x7d402000, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog prog = {sizeof f / sizeof f[0], f};
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) || syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog)) {
        perror("winefilter: seccomp");
        return 2;
    }
    char buf[64] = {0};
    int fd = open(argv[1], O_RDONLY);
    ssize_t n = fd >= 0 ? read(fd, buf, sizeof buf - 1) : -1;
    if (trapped_ip) {
        printf("wine filter trapped a syscall from %#lx\n", trapped_ip);
        return 1;
    }
    if (fd < 0 || n <= 0) {
        printf("wine filter: open or read failed (%s)\n", strerror(errno));
        return 1;
    }
    printf("wine filter ok\n");
    return 0;
}
