/*
 * Runs a command under a seccomp filter that refuses every syscall number
 * the kernel does not know with ENOSYS, as container runtimes' default
 * profiles do.  Such a refusal outranks a user notification of the filters
 * installed after it, which is what proot-next's own filter is.
 *
 *   denyunknown COMMAND [ARG...]
 */
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <errno.h>

int main(int argc, char **argv) {
    if (argc < 2)
        return 2;
    struct sock_filter f[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, 512, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | ENOSYS),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog prog = {sizeof f / sizeof f[0], f};
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) || syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog)) {
        perror("denyunknown: seccomp");
        return 2;
    }
    execvp(argv[1], argv + 1);
    perror("denyunknown: exec");
    return 127;
}
