/*
 * What a program may take for granted about a syscall, checked under the
 * guest stub: registers survive, NULL and long paths behave, output buffers
 * come back, many threads at once, blocked signals, a SIGSYS handler of its
 * own, spawn, vfork, and an exec with a large environment.
 *
 *   stubprobe DIR    DIR is an empty directory, as the program sees it
 *
 * Builds for x86_64 and aarch64, and with -no-pie for i386 (-m32) and 32-bit
 * ARM.
 *
 * Prints "ok <case>" or "FAIL <case>: ..." per case and exits 1 on a failure.
 * The cases hold without proot as well, which is how the test checks them.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

static const char *dir;
static char file[4096];
static int failed;

#define CHECK(name, cond, ...)                                                                     \
    do {                                                                                           \
        int e_ = errno;                                                                            \
        if (cond) {                                                                                \
            printf("ok %s\n", name);                                                               \
        } else {                                                                                   \
            failed = 1;                                                                            \
            printf("FAIL %s: ", name);                                                             \
            printf(__VA_ARGS__);                                                                   \
            printf(" (errno %d)\n", e_);                                                           \
        }                                                                                          \
        fflush(stdout);                                                                            \
    } while (0)

static const char content[] = "hello stub";

static int read_back(int fd) {
    char buf[64] = {0};
    ssize_t n = read(fd, buf, sizeof buf - 1);
    close(fd);
    return n == (ssize_t)strlen(content) && strcmp(buf, content) == 0;
}

#if defined(__x86_64__)
/* openat by hand with known values in every register a syscall preserves;
 * r9 is the last argument register. */
static void registers(unsigned long r9) {
    unsigned long out[9];
    __asm__ volatile("mov $0x1111, %%r8\n\t"
                     "mov %[r9], %%r9\n\t"
                     "mov $0x3333, %%r10\n\t"
                     "mov $0x4444, %%r12\n\t"
                     "mov $0x5555, %%rbx\n\t"
                     "mov $257, %%eax\n\t"
                     "mov $-100, %%rdi\n\t"
                     "mov %[p], %%rsi\n\t"
                     "xor %%edx, %%edx\n\t"
                     "syscall\n\t"
                     "mov %%rax, 0(%[o])\n\t"
                     "mov %%rdi, 8(%[o])\n\t"
                     "mov %%rsi, 16(%[o])\n\t"
                     "mov %%rdx, 24(%[o])\n\t"
                     "mov %%r10, 32(%[o])\n\t"
                     "mov %%r8, 40(%[o])\n\t"
                     "mov %%r9, 48(%[o])\n\t"
                     "mov %%r12, 56(%[o])\n\t"
                     "mov %%rbx, 64(%[o])\n\t"
                     :
                     : [p] "r"(file), [o] "r"(out), [r9] "r"(r9)
                     : "rax", "rbx", "rdi", "rsi", "rdx", "r10", "r8", "r9", "r12", "rcx", "r11",
                       "memory");
    long fd = (long)out[0];
    int ok = fd >= 0 && read_back((int)fd) && out[1] == (unsigned long)-100 &&
             out[2] == (unsigned long)file && out[3] == 0 && out[4] == 0x3333 && out[5] == 0x1111 &&
             out[6] == r9 && out[7] == 0x4444 && out[8] == 0x5555;
    CHECK(r9 == 0x4321 ? "registers-old-magic" : "registers", ok,
          "fd %ld rdi %lx rsi %lx rdx %lx r10 %lx r8 %lx r9 %lx r12 %lx rbx %lx", fd, out[1], out[2],
          out[3], out[4], out[5], out[6], out[7], out[8]);
}
#elif defined(__i386__)
unsigned long regs_in[2];
unsigned long regs_out[7];

/* openat by hand through int $0x80 with known values in every register a
 * syscall preserves; ebp is the last argument register.  Built -no-pie, so
 * the globals are addressed directly. */
static void registers(unsigned long ebp) {
    regs_in[0] = (unsigned long)file;
    regs_in[1] = ebp;
    __asm__ volatile("pushl %%ebp\n\t"
                     "pushl %%ebx\n\t"
                     "movl $-100, %%ebx\n\t"
                     "movl regs_in, %%ecx\n\t"
                     "xorl %%edx, %%edx\n\t"
                     "movl $0x3333, %%esi\n\t"
                     "movl $0x1111, %%edi\n\t"
                     "movl regs_in+4, %%ebp\n\t"
                     "movl $295, %%eax\n\t"
                     "int $0x80\n\t"
                     "movl %%eax, regs_out\n\t"
                     "movl %%ebx, regs_out+4\n\t"
                     "movl %%ecx, regs_out+8\n\t"
                     "movl %%edx, regs_out+12\n\t"
                     "movl %%esi, regs_out+16\n\t"
                     "movl %%edi, regs_out+20\n\t"
                     "movl %%ebp, regs_out+24\n\t"
                     "popl %%ebx\n\t"
                     "popl %%ebp\n\t"
                     :
                     :
                     : "eax", "ecx", "edx", "esi", "edi", "memory");
    long fd = (long)regs_out[0];
    int ok = fd >= 0 && read_back((int)fd) && regs_out[1] == (unsigned long)-100 &&
             regs_out[2] == (unsigned long)file && regs_out[3] == 0 && regs_out[4] == 0x3333 &&
             regs_out[5] == 0x1111 && regs_out[6] == ebp;
    CHECK(ebp == 0x4321 ? "registers-old-magic" : "registers", ok,
          "fd %ld ebx %lx ecx %lx edx %lx esi %lx edi %lx ebp %lx", fd, regs_out[1], regs_out[2],
          regs_out[3], regs_out[4], regs_out[5], regs_out[6]);
}
#elif defined(__aarch64__)
/* openat by hand with known values in the registers a syscall preserves;
 * x5 is the last argument register, x8 the number, x16 the register the
 * stub's own gates return through, x19 one the C ABI preserves. */
static void registers(unsigned long last) {
    unsigned long out[9];
    __asm__ volatile("mov x0, #-100\n\t"
                     "mov x1, %[p]\n\t"
                     "mov x2, #0\n\t"
                     "mov x3, #0x3333\n\t"
                     "mov x4, #0x1111\n\t"
                     "mov x5, %[last]\n\t"
                     "mov x8, #56\n\t"
                     "mov x16, #0x4444\n\t"
                     "mov x19, #0x5555\n\t"
                     "svc #0\n\t"
                     "stp x0, x1, [%[o]]\n\t"
                     "stp x2, x3, [%[o], #16]\n\t"
                     "stp x4, x5, [%[o], #32]\n\t"
                     "stp x8, x16, [%[o], #48]\n\t"
                     "str x19, [%[o], #64]\n\t"
                     :
                     : [p] "r"(file), [o] "r"(out), [last] "r"(last)
                     : "x0", "x1", "x2", "x3", "x4", "x5", "x8", "x16", "x19", "memory");
    long fd = (long)out[0];
    int ok = fd >= 0 && read_back((int)fd) && out[1] == (unsigned long)file && out[2] == 0 &&
             out[3] == 0x3333 && out[4] == 0x1111 && out[5] == last && out[6] == 56 &&
             out[7] == 0x4444 && out[8] == 0x5555;
    CHECK(last == 0x4321 ? "registers-old-magic" : "registers", ok,
          "fd %ld x1 %lx x2 %lx x3 %lx x4 %lx x5 %lx x8 %lx x16 %lx x19 %lx", fd, out[1], out[2],
          out[3], out[4], out[5], out[6], out[7], out[8]);
}
#elif defined(__arm__)
unsigned long regs_in[2];
unsigned long regs_out[7];

/* openat by hand through svc with known values in the registers a syscall
 * preserves; r5 is the last argument register, r7 the number.  Built
 * -no-pie, so the globals are addressed by their absolute halves. */
static void registers(unsigned long last) {
    regs_in[0] = (unsigned long)file;
    regs_in[1] = last;
    __asm__ volatile("push {r4, r5, r6, r7}\n\t"
                     "movw r6, #:lower16:regs_in\n\t"
                     "movt r6, #:upper16:regs_in\n\t"
                     "mvn r0, #99\n\t"
                     "ldr r1, [r6]\n\t"
                     "mov r2, #0\n\t"
                     "movw r3, #0x3333\n\t"
                     "movw r4, #0x1111\n\t"
                     "ldr r5, [r6, #4]\n\t"
                     "movw r7, #322\n\t"
                     "svc #0\n\t"
                     "movw r6, #:lower16:regs_out\n\t"
                     "movt r6, #:upper16:regs_out\n\t"
                     "str r0, [r6]\n\t"
                     "str r1, [r6, #4]\n\t"
                     "str r2, [r6, #8]\n\t"
                     "str r3, [r6, #12]\n\t"
                     "str r4, [r6, #16]\n\t"
                     "str r5, [r6, #20]\n\t"
                     "str r7, [r6, #24]\n\t"
                     "pop {r4, r5, r6, r7}\n\t"
                     :
                     :
                     : "r0", "r1", "r2", "r3", "memory");
    long fd = (long)regs_out[0];
    int ok = fd >= 0 && read_back((int)fd) && regs_out[1] == (unsigned long)file && regs_out[2] == 0 &&
             regs_out[3] == 0x3333 && regs_out[4] == 0x1111 && regs_out[5] == last &&
             regs_out[6] == 322;
    CHECK(last == 0x4321 ? "registers-old-magic" : "registers", ok,
          "fd %ld r1 %lx r2 %lx r3 %lx r4 %lx r5 %lx r7 %lx", fd, regs_out[1], regs_out[2],
          regs_out[3], regs_out[4], regs_out[5], regs_out[6]);
}
#endif

static void null_paths(void) {
    int fd = open(file, O_RDWR);
    CHECK("futimens", fd >= 0 && futimens(fd, NULL) == 0, "fd %d", fd);
    CHECK("utimensat-at-fd", fd >= 0 && syscall(SYS_utimensat, fd, NULL, NULL, 0) == 0, "fd %d", fd);
    close(fd);
    CHECK("open-null", syscall(SYS_openat, AT_FDCWD, NULL, O_RDONLY) < 0 && errno == EFAULT, "not EFAULT");
}

static void long_paths(void) {
    char path[8192];
    snprintf(path, sizeof path, "%s", dir);
    for (int i = 0; i < 8; i++) {
        size_t n = strlen(path);
        snprintf(path + n, sizeof path - n, "/%s%d", "a-directory-name-of-some-fifty-characters-long-xx", i);
        mkdir(path, 0755);
    }
    size_t n = strlen(path);
    snprintf(path + n, sizeof path - n, "/f");
    int fd = open(path, O_CREAT | O_WRONLY, 0644);
    CHECK("long-path", fd >= 0 && strlen(path) > 400, "len %zu", strlen(path));
    close(fd);
    memset(path, 'x', 5000);
    path[0] = '/';
    path[5000] = 0;
    CHECK("too-long-path", open(path, O_RDONLY) < 0 && errno == ENAMETOOLONG, "not ENAMETOOLONG");
}

static void outputs(void) {
    char link[4200], buf[256];
    const char *target = "some/target/that/is/long/enough/to/notice/a/short/copy";
    snprintf(link, sizeof link, "%s/link", dir);
    symlink(target, link);
    ssize_t n = readlink(link, buf, sizeof buf);
    CHECK("readlink", n == (ssize_t)strlen(target) && memcmp(buf, target, n) == 0, "%zd", n);
    memset(buf, 0, sizeof buf);
    n = readlink(link, buf, 5);
    CHECK("readlink-short", n == 5 && memcmp(buf, target, 5) == 0 && buf[5] == 0, "%zd", n);
    char cwd[4200];
    CHECK("getcwd", chdir(dir) == 0 && getcwd(cwd, sizeof cwd) && strcmp(cwd, dir) == 0, "%s", cwd);
    CHECK("getcwd-erange", getcwd(cwd, 2) == NULL && errno == ERANGE, "not ERANGE");
    struct stat st;
    CHECK("stat", stat(file, &st) == 0 && st.st_size == (off_t)strlen(content), "size %ld",
          (long)st.st_size);
    struct statx sx;
    CHECK("statx", statx(AT_FDCWD, file, 0, STATX_SIZE, &sx) == 0 && sx.stx_size == strlen(content),
          "size %llu", (unsigned long long)sx.stx_size);
}

static void *worker(void *arg) {
    long bad = 0;
    for (int i = 0; i < 300; i++) {
        struct stat st;
        if (stat(file, &st) != 0 || st.st_size != (off_t)strlen(content))
            bad++;
        int fd = open(file, O_RDONLY);
        if (fd < 0 || !read_back(fd))
            bad++;
    }
    return (void *)bad;
}

static void threads(void) {
    pthread_t t[48];
    long bad = 0;
    for (int i = 0; i < 48; i++)
        pthread_create(&t[i], NULL, worker, NULL);
    for (int i = 0; i < 48; i++) {
        void *r;
        pthread_join(t[i], &r);
        bad += (long)r;
    }
    CHECK("threads", bad == 0, "%ld bad answers", bad);
}

static void blocked(void) {
    sigset_t all, old;
    sigfillset(&all);
    pthread_sigmask(SIG_BLOCK, &all, &old);
    int fd = open(file, O_RDONLY);
    int ok = fd >= 0 && read_back(fd);
    pthread_sigmask(SIG_SETMASK, &old, NULL);
    CHECK("all-signals-blocked", ok, "open failed");
}

static volatile int in_handler;

static void usr1(int sig) {
    (void)sig;
    int fd = open(file, O_RDONLY);
    in_handler = fd >= 0 && read_back(fd) ? 1 : -1;
}

static void full_mask_handler(void) {
    struct sigaction sa = {0};
    sa.sa_handler = usr1;
    sigfillset(&sa.sa_mask);
    sigaction(SIGUSR1, &sa, NULL);
    raise(SIGUSR1);
    CHECK("handler-with-full-mask", in_handler == 1, "%d", in_handler);
}

static volatile int sys_seen;

static void own_sigsys(int sig, siginfo_t *si, void *uc) {
    (void)uc;
    sys_seen = sig == SIGSYS && si->si_code == SI_TKILL ? 1 : -1;
}

static void sigsys_chain(void) {
    struct sigaction sa = {0}, old = {0};
    sa.sa_sigaction = own_sigsys;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGSYS, &sa, NULL);
    sigaction(SIGSYS, NULL, &old);
    CHECK("sigsys-handler-reported", old.sa_sigaction == own_sigsys, "%p", (void *)old.sa_sigaction);
    raise(SIGSYS);
    CHECK("sigsys-handler-called", sys_seen == 1, "%d", sys_seen);
    sa.sa_handler = SIG_DFL;
    sa.sa_flags = 0;
    sigaction(SIGSYS, &sa, NULL);
    int fd = open(file, O_RDONLY);
    CHECK("open-after-sigsys-default", fd >= 0 && read_back(fd), "fd %d", fd);
}

static int status_of(pid_t pid) {
    int st;
    if (waitpid(pid, &st, 0) != pid)
        return -1;
    return WIFEXITED(st) ? WEXITSTATUS(st) : 128 + WTERMSIG(st);
}

static void spawn(void) {
    pid_t pid;
    char *argv[] = {"sh", "-c", "exit 3", NULL};
    int rc = posix_spawn(&pid, "/bin/sh", NULL, NULL, argv, environ);
    CHECK("posix-spawn", rc == 0 && status_of(pid) == 3, "rc %d", rc);
    posix_spawnattr_t attr;
    sigset_t all;
    sigfillset(&all);
    posix_spawnattr_init(&attr);
    posix_spawnattr_setsigmask(&attr, &all);
    posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETSIGMASK);
    rc = posix_spawn(&pid, "/bin/sh", NULL, &attr, argv, environ);
    CHECK("posix-spawn-all-blocked", rc == 0 && status_of(pid) == 3, "rc %d", rc);
    pid = vfork();
    if (pid == 0) {
        execl("/bin/sh", "sh", "-c", "exit 4", (char *)NULL);
        _exit(127);
    }
    CHECK("vfork-exec", status_of(pid) == 4, "pid %d", pid);
    pid = fork();
    if (pid == 0) {
        int fd = open(file, O_RDONLY);
        _exit(fd >= 0 && read_back(fd) ? 5 : 6);
    }
    CHECK("fork", status_of(pid) == 5, "pid %d", pid);
}

static void big_environment(void) {
    size_t len = 50 * 1024;
    char *big = malloc(len + 1);
    memset(big, 'x', len);
    big[len] = 0;
    for (int i = 0; i < 4; i++) {
        char name[16];
        snprintf(name, sizeof name, "PN_BIG%d", i);
        setenv(name, big, 1);
    }
    free(big);
    int p[2];
    pipe(p);
    pid_t pid = fork();
    if (pid == 0) {
        dup2(p[1], 1);
        execl("/bin/sh", "sh", "-c", "echo $((${#PN_BIG0} + ${#PN_BIG1} + ${#PN_BIG2} + ${#PN_BIG3}))",
              (char *)NULL);
        _exit(127);
    }
    close(p[1]);
    char out[64] = {0};
    ssize_t n = read(p[0], out, sizeof out - 1);
    close(p[0]);
    int st = status_of(pid);
    for (int i = 0; i < 4; i++) {
        char name[16];
        snprintf(name, sizeof name, "PN_BIG%d", i);
        unsetenv(name);
    }
    CHECK("exec-large-environment", st == 0 && n > 0 && atol(out) == 4 * (long)len, "status %d out %s",
          st, out);
}

int main(int argc, char **argv) {
    if (argc != 2)
        return 2;
    dir = argv[1];
    snprintf(file, sizeof file, "%s/file", dir);
    int fd = open(file, O_CREAT | O_TRUNC | O_WRONLY, 0644);
    if (fd < 0 || write(fd, content, strlen(content)) != (ssize_t)strlen(content)) {
        printf("FAIL setup: %s (errno %d)\n", file, errno);
        return 1;
    }
    close(fd);
    registers(0x2222);
    registers(0x4321);
    null_paths();
    long_paths();
    outputs();
    threads();
    blocked();
    full_mask_handler();
    sigsys_chain();
    spawn();
    big_environment();
    printf("done\n");
    return failed;
}
