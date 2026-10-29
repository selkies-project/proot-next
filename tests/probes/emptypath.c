// An empty path, call by call, in the directory argv[1]: refused with ENOENT,
// except where AT_EMPTY_PATH (or readlinkat, always) lets it name a descriptor.
// CUDA's driver unlinks "" before it binds an abstract socket.  Errno names
// come from strerrorname_np (glibc 2.32 and later).
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef SYS_faccessat2
#define SYS_faccessat2 439
#endif
#ifndef SYS_fchmodat2
#define SYS_fchmodat2 452
#endif

extern char **environ;

static void say(const char *call, long rc) {
    if (rc < 0)
        printf("%s: %s\n", call, strerrorname_np(errno));
    else
        printf("%s: ok\n", call);
}

int main(int argc, char **argv) {
    char buf[64], link[512];
    char *args[] = {"x", NULL};
    struct stat st;
    struct statfs sfs;
    struct statx sx;
    if (argc != 2 || chdir(argv[1]))
        return 2;
    say("unlink", unlink(""));
    say("rmdir", rmdir(""));
    say("mkdir", mkdir("", 0755));
    say("open", open("", O_RDONLY));
    say("access", access("", F_OK));
    say("stat", stat("", &st));
    say("lstat", lstat("", &st));
    say("fstatat", fstatat(AT_FDCWD, "", &st, 0));
    say("statx", statx(AT_FDCWD, "", 0, STATX_BASIC_STATS, &sx));
    say("statfs", statfs("", &sfs));
    say("truncate", truncate("", 0));
    say("chdir", chdir(""));
    say("rename", rename("", "x"));
    say("readlink", readlink("", buf, sizeof buf));
    say("chroot", chroot(""));
    say("inotify_add_watch", inotify_add_watch(inotify_init1(0), "", IN_ALL_EVENTS));
    say("execve", execve("", args, environ));
    say("execveat", syscall(SYS_execveat, AT_FDCWD, "", args, environ, 0));

    int here = open(".", O_RDONLY | O_DIRECTORY);
    say("fstatat AT_EMPTY_PATH", fstatat(here, "", &st, AT_EMPTY_PATH));
    say("statx AT_EMPTY_PATH", statx(here, "", AT_EMPTY_PATH, STATX_BASIC_STATS, &sx));
    say("faccessat2 AT_EMPTY_PATH", syscall(SYS_faccessat2, here, "", F_OK, AT_EMPTY_PATH));
    unlink("link");
    if (symlink("target", "link"))
        return 3;
    snprintf(link, sizeof link, "%s/link", argv[1]);
    int lfd = open(link, O_PATH | O_NOFOLLOW);
    ssize_t n = readlinkat(lfd, "", buf, sizeof buf);
    printf("readlinkat of a link: %.*s\n", n < 0 ? 0 : (int)n, buf);
    say("readlinkat of a directory", readlinkat(here, "", buf, sizeof buf));
    int f = open("file", O_CREAT | O_RDWR, 0600);
    say("readlinkat of a file", readlinkat(f, "", buf, sizeof buf));
    long rc = syscall(SYS_fchmodat2, f, "", 0640, AT_EMPTY_PATH);
    if (rc == 0 && fstat(f, &st) == 0)
        printf("fchmodat2 AT_EMPTY_PATH: %o\n", st.st_mode & 0777);
    else
        say("fchmodat2 AT_EMPTY_PATH", rc);
    say("execveat AT_EMPTY_PATH of the working directory",
        syscall(SYS_execveat, AT_FDCWD, "", args, environ, AT_EMPTY_PATH));
    return 0;
}
