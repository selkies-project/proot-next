// Publishes an O_TMPFILE the way Qt's QSaveFile does: linkat of its
// /proc/self/fd link with AT_SYMLINK_FOLLOW, which links the open inode;
// without the flag the link itself is on procfs and cannot be linked.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv) {
    char target[512], link[64], buf[16] = {0};
    if (argc != 2) return 2;
    snprintf(target, sizeof target, "%s/out", argv[1]);
    unlink(target);
    int fd = open(argv[1], O_RDWR | O_TMPFILE, 0644);
    if (fd < 0 || write(fd, "tmp", 3) != 3) {
        perror("O_TMPFILE");
        return 1;
    }
    snprintf(link, sizeof link, "/proc/self/fd/%d", fd);
    int r = linkat(AT_FDCWD, link, AT_FDCWD, target, 0);
    printf("nofollow: %s\n", r ? strerror(errno) : "ok");
    r = linkat(AT_FDCWD, link, AT_FDCWD, target, AT_SYMLINK_FOLLOW);
    int in = open(target, O_RDONLY);
    printf("follow: %s %s\n", r ? strerror(errno) : "ok", in >= 0 && read(in, buf, 3) == 3 ? buf : "-");
    return 0;
}
