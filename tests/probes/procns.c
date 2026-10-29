// Stats /proc/<pid>/ns/pid the way CUDA's driver does to name its socket: a
// stat that follows the link gives the namespace's inode, the one in the link's
// text, through /proc/<pid> and through /proc/self alike.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

int main(void) {
    char text[64], path[64];
    ssize_t n = readlink("/proc/self/ns/pid", text, sizeof text - 1);
    if (n < 0) {
        perror("readlink");
        return 1;
    }
    text[n] = 0;
    char *open = strchr(text, '[');
    unsigned long ino = open ? strtoul(open + 1, NULL, 10) : 0;
    struct stat by_pid, by_self;
    snprintf(path, sizeof path, "/proc/%d/ns/pid", getpid());
    int a = stat(path, &by_pid), b = stat("/proc/self/ns/pid", &by_self);
    printf("pid: %s\n", a ? "stat failed" : by_pid.st_ino == ino ? "namespace" : "other inode");
    printf("self: %s\n", b ? "stat failed" : by_self.st_ino == ino ? "namespace" : "other inode");
    return 0;
}
