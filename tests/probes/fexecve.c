// execveat(fd, "", AT_EMPTY_PATH) runs what fd names: this probe itself (an
// ELF) and a #! script, both in the directory argv[1], from children that print
// their own words.  A script's descriptor stays open across the exec, as the
// kernel needs it to.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

int main(int argc, char **argv) {
    char path[512];
    const char *names[] = {"fexecve", "h.sh"};
    char *words[][5] = {{"fexecve", "--say", "elf", "fd", NULL}, {"h", "fd", NULL}};
    if (argc == 4 && !strcmp(argv[1], "--say")) {
        printf("%s %s\n", argv[2], argv[3]);
        return 0;
    }
    if (argc != 2)
        return 2;
    for (int i = 0; i < 2; i++) {
        fflush(stdout);
        pid_t child = fork();
        if (child == 0) {
            snprintf(path, sizeof path, "%s/%s", argv[1], names[i]);
            int fd = open(path, O_RDONLY);
            syscall(SYS_execveat, fd, "", words[i], environ, AT_EMPTY_PATH);
            printf("execveat failed: %s\n", strerror(errno));
            _exit(1);
        }
        waitpid(child, NULL, 0);
    }
    return 0;
}
