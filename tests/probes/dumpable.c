/* A process that clears its dumpable flag, as Bitwarden's process isolation
 * and Chromium's sandbox do, and then keeps using paths, descriptor-relative
 * paths and threads.  Prints one line per check; exits non-zero on the first
 * failure.  Argument: a directory holding a file named "f". */
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <unistd.h>

static void *thread(void *arg) { return arg; }

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: dumpable DIR\n");
        return 2;
    }
    if (prctl(PR_SET_DUMPABLE, 0) != 0) {
        printf("set: %s\n", strerror(errno));
        return 1;
    }
    printf("dumpable=%d\n", prctl(PR_GET_DUMPABLE));
    int dir = open(argv[1], O_RDONLY | O_DIRECTORY);
    if (dir < 0) {
        printf("open: %s\n", strerror(errno));
        return 1;
    }
    int fd = openat(dir, "f", O_RDONLY);
    if (fd < 0) {
        printf("openat: %s\n", strerror(errno));
        return 1;
    }
    close(fd);
    close(dir);
    pthread_t t;
    int rc = pthread_create(&t, NULL, thread, NULL);
    if (rc != 0) {
        printf("pthread_create: %s\n", strerror(rc));
        return 1;
    }
    pthread_join(t, NULL);
    if (prctl(PR_SET_DUMPABLE, 1) != 0) {
        printf("reset: %s\n", strerror(errno));
        return 1;
    }
    printf("dumpable=%d\n", prctl(PR_GET_DUMPABLE));
    printf("ok\n");
    return 0;
}
