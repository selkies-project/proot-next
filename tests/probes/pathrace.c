/* A guest racing its own path lookups.  One thread renames the directories
 * of a chain inside the guest away and puts a symlink to a host directory
 * the guest cannot reach by name in their place, while other threads open
 * and create files through the chain.  The supervisor must keep every call
 * inside the guest: a read sees the guest's own file or fails, and a file
 * created lands in the guest's chain, never in the host directory.
 *
 * usage: pathrace <chain-dir> <host-dir> <seconds> [openers]
 *
 * <chain-dir> is a guest path to build the chain under; <host-dir> is the
 * host path the planted symlink points to, where the test keeps a chain of
 * the same shape whose file reads "outside".  Prints one FINAL line with
 * the counts: reads that saw the guest's file ("inside"), reads that saw
 * the host's ("outside"), ENOENT and other failures, and files created.
 * Exits 0 when no read saw the host's file, 1 when one did, 2 on a setup
 * error.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define DEPTH 6

static char chain[512], bak[512], lnk[512];
static char rpath[1024], wpath[1024], hostpath[1024];
static volatile int stop;
static volatile unsigned long n_inside, n_outside, n_enoent, n_other, n_created;

static void add(volatile unsigned long *n) { __sync_fetch_and_add(n, 1); }

static void deep(char *out, size_t len, const char *base, const char *leaf)
{
    int i, n = snprintf(out, len, "%s", base);
    for (i = 1; i <= DEPTH; i++)
        n += snprintf(out + n, len - n, "/a%d", i);
    snprintf(out + n, len - n, "/%s", leaf);
}

static void *opener(void *x)
{
    char b[64];
    (void)x;
    while (!stop) {
        int fd = open(rpath, O_RDONLY);
        if (fd < 0) {
            add(errno == ENOENT ? &n_enoent : &n_other);
            continue;
        }
        int n = read(fd, b, sizeof b - 1);
        close(fd);
        if (n <= 0) {
            add(&n_other);
            continue;
        }
        b[n] = 0;
        if (strstr(b, "outside"))
            add(&n_outside);
        else if (strstr(b, "inside"))
            add(&n_inside);
        else
            add(&n_other);
    }
    return NULL;
}

static void *creator(void *x)
{
    (void)x;
    while (!stop) {
        int fd = open(wpath, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd < 0)
            continue;
        if (write(fd, "created\n", 8) == 8)
            add(&n_created);
        close(fd);
    }
    return NULL;
}

static void *flipper(void *x)
{
    (void)x;
    while (!stop) {
        if (rename(chain, bak) != 0)
            continue;
        rename(lnk, chain);
        rename(chain, lnk);
        rename(bak, chain);
    }
    return NULL;
}

int main(int argc, char **argv)
{
    int i, secs, openers = 4;
    pthread_t th[64];
    if (argc < 4)
        return 2;
    secs = atoi(argv[3]);
    if (argc > 4)
        openers = atoi(argv[4]);
    if (openers < 1 || openers > 60)
        return 2;
    snprintf(chain, sizeof chain, "%s/chain", argv[1]);
    snprintf(bak, sizeof bak, "%s/chain.bak", argv[1]);
    snprintf(lnk, sizeof lnk, "%s/chain.lnk", argv[1]);
    deep(rpath, sizeof rpath, chain, "flag");
    deep(wpath, sizeof wpath, chain, "wn");
    deep(hostpath, sizeof hostpath, argv[2], "flag");

    char p[600];
    snprintf(p, sizeof p, "%s", chain);
    if (mkdir(p, 0777) && errno != EEXIST) {
        perror("mkdir chain");
        return 2;
    }
    for (i = 1; i <= DEPTH; i++) {
        snprintf(p + strlen(p), sizeof p - strlen(p), "/a%d", i);
        if (mkdir(p, 0777) && errno != EEXIST) {
            perror("mkdir");
            return 2;
        }
    }
    FILE *f = fopen(rpath, "w");
    if (!f) {
        perror("flag");
        return 2;
    }
    fputs("inside\n", f);
    fclose(f);
    unlink(lnk);
    if (symlink(argv[2], lnk)) {
        perror("symlink");
        return 2;
    }
    /* The host directory is not reachable by its name from the guest. */
    int fd = open(hostpath, O_RDONLY);
    if (fd >= 0) {
        printf("setup: %s is reachable from the guest\n", hostpath);
        return 2;
    }
    fd = open(rpath, O_RDONLY);
    if (fd < 0) {
        perror("chain");
        return 2;
    }
    close(fd);

    for (i = 0; i < openers; i++)
        pthread_create(&th[i], NULL, opener, NULL);
    pthread_create(&th[openers], NULL, creator, NULL);
    pthread_create(&th[openers + 1], NULL, flipper, NULL);
    struct timespec ts = {secs, 0};
    nanosleep(&ts, NULL);
    stop = 1;
    for (i = 0; i < openers + 2; i++)
        pthread_join(th[i], NULL);
    printf("FINAL inside=%lu outside=%lu enoent=%lu other=%lu created=%lu\n",
           n_inside, n_outside, n_enoent, n_other, n_created);
    return n_outside > 0 ? 1 : 0;
}
