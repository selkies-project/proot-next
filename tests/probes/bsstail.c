/*
 * The rest of the page a program's bss ends in reads zero, as the kernel
 * leaves it: glibc's dynamic loader allocates its first objects there.  A
 * loader that clears the bss alone leaves whatever the file holds past the
 * data, which in this program is its own symbol and string tables.
 *
 *   bsstail        prints "bss tail zero" or "bss tail dirty: N bytes", exit 0 or 1
 */
#include <stdint.h>
#include <stdio.h>

extern char _end[];

int counter;
const char *names[] = {"a symbol table follows the data in the file", "so the page tail is not zero there"};

int main(void) {
    long bad = 0;
    uintptr_t end = (uintptr_t)_end, page = (end + 4095) & ~(uintptr_t)4095;
    for (uintptr_t a = end; a < page; a++)
        bad += *(volatile char *)a != 0;
    if (bad) {
        printf("bss tail dirty: %ld bytes\n", bad);
        return 1;
    }
    printf("bss tail zero\n");
    return counter + (names[0][0] == 0);
}
