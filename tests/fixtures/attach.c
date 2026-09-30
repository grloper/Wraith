#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

/* Block in read from anonymous code before attachment. The following socket
 * must be blocked at ENTRY, not inspected one stop late at its exit. */
static void *payload(void *unused) {
    (void)unused;
    const unsigned char code[] = {
        0x31,0xc0, 0x31,0xff, 0x53, 0x48,0x89,0xe6,
        0xba,1,0,0,0, 0x0f,0x05, 0x5b,
        0xb8,41,0,0,0, 0xbf,2,0,0,0, 0xbe,1,0,0,0,
        0x31,0xd2, 0x0f,0x05, 0xc3
    };
    void *page = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) _exit(24);
    memcpy(page, code, sizeof(code));
    puts("READY");
    fflush(stdout);
    long result = ((long (*)(void))page)();
    _exit(result == -38 ? 0 : 23);
}

static void *replace_image(void *unused) {
    (void)unused;
    execl("/bin/echo", "echo", "WORKER_EXEC_REACHED", (char *)NULL);
    _exit(27);
}

int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "exec") == 0) {
        pthread_t worker;
        if (pthread_create(&worker, NULL, replace_image, NULL)) return 25;
        pthread_join(worker, NULL);
        return 28;
    }
    if (argc > 1 && strcmp(argv[1], "thread") == 0) {
        pthread_t worker;
        if (pthread_create(&worker, NULL, payload, NULL)) return 25;
        pthread_join(worker, NULL);
    } else {
        payload(NULL);
    }
    return 26;
}
