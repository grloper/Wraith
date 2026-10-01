#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <pthread.h>
#include <sys/resource.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

static volatile sig_atomic_t signals_seen;
static void handler(int signal_number) {
    (void)signal_number;
    syscall(SYS_getpid);
    signals_seen++;
}

static int altstack(void) {
    void *memory = malloc(65536);
    if (!memory) return 10;
    memset(memory, 0, 65536);
    stack_t stack = {.ss_sp = memory, .ss_size = 65536, .ss_flags = 0};
    if (sigaltstack(&stack, NULL)) return 11;
    struct sigaction action = {.sa_handler = handler, .sa_flags = SA_ONSTACK};
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGUSR1, &action, NULL)) return 12;
    for (int i = 0; i < 8; i++) if (raise(SIGUSR1)) return 13;
    stack.ss_flags = SS_DISABLE;
    if (sigaltstack(&stack, NULL)) return 14;
    free(memory);
    return signals_seen == 8 ? 0 : 15;
}

static int partial_protect(void) {
    size_t page = (size_t)sysconf(_SC_PAGESIZE);
    uint8_t *memory = mmap(NULL, page * 3, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (memory == MAP_FAILED) return 20;
    /* getpid; ret. Safe direct syscall from the first page after partial RX. */
    const uint8_t payload[] = {0xb8, 39, 0, 0, 0, 0x0f, 0x05, 0xc3};
    memcpy(memory, payload, sizeof(payload));
    if (munmap(memory + page, page)) return 21;
    errno = 0;
    if (mprotect(memory, page * 3, PROT_READ | PROT_EXEC) != -1 || errno != ENOMEM) return 22;
    /* On Linux mprotect can change the first VMA before hitting the hole. */
    long result = ((long (*)(void))memory)();
    munmap(memory, page);
    munmap(memory + page * 2, page);
    return result == (long)getpid() ? 0 : 23;
}

static int failed_input(void) {
    size_t page = (size_t)sysconf(_SC_PAGESIZE);
    uint8_t *memory = mmap(NULL, page, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (memory == MAP_FAILED) return 30;
    /* socket(AF_INET, SOCK_STREAM, 0); ret. Strict RX policy still detects it. */
    const uint8_t payload[] = {0xb8, 41, 0, 0, 0, 0xbf, 2, 0, 0, 0,
                              0xbe, 1, 0, 0, 0, 0x31, 0xd2, 0x0f, 0x05, 0xc3};
    memcpy(memory, payload, sizeof(payload));
    if (mprotect(memory, page, PROT_READ | PROT_EXEC)) return 31;
    for (int i = 0; i < 100; i++) syscall(SYS_getpid);
    char buffer[32];
    errno = 0;
    if (syscall(SYS_recvfrom, -1, buffer, sizeof(buffer), 0, NULL, NULL) != -1 || errno != EBADF) return 32;
    if (syscall(SYS_read, 0, buffer, 0) != 0) return 33;
    long descriptor = ((long (*)(void))memory)();
    if (descriptor >= 0) close((int)descriptor);
    munmap(memory, page);
    return descriptor >= 0 ? 0 : 34;
}

static int signal_outcome(int handled, int signal_number) {
    struct rlimit core_limit = {.rlim_cur = 0, .rlim_max = 0};
    if (setrlimit(RLIMIT_CORE, &core_limit)) return 39;
    struct sigaction action = {.sa_handler = handled ? handler : SIG_DFL};
    sigemptyset(&action.sa_mask);
    if (sigaction(signal_number, &action, NULL)) return 40;
    if (raise(signal_number)) return 41;
    return handled && signals_seen == 1 ? 0 : 42;
}

static void *fatal_worker(void *unused) {
    (void)unused;
    signal_outcome(0, SIGSEGV);
    return NULL;
}

static int threaded_fatal(void) {
    pthread_t thread;
    if (pthread_create(&thread, NULL, fatal_worker, NULL)) return 43;
    if (pthread_join(thread, NULL)) return 44;
    return 45; /* Unreachable for the default unhandled disposition. */
}

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    if (!strcmp(argv[1], "altstack")) return altstack();
    if (!strcmp(argv[1], "partial")) return partial_protect();
    if (!strcmp(argv[1], "failed-input")) return failed_input();
    if (!strcmp(argv[1], "handled-segv")) return signal_outcome(1, SIGSEGV);
    if (!strcmp(argv[1], "fatal-segv")) return signal_outcome(0, SIGSEGV);
    if (!strcmp(argv[1], "fatal-fpe")) return signal_outcome(0, SIGFPE);
    if (!strcmp(argv[1], "fatal-ill")) return signal_outcome(0, SIGILL);
    if (!strcmp(argv[1], "fatal-bus")) return signal_outcome(0, SIGBUS);
    if (!strcmp(argv[1], "fatal-abrt")) return signal_outcome(0, SIGABRT);
    if (!strcmp(argv[1], "threaded-fatal")) return threaded_fatal();
    return 2;
}
