#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <signal.h>
#include <errno.h>

void check_syscall_block(const char *name, int result)
{
    if (result == -1 && errno == EPERM)
    {
        printf("%s blocked successfully (EPERM).\n", name);
    }
    else if (result == -1)
    {
        printf("ERROR! %s failed for another reason (errno: %d).\n", name, errno);
    }
    else
    {
        printf("ERROR! %s was not blocked!\n", name);
    }
}

int main(void)
{
    printf("Starting Seccomp Test...\n\n");

    // Hardware access test
    errno = 0;
    int res_ioctl = ioctl(STDOUT_FILENO, TIOCGWINSZ, NULL);
    check_syscall_block("ioctl", res_ioctl);

    // UID change test
    errno = 0;
    int res_setuid = setuid(1000);
    check_syscall_block("setuid", res_setuid);

    // Process intervention test
    errno = 0;
    int res_kill = kill(getpid(), 0);
    check_syscall_block("kill", res_kill);

    // Memory protection tests

    // Test mmap with PROT_EXEC
    errno = 0;
    void *exec_mem = mmap(NULL, 4096,
                          PROT_READ | PROT_EXEC,
                          MAP_PRIVATE | MAP_ANONYMOUS,
                          -1, 0);

    if (exec_mem == MAP_FAILED)
    {
        check_syscall_block("mmap(PROT_EXEC)", -1);
    }
    else
    {
        check_syscall_block("mmap(PROT_EXEC)", 0);
        munmap(exec_mem, 4096);
    }

    // Allocate writable memory for the next tests
    void *memory = mmap(NULL, 4096,
                        PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS,
                        -1, 0);

    if (memory == MAP_FAILED)
    {
        printf("ERROR! Could not allocate memory for mprotect tests (errno: %d).\n", errno);
        return 1;
    }

    // Test mprotect with PROT_EXEC
    errno = 0;
    int res_mprotect = mprotect(memory, 4096,
                                PROT_READ | PROT_EXEC);
    check_syscall_block("mprotect(PROT_EXEC)", res_mprotect);

    // Test pkey_mprotect with PROT_EXEC
    errno = 0;
    int res_pkey = pkey_mprotect(memory, 4096,
                                 PROT_READ | PROT_EXEC, 0);
    check_syscall_block("pkey_mprotect(PROT_EXEC)", res_pkey);

    // Cleanup
    munmap(memory, 4096);

    printf("\nTest Finished!\n");
    return 0;
}
