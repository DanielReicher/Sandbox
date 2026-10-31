#include <seccomp.h>
#include <errno.h>
#include <stdio.h>
//allows profram to communicate with OS and effect process managment.
#include <unistd.h>

//function handles seccomp tech.
int block_syscalls()
{
    //allowing all syscalls as the deafault.
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);

    if (ctx == NULL) //for debug
    {
        fprintf(stderr, "Failed to initialize seccomp\n");
        return -1;
    }
    //restrict ioctl - send dirct requests to the hardware syscall.
    if(seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(ioctl), 0) < 0)
    {
        fprintf(stderr, "Failed to block ioctl\n");
        seccomp_release(ctx);
        return -1;
    }
    // Block ioperm.
    if (seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(ioperm), 0) < 0)
    {
        fprintf(stderr, "Failed to block ioperm\n");
        seccomp_release(ctx);
        return -1;
    }

    // Block iopl.
    if (seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(iopl), 0) < 0)
    {
        fprintf(stderr, "Failed to block iopl\n");
        seccomp_release(ctx);
        return -1;
    }

    //load rules to the kernel.
    if(seccomp_load(ctx) < 0)
    {
        fprintf(stderr, "Failed to load seccomp filter\n");
        seccomp_release(ctx);
        return -1;
    }
    seccomp_release(ctx);
    return 0;
}

int main(int argc, char *argv[])
{
    if(argc < 2)
    {
        printf("Usage: %s \n", argv[0]);
        return 1;
    }

    //call function and block dengerous syscalls.
    if(block_syscalls()<0)
    {
        return 1;
    }

    //call the isolated process with the new syscalls limitation.
    execvp(argv[1], &argv[1]);
    
    perror("execvp");
    return 1;

}