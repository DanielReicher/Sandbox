#include <seccomp.h>
#include <errno.h>
#include <stdio.h>
//allows profram to communicate with OS and effect process managment.
#include <unistd.h>

//function handles seccomp tech.
void block_syscalls()
{
    //allowing all syscalls as the deafault.
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);
    
    //restrict ioctl - send dirct requests to the hardware syscall.
    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(ioctl), 0);

    //load rules to the kernel.
    seccomp_load(ctx);
    seccomp_release(ctx);
}

int main(int argc, char *argv[])
{
    if(argc < 2)
    {
        printf("Usage: %s \n", argv[0]);
        return 1;
    }

    //call function and block dengerous syscalls.
    block_syscalls();

    //call the isolated process with the new syscalls limitation.
    execvp(argv[1], &argv[1]);

    return 0;
}