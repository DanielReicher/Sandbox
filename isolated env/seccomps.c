#include <seccomp.h>
#include <errno.h>
#include <stdio.h>
//allows profram to communicate with OS and effect process managment.
#include <unistd.h>



int handle_seccomp()
{
    int succeded = 1;
    //allowing all syscalls as the deafault.
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);

    if (ctx == NULL) //for debug
    {
        fprintf(stderr, "Failed to initialize seccomp (hardware func)\n");
        return -1;
    }

    //block different types of syscalls + check if there was an error..

    if(block_hardware_syscalls(ctx) == -1)
        return -1;

    if(block_hardware_syscalls(ctx) == -1)
        return -1;
    
    if(block_hardware_syscalls(ctx) == -1)
        return -1;
    
    //release seccomps.
    seccomp_release(ctx);
    return 0;

}
/*
function blocks all hardware-access syscalls with seccomp.
*/
int block_hardware_syscalls(scmp_filter_ctx ctx)
{
    
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
   return 0;
}

/*
function blocks all root-access syscalls with seccomp.
*/
int block_root_access_syscalls(scmp_filter_ctx ctx)
{
    //restrict setgid.
    if(seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(setgid), 0) < 0)
    {
        fprintf(stderr, "Failed to block setgid\n");
        seccomp_release(ctx);
        return -1;
    }
    //block setuid.
    if (seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(setuid), 0) < 0)
    {
        fprintf(stderr, "Failed to block setuid\n");
        seccomp_release(ctx);
        return -1;
    }
    
    //block capset - change the process capabilities.
    if (seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(capset), 0) < 0)
    {
        fprintf(stderr, "Failed to block capset\n");
        seccomp_release(ctx);
        return -1;
    }


    //block finit_module and init_module - load modules to kernel.
    if (seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(finit_module), 0) < 0)
    {
        fprintf(stderr, "Failed to block finit_module\n");
        seccomp_release(ctx);
        return -1;
    }

    //block init_module.
    if (seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(init_module), 0) < 0)
    {
        fprintf(stderr, "Failed to block init_module\n");
        seccomp_release(ctx);
        return -1;
    }

    //block delete_module - deletes a module from kernel.
    if (seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(delete_module), 0) < 0)
    {
        fprintf(stderr, "Failed to block delete_module\n");
        seccomp_release(ctx);
        return -1;
    }

    // Block ptrace - detect after processes.
    if (seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(ptrace), 0) < 0)
    {
        fprintf(stderr, "Failed to block ptrace\n");
        seccomp_release(ctx);
        return -1;
    }

    //block mount - add/delete file trees from system.
    if (seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(mount), 0) < 0)
    {
        fprintf(stderr, "Failed to block mount\n");
        seccomp_release(ctx);
        return -1;
    }

    //block chroot - changes root.
    if (seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(chroot), 0) < 0)
    {
        fprintf(stderr, "Failed to block chroot\n");
        seccomp_release(ctx);
        return -1;
    }

    // Block reboot - poweroff/restart device - used for Dos.
    if (seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(reboot), 0) < 0)
    {
        fprintf(stderr, "Failed to block reboot\n");
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