
#include <seccomp.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/mman.h>

// Function declarations
int handle_seccomp(void);
int block_hardware_syscalls(scmp_filter_ctx ctx);
int block_root_access_syscalls(scmp_filter_ctx ctx);
int block_interventio_in_processes_syscalls(scmp_filter_ctx ctx);
int block_memory_syscalls(scmp_filter_ctx ctx);


int handle_seccomp(void)
{
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);

    if (ctx == NULL)
    {
        fprintf(stderr, "Failed to initialize seccomp\n");
        return -1;
    }

    if (block_hardware_syscalls(ctx) == -1)
        goto error;

    if (block_root_access_syscalls(ctx) == -1)
        goto error;

    if (block_interventio_in_processes_syscalls(ctx) == -1)
        goto error;

    if (block_memory_syscalls(ctx) == -1)
        goto error;

    // Load all rules into the kernel once.
    if (seccomp_load(ctx) < 0)
    {
        fprintf(stderr, "Failed to load seccomp filter\n");
        goto error;
    }

    seccomp_release(ctx);
    return 0;

error:
    seccomp_release(ctx);
    return -1;
}


/*
Blocks hardware-access syscalls.
*/
int block_hardware_syscalls(scmp_filter_ctx ctx)
{
    // Block ioctl.
    if (seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM),
        SCMP_SYS(ioctl), 0) < 0)
    {
        fprintf(stderr, "Failed to block ioctl\n");
        return -1;
    }

    // Block ioperm.
    if (seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM),
        SCMP_SYS(ioperm), 0) < 0)
    {
        fprintf(stderr, "Failed to block ioperm\n");
        return -1;
    }

    // Block iopl.
    if (seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM),
        SCMP_SYS(iopl), 0) < 0)
    {
        fprintf(stderr, "Failed to block iopl\n");
        return -1;
    }

    return 0;
}


/*
Blocks root-access and privileged syscalls.
*/
int block_root_access_syscalls(scmp_filter_ctx ctx)
{
    // Block setgid.
    if (seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM),
        SCMP_SYS(setgid), 0) < 0)
    {
        fprintf(stderr, "Failed to block setgid\n");
        return -1;
    }

    // Block setuid.
    if (seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM),
        SCMP_SYS(setuid), 0) < 0)
    {
        fprintf(stderr, "Failed to block setuid\n");
        return -1;
    }

    // Block capset.
    if (seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM),
        SCMP_SYS(capset), 0) < 0)
    {
        fprintf(stderr, "Failed to block capset\n");
        return -1;
    }

    // Block finit_module.
    if (seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM),
        SCMP_SYS(finit_module), 0) < 0)
    {
        fprintf(stderr, "Failed to block finit_module\n");
        return -1;
    }

    // Block init_module.
    if (seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM),
        SCMP_SYS(init_module), 0) < 0)
    {
        fprintf(stderr, "Failed to block init_module\n");
        return -1;
    }

    // Block delete_module.
    if (seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM),
        SCMP_SYS(delete_module), 0) < 0)
    {
        fprintf(stderr, "Failed to block delete_module\n");
        return -1;
    }

    // Block mount.
    if (seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM),
        SCMP_SYS(mount), 0) < 0)
    {
        fprintf(stderr, "Failed to block mount\n");
        return -1;
    }

    // Block chroot.
    if (seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM),
        SCMP_SYS(chroot), 0) < 0)
    {
        fprintf(stderr, "Failed to block chroot\n");
        return -1;
    }

    // Block reboot.
    if (seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM),
        SCMP_SYS(reboot), 0) < 0)
    {
        fprintf(stderr, "Failed to block reboot\n");
        return -1;
    }

    return 0;
}


/*
Blocks interference with other processes.
*/
int block_interventio_in_processes_syscalls(scmp_filter_ctx ctx)
{
    // Block ptrace.
    if (seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM),
        SCMP_SYS(ptrace), 0) < 0)
    {
        fprintf(stderr, "Failed to block ptrace\n");
        return -1;
    }

    // Block process_vm_writev.
    if (seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM),
        SCMP_SYS(process_vm_writev), 0) < 0)
    {
        fprintf(stderr, "Failed to block process_vm_writev\n");
        return -1;
    }

    // Block process_vm_readv.
    if (seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM),
        SCMP_SYS(process_vm_readv), 0) < 0)
    {
        fprintf(stderr, "Failed to block process_vm_readv\n");
        return -1;
    }

    // Block setns.
    if (seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM),
        SCMP_SYS(setns), 0) < 0)
    {
        fprintf(stderr, "Failed to block setns\n");
        return -1;
    }

    // Block unshare.
    if (seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM),
        SCMP_SYS(unshare), 0) < 0)
    {
        fprintf(stderr, "Failed to block unshare\n");
        return -1;
    }

    // Block kill.
    if (seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM),
        SCMP_SYS(kill), 0) < 0)
    {
        fprintf(stderr, "Failed to block kill\n");
        return -1;
    }

    return 0;
}


/*
Blocks memory operations that request executable permissions.
*/
int block_memory_syscalls(scmp_filter_ctx ctx)
{
    // Block mprotect when PROT_EXEC is requested.
    if (seccomp_rule_add(ctx,
        SCMP_ACT_ERRNO(EPERM),
        SCMP_SYS(mprotect),
        1,
        SCMP_CMP(2, SCMP_CMP_MASKED_EQ, PROT_EXEC, PROT_EXEC)) < 0)
    {
        fprintf(stderr, "Failed to block executable mprotect\n");
        return -1;
    }

    // Block pkey_mprotect when PROT_EXEC is requested.
    if (seccomp_rule_add(ctx,
        SCMP_ACT_ERRNO(EPERM),
        SCMP_SYS(pkey_mprotect),
        1,
        SCMP_CMP(2, SCMP_CMP_MASKED_EQ, PROT_EXEC, PROT_EXEC)) < 0)
    {
        fprintf(stderr, "Failed to block executable pkey_mprotect\n");
        return -1;
    }

    // Block mmap when PROT_EXEC is requested.
    if (seccomp_rule_add(ctx,
        SCMP_ACT_ERRNO(EPERM),
        SCMP_SYS(mmap),
        1,
        SCMP_CMP(2, SCMP_CMP_MASKED_EQ, PROT_EXEC, PROT_EXEC)) < 0)
    {
        fprintf(stderr, "Failed to block executable mmap\n");
        return -1;
    }

    return 0;
}


int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        printf("Usage: %s <program> [arguments]\n", argv[0]);
        return 1;
    }

    // Apply Seccomp restrictions.
    if (handle_seccomp() == -1)
    {
        fprintf(stderr, "Failed to apply seccomp restrictions\n");
        return 1;
    }

    // Execute the isolated process.
    execvp(argv[1], &argv[1]);

    perror("execvp");
    return 1;
}
