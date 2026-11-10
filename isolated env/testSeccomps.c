#include <stdio.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <signal.h>

//report what a syscall failed.
#include <errno.h>

void check_syscall_block(const char* name, int result) 
{
    //check if succeeded or not.
    if (result == -1 && errno == EPERM)
        printf("%s blocked successfully (EPERM).\n", name);
    else
        printf("ERROR! %s not blocked! (errno: %d)\n", name, errno);
}

int main() 
{
    printf("starting Seccomp Test...\n");

    //hardware access test - ioctl (use stdout).
    int res_ioctl = ioctl(STDOUT_FILENO, TIOCGWINSZ, NULL);
    check_syscall_block("ioctl", res_ioctl);

    //root access test - setuid (try change a users's id).
    int res_setuid = setuid(1000);
    check_syscall_block("setuid", res_setuid);

    //process intervention test - kill(sends signal 0 to our process, check if exists and supoused to work out).
    int res_kill = kill(getpid(), 0);
    check_syscall_block("kill", res_kill);

    printf("\nTest Finished!\n");
    return 0;
}