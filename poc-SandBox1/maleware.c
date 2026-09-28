#include <stdio.h>
#include <sys/ioctl.h>
#include <errno.h>

int main()
{
    printf("maleware is trying to execute ioctl...");

    //try using ioctl and access hardware.
    int res = ioctl(0, 0, 0);

    if(res == -1 && errno == EPERM)
    {
        printf("Seccomp succedded! malware was stopped.");
    }
    else
    {
        printf("Seccomp failed! malware accessed hardware.");
    }

    return 0;
}