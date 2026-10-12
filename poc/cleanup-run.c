#include <sys/mount.h>
#include <unistd.h>
#include <stdio.h>

int main(int argc, char *argv[])
{
    if (argc < 2)
        return 1;

    if (umount2("/old_root", MNT_DETACH) == -1)
    {
        perror("umount2");
        return 1;
    }

    execv(argv[1], &argv[1]);
    perror("execv");
    return 1;
}
