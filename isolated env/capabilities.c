#include <stdio.h>
#include <stdlib.h>
#include <sys/capability.h>
#include <sys/prctl.h>
#include <linux/capability.h>
#include <unistd.h>
#include <errno.h>

//remove a capability from effective, permitted and inheritable sets.
int drop_capability(cap_t cap, cap_value_t capability, const char *name)
{
    cap_flag_value_t value;

    cap_flag_t flags[] = {
        CAP_EFFECTIVE,  // Capabilities that are currently active and can be used by the process
        CAP_PERMITTED,   // Capabilities that the process is allowed to enable
        CAP_INHERITABLE // Capabilities that can be inherited across exec under the appropriate conditions
    };

    for (int i = 0; i < 3; i++)
    {
        if (cap_set_flag(cap, flags[i], 1, &capability, CAP_CLEAR) == -1)
        {
            perror("cap_set_flag");
            return -1;
        }
    }

    if (cap_set_proc(cap) == -1)
    {
        perror("cap_set_proc");
        return -1;
    }

    //verify that the capability was removed.
    for (int i = 0; i < 3; i++)
    {
        if (cap_get_flag(cap, capability, flags[i], &value) == -1)
        {
            perror("cap_get_flag");
            return -1;
        }

        if (value == CAP_SET)
        {
            fprintf(stderr, "%s was not removed successfully\n", name);
            return -1;
        }
    }

    printf("%s removed successfully\n", name);
    return 0;
}


int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        fprintf(stderr, "Usage: %s <program> [arguments...]\n", argv[0]);
        return 1;
    }

    cap_t cap = cap_get_proc();

    if (cap == NULL)
    {
        perror("cap_get_proc");
        return 1;
    }

    //remove dangerous capabilities.
    if (drop_capability(cap, CAP_SYS_ADMIN, "CAP_SYS_ADMIN") == -1)
        goto error;

    if (drop_capability(cap, CAP_SYS_PTRACE, "CAP_SYS_PTRACE") == -1)
        goto error;

    if (drop_capability(cap, CAP_NET_RAW, "CAP_NET_RAW") == -1)
        goto error;

    if (drop_capability(cap, CAP_SYS_ADMIN, "CAP_DAC_OVERRIDE") == -1)
        goto error;

    if (drop_capability(cap, CAP_SYS_PTRACE, "CAP_SYS_PTRACE") == -1)
        goto error;

    if (drop_capability(cap, CAP_NET_RAW, "CAP_NET_RAW") == -1)
        goto error;

    cap_free(cap);

    //execute the program supplied as an argument.
    execvp(argv[1], &argv[1]);

    perror("execvp");
    return 1;

error:
    cap_free(cap);
    return 1;
}
