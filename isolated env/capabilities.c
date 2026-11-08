#include <stdio.h>
#include <stdlib.h>
#include <sys/capability.h>
#include <sys/prctl.h>
#include <linux/capability.h>
#include <unistd.h>
#include <errno.h>

int main() {
    cap_t cap = cap_get_proc();
    if (cap == NULL) {
        perror("cap_get_proc");
        return 1;
    }

    cap_flag_value_t value;
    if (cap_get_flag(cap, CAP_NET_BIND_SERVICE, CAP_PERMITTED, &value) != 0) {
        perror("cap_get_flag CAP_PERMITTED");
        cap_free(cap);
        return 1;
    }
    if (value != CAP_SET) {
        fprintf(stderr, "CAP_NET_BIND_SERVICE not in permitted set\n");
        cap_free(cap);
        return 1;
    }

    if (cap_get_flag(cap, CAP_NET_BIND_SERVICE, CAP_INHERITABLE, &value) != 0) {
        perror("cap_get_flag CAP_INHERITABLE");
        cap_free(cap);
        return 1;
    }
    if (value != CAP_SET) {
        fprintf(stderr, "CAP_NET_BIND_SERVICE not in inheritable set\n");
        cap_free(cap);
        return 1;
    }

    if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, CAP_NET_BIND_SERVICE, 0, 0) != 0) {
        perror("prctl(PR_CAP_AMBIENT_RAISE)");
        cap_free(cap);
        return 1;
    }

    cap_free(cap);

    printf("CAP_NET_BIND_SERVICE added to ambient set\n");

    // Execute a program that binds to a privileged port
    execl("/path/to/your/program", "/path/to/your/program", NULL);
    perror("execl"); // If execl fails
    return 1;
}