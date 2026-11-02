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

int main() {
    printf("--- Starting Seccomp Test ---\n");

    // 1. Hardware access test: ioctl
    // שימוש בקריאה לא מזיקה ל-stdout כדי לבדוק חסימה
    int res_ioctl = ioctl(STDOUT_FILENO, TIOCGWINSZ, NULL);
    check_syscall_block("ioctl", res_ioctl);

    // 2. Root access test: setuid
    // ניסיון לשנות מזהה משתמש
    int res_setuid = setuid(1000);
    check_syscall_block("setuid", res_setuid);

    // 3. Process intervention test: kill
    // שליחת סיגנל 0 לתהליך של עצמנו (בדרך כלל בודק אם התהליך קיים ומצליח תמיד)
    int res_kill = kill(getpid(), 0);
    check_syscall_block("kill", res_kill);

    printf("--- Test Finished ---\n");
    return 0;
}