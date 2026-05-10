#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>

static volatile int running = 1;

static void handle_sigusr1(int sig) {
    (void)sig;
    const char *msg = "monitor: new report added\n";
    write(STDOUT_FILENO, msg, strlen(msg));
}

static void handle_sigint(int sig) {
    (void)sig;
    running = 0;
}

int main(void) {
    int fd = open(".monitor_pid", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        perror("ERROR: cannot create .monitor_pid");
        return 1;
    }

    char buf[32];
    int len = snprintf(buf, sizeof(buf), "%ld\n", (long)getpid());
    write(fd, buf, len);
    close(fd);

    struct sigaction sa_usr1;
    memset(&sa_usr1, 0, sizeof(sa_usr1));
    sa_usr1.sa_handler = handle_sigusr1;
    sigemptyset(&sa_usr1.sa_mask);
    sa_usr1.sa_flags = SA_RESTART;
    sigaction(SIGUSR1, &sa_usr1, NULL);

    struct sigaction sa_int;
    memset(&sa_int, 0, sizeof(sa_int));
    sa_int.sa_handler = handle_sigint;
    sigemptyset(&sa_int.sa_mask);
    sa_int.sa_flags = 0;
    sigaction(SIGINT, &sa_int, NULL);

    printf("monitor started (pid %ld)\n", (long)getpid());
    fflush(stdout);

    while (running) {
        pause();
    }

    printf("monitor stopping\n");
    unlink(".monitor_pid");
    return 0;
}
