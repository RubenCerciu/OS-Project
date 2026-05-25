#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>

static volatile int running = 1;
static int out_fd = -1;

static void write_msg(const char *type, const char *text) {
    char buf[512];
    int len = snprintf(buf, sizeof(buf), "%s:%zu:%s\n", type, strlen(text), text);
    int fd = (out_fd >= 0) ? out_fd : STDOUT_FILENO;
    write(fd, buf, len);
}

static void handle_sigusr1(int sig) {
    (void)sig;
    write_msg("EVENT", "new report added");
}

static void handle_sigint(int sig) {
    (void)sig;
    running = 0;
}

int main(int argc, char *argv[]) {
    int pipe_write_fd = -1;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--pipe-fd") == 0 && i + 1 < argc) {
            pipe_write_fd = atoi(argv[++i]);
        }
    }

    if (pipe_write_fd >= 0) {
        out_fd = pipe_write_fd;
    }

    int pidfd = open(".monitor_pid", O_RDONLY);
    if (pidfd >= 0) {
        char buf[32];
        memset(buf, 0, sizeof(buf));
        ssize_t n = read(pidfd, buf, sizeof(buf) - 1);
        close(pidfd);
        if (n > 0) {
            char *endp;
            long existing_pid = strtol(buf, &endp, 10);
            if (existing_pid > 0 && kill((pid_t)existing_pid, 0) == 0) {
                char errmsg[128];
                snprintf(errmsg, sizeof(errmsg),
                    "monitor already running with pid %ld", existing_pid);
                write_msg("ERROR", errmsg);
                if (out_fd >= 0) close(out_fd);
                return 1;
            }
        }
    }

    int fd = open(".monitor_pid", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        write_msg("ERROR", "cannot create .monitor_pid");
        if (out_fd >= 0) close(out_fd);
        return 1;
    }

    char pidbuf[32];
    int plen = snprintf(pidbuf, sizeof(pidbuf), "%ld\n", (long)getpid());
    write(fd, pidbuf, plen);
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

    char startmsg[64];
    snprintf(startmsg, sizeof(startmsg), "monitor started with pid %ld", (long)getpid());
    write_msg("INFO", startmsg);

    while (running) {
        pause();
    }

    write_msg("INFO", "monitor stopping");
    unlink(".monitor_pid");
    if (out_fd >= 0) close(out_fd);
    return 0;
}
