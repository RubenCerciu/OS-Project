#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>

#define MAX_LINE 1024

static pid_t hub_mon_pid = -1;

static void reap_children(int sig) {
    (void)sig;
    int saved_errno = errno;
    while (waitpid(-1, NULL, WNOHANG) > 0);
    errno = saved_errno;
}

static int read_typed_message(int fd, char *type_out, char *text_out, int text_max) {
    char header[256];
    int hpos = 0;
    char c;

    while (hpos < (int)sizeof(header) - 1) {
        ssize_t n = read(fd, &c, 1);
        if (n <= 0) return -1;
        if (c == '\n') break;
        header[hpos++] = c;
    }
    header[hpos] = '\0';

    char *p1 = strchr(header, ':');
    if (!p1) return -1;
    *p1 = '\0';

    char *p2 = strchr(p1 + 1, ':');
    if (!p2) return -1;
    *p2 = '\0';

    strncpy(type_out, header, 31);
    type_out[31] = '\0';

    int textlen = atoi(p1 + 1);
    if (textlen < 0 || textlen >= text_max) return -1;

    int read_total = 0;
    while (read_total < textlen) {
        ssize_t n = read(fd, text_out + read_total, textlen - read_total);
        if (n <= 0) return -1;
        read_total += (int)n;
    }
    text_out[textlen] = '\0';

    return 0;
}

static void print_monitor_message(const char *type, const char *text) {
    if (strcmp(type, "ERROR") == 0) {
        printf("[hub_mon] monitor error: %s\n", text);
        fflush(stdout);
        printf("[hub_mon] monitor has ended\n");
        fflush(stdout);
    } else if (strcmp(type, "INFO") == 0) {
        printf("[hub_mon] %s\n", text);
        fflush(stdout);
        if (strncmp(text, "monitor stopping", 16) == 0) {
            printf("[hub_mon] monitor has ended\n");
            fflush(stdout);
        }
    } else if (strcmp(type, "EVENT") == 0) {
        printf("[hub_mon] event: %s\n", text);
        fflush(stdout);
    } else {
        printf("[hub_mon] [%s] %s\n", type, text);
        fflush(stdout);
    }
}

static void cmd_start_monitor(void) {
    if (hub_mon_pid > 0) {
        if (kill(hub_mon_pid, 0) == 0) {
            printf("monitor is already running (hub_mon pid %ld)\n", (long)hub_mon_pid);
            return;
        }
        hub_mon_pid = -1;
    }

    int relay_pipe[2];
    if (pipe(relay_pipe) < 0) {
        fprintf(stderr, "ERROR: pipe failed: %s\n", strerror(errno));
        return;
    }

    pid_t hm_pid = fork();
    if (hm_pid < 0) {
        fprintf(stderr, "ERROR: fork failed: %s\n", strerror(errno));
        close(relay_pipe[0]);
        close(relay_pipe[1]);
        return;
    }

    if (hm_pid == 0) {
        close(relay_pipe[0]);
        int relay_write = relay_pipe[1];

        int mon_pipe[2];
        if (pipe(mon_pipe) < 0) {
            const char *msg = "ERROR:32:hub_mon inner pipe failed\n";
            write(relay_write, msg, strlen(msg));
            close(relay_write);
            exit(1);
        }

        pid_t mon_pid = fork();
        if (mon_pid < 0) {
            const char *msg = "ERROR:29:hub_mon fork monitor failed\n";
            write(relay_write, msg, strlen(msg));
            close(mon_pipe[0]);
            close(mon_pipe[1]);
            close(relay_write);
            exit(1);
        }

        if (mon_pid == 0) {
            close(mon_pipe[0]);
            close(relay_write);

            char fd_str[16];
            snprintf(fd_str, sizeof(fd_str), "%d", mon_pipe[1]);

            execl("./monitor_reports", "monitor_reports", "--pipe-fd", fd_str, (char *)NULL);
            fprintf(stderr, "ERROR: exec monitor_reports failed: %s\n", strerror(errno));
            exit(1);
        }

        close(mon_pipe[1]);

        char type[32];
        char text[MAX_LINE];
        int done = 0;
        while (!done) {
            int ret = read_typed_message(mon_pipe[0], type, text, sizeof(text) - 1);
            if (ret < 0) break;

            char fwd[MAX_LINE + 64];
            int flen = snprintf(fwd, sizeof(fwd), "%s:%zu:%s\n", type, strlen(text), text);
            write(relay_write, fwd, flen);

            if (strcmp(type, "ERROR") == 0 ||
                (strcmp(type, "INFO") == 0 && strncmp(text, "monitor stopping", 16) == 0)) {
                done = 1;
            }
        }

        close(mon_pipe[0]);
        close(relay_write);

        int status;
        waitpid(mon_pid, &status, 0);
        exit(0);
    }

    close(relay_pipe[1]);
    hub_mon_pid = hm_pid;

    pid_t reader_pid = fork();
    if (reader_pid < 0) {
        fprintf(stderr, "ERROR: fork reader failed: %s\n", strerror(errno));
        close(relay_pipe[0]);
        return;
    }

    if (reader_pid == 0) {
        int rfd = relay_pipe[0];
        char type[32];
        char text[MAX_LINE];

        while (1) {
            int ret = read_typed_message(rfd, type, text, sizeof(text) - 1);
            if (ret < 0) {
                printf("[hub_mon] monitor pipe closed\n");
                fflush(stdout);
                break;
            }
            int is_terminal = (strcmp(type, "ERROR") == 0 ||
                (strcmp(type, "INFO") == 0 && strncmp(text, "monitor stopping", 16) == 0));
            print_monitor_message(type, text);
            if (is_terminal) break;
        }
        close(rfd);
        exit(0);
    }

    close(relay_pipe[0]);
    printf("monitor started (hub_mon pid %ld, reader pid %ld)\n",
           (long)hub_mon_pid, (long)reader_pid);
}

static void cmd_calculate_scores(char **districts, int num_districts) {
    if (num_districts == 0) {
        fprintf(stderr, "ERROR: calculate_scores requires at least one district\n");
        return;
    }

    int *pipefd_list = malloc(num_districts * 2 * sizeof(int));
    if (!pipefd_list) {
        fprintf(stderr, "ERROR: malloc failed\n");
        return;
    }

    pid_t *pids = malloc(num_districts * sizeof(pid_t));
    if (!pids) {
        fprintf(stderr, "ERROR: malloc failed\n");
        free(pipefd_list);
        return;
    }

    for (int i = 0; i < num_districts; i++) {
        int *pfd = &pipefd_list[i * 2];

        struct stat st;
        if (stat(districts[i], &st) != 0 || !S_ISDIR(st.st_mode)) {
            fprintf(stderr, "WARNING: district '%s' does not exist, skipping\n", districts[i]);
            pfd[0] = -1;
            pfd[1] = -1;
            pids[i] = -1;
            continue;
        }

        if (pipe(pfd) < 0) {
            fprintf(stderr, "ERROR: pipe failed for district '%s': %s\n",
                    districts[i], strerror(errno));
            pfd[0] = -1;
            pfd[1] = -1;
            pids[i] = -1;
            continue;
        }

        pid_t pid = fork();
        if (pid < 0) {
            fprintf(stderr, "ERROR: fork failed for district '%s': %s\n",
                    districts[i], strerror(errno));
            close(pfd[0]);
            close(pfd[1]);
            pfd[0] = -1;
            pfd[1] = -1;
            pids[i] = -1;
            continue;
        }

        if (pid == 0) {
            close(pfd[0]);
            if (dup2(pfd[1], STDOUT_FILENO) < 0) {
                fprintf(stderr, "ERROR: dup2 failed: %s\n", strerror(errno));
                exit(1);
            }
            close(pfd[1]);

            execl("./scorer", "scorer", districts[i], (char *)NULL);
            fprintf(stderr, "ERROR: exec scorer failed: %s\n", strerror(errno));
            exit(1);
        }

        close(pfd[1]);
        pfd[1] = -1;
        pids[i] = pid;
    }

    printf("\n=== Combined Workload Report ===\n\n");

    for (int i = 0; i < num_districts; i++) {
        int *pfd = &pipefd_list[i * 2];
        if (pfd[0] < 0) continue;

        char buf[4096];
        ssize_t n;
        while ((n = read(pfd[0], buf, sizeof(buf) - 1)) > 0) {
            buf[n] = '\0';
            printf("%s", buf);
        }
        close(pfd[0]);

        if (pids[i] > 0) {
            int status;
            waitpid(pids[i], &status, 0);
        }
    }

    printf("\n=== End of Workload Report ===\n");

    free(pipefd_list);
    free(pids);
}

static void print_usage(void) {
    printf("city_hub commands:\n");
    printf("  start_monitor\n");
    printf("  calculate_scores <district1> [district2] ...\n");
    printf("  exit\n");
}

int main(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = reap_children;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    sigaction(SIGCHLD, &sa, NULL);

    char line[MAX_LINE];

    printf("city_hub ready. Type 'help' for commands.\n");

    while (1) {
        printf("hub> ");
        fflush(stdout);

        if (!fgets(line, sizeof(line), stdin)) {
            printf("\n");
            break;
        }

        size_t len = strlen(line);
        if (len > 0 && line[len - 1] == '\n') line[--len] = '\0';
        if (len == 0) continue;

        char *tokens[64];
        int ntok = 0;
        char *p = line;
        char *tok;
        while (ntok < 63 && (tok = strtok(p, " \t")) != NULL) {
            tokens[ntok++] = tok;
            p = NULL;
        }
        if (ntok == 0) continue;

        if (strcmp(tokens[0], "start_monitor") == 0) {
            cmd_start_monitor();
        } else if (strcmp(tokens[0], "calculate_scores") == 0) {
            cmd_calculate_scores(&tokens[1], ntok - 1);
        } else if (strcmp(tokens[0], "exit") == 0 || strcmp(tokens[0], "quit") == 0) {
            printf("Exiting city_hub.\n");
            break;
        } else if (strcmp(tokens[0], "help") == 0) {
            print_usage();
        } else {
            fprintf(stderr, "ERROR: unknown command '%s'\n", tokens[0]);
            print_usage();
        }
    }

    return 0;
}
