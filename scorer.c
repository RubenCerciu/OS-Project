#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

#define NAME_LEN     64
#define CATEGORY_LEN 32
#define DESC_LEN     256

typedef struct {
    int    id;
    char   inspector[NAME_LEN];
    double latitude;
    double longitude;
    char   category[CATEGORY_LEN];
    int    severity;
    long   timestamp;
    char   description[DESC_LEN];
} Report;

#define MAX_INSPECTORS 256

typedef struct {
    char name[NAME_LEN];
    int  score;
    int  count;
} InspectorScore;

int main(int argc, char *argv[]) {
    if (argc < 2) {
        write(STDOUT_FILENO, "ERROR: scorer requires district name\n", 37);
        return 1;
    }

    const char *district = argv[1];

    char path[512];
    snprintf(path, sizeof(path), "%s/reports.dat", district);

    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        char msg[512];
        int len = snprintf(msg, sizeof(msg),
            "ERROR: cannot open %s/reports.dat\n", district);
        write(STDOUT_FILENO, msg, len);
        return 1;
    }

    InspectorScore scores[MAX_INSPECTORS];
    int num_inspectors = 0;

    Report r;
    while (read(fd, &r, sizeof(r)) == (ssize_t)sizeof(r)) {
        int found = 0;
        for (int i = 0; i < num_inspectors; i++) {
            if (strcmp(scores[i].name, r.inspector) == 0) {
                scores[i].score += r.severity;
                scores[i].count++;
                found = 1;
                break;
            }
        }
        if (!found && num_inspectors < MAX_INSPECTORS) {
            strncpy(scores[num_inspectors].name, r.inspector, NAME_LEN - 1);
            scores[num_inspectors].name[NAME_LEN - 1] = '\0';
            scores[num_inspectors].score = r.severity;
            scores[num_inspectors].count = 1;
            num_inspectors++;
        }
    }
    close(fd);

    char header[256];
    int hlen = snprintf(header, sizeof(header),
        "=== Workload scores for district '%s' ===\n", district);
    write(STDOUT_FILENO, header, hlen);

    if (num_inspectors == 0) {
        const char *msg = "  (no reports found)\n";
        write(STDOUT_FILENO, msg, strlen(msg));
    } else {
        for (int i = 0; i < num_inspectors; i++) {
            char line[256];
            int llen = snprintf(line, sizeof(line),
                "  Inspector: %-20s | Reports: %3d | Workload score: %d\n",
                scores[i].name, scores[i].count, scores[i].score);
            write(STDOUT_FILENO, line, llen);
        }
    }

    return 0;
}
