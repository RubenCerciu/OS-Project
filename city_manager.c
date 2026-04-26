#define _POSIX_C_SOURCE 200809L
#define _XOPEN_SOURCE   700
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <errno.h>
#include <dirent.h>

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
    time_t timestamp;
    char   description[DESC_LEN];
} Report;

void mode_to_str(mode_t mode, char *out) {
    out[0] = (mode & S_IRUSR) ? 'r' : '-';
    out[1] = (mode & S_IWUSR) ? 'w' : '-';
    out[2] = (mode & S_IXUSR) ? 'x' : '-';
    out[3] = (mode & S_IRGRP) ? 'r' : '-';
    out[4] = (mode & S_IWGRP) ? 'w' : '-';
    out[5] = (mode & S_IXGRP) ? 'x' : '-';
    out[6] = (mode & S_IROTH) ? 'r' : '-';
    out[7] = (mode & S_IWOTH) ? 'w' : '-';
    out[8] = (mode & S_IXOTH) ? 'x' : '-';
    out[9] = '\0';
}

int check_perms(const char *path, mode_t expected) {
    struct stat st;
    if (stat(path, &st) < 0) {
        fprintf(stderr, "ERROR: cannot stat '%s': %s\n", path, strerror(errno));
        return 0;
    }
    mode_t actual = st.st_mode & 0777;
    if (actual != (expected & 0777)) {
        char a[10], e[10];
        mode_to_str(actual, a);
        mode_to_str(expected, e);
        fprintf(stderr, "ERROR: permission mismatch on '%s': expected %s, found %s\n",
                path, e, a);
        return 0;
    }
    return 1;
}

int role_may(const char *role, const char *action, const char *file) {
    int is_mgr = (strcmp(role, "manager") == 0);

    if (strcmp(file, "reports.dat") == 0)
        return 1;

    if (strcmp(file, "district.cfg") == 0) {
        if (strcmp(action, "write") == 0) return is_mgr;
        return 1;
    }

    if (strcmp(file, "logged_district") == 0) {
        if (strcmp(action, "write") == 0) return is_mgr;
        return 1;
    }

    if (strcmp(file, "district_dir") == 0) {
        if (strcmp(action, "write") == 0) return is_mgr;
        return 1;
    }

    return 1;
}

void log_action(const char *district, const char *role,
                const char *user, const char *action) {
    char path[512];
    snprintf(path, sizeof(path), "%s/logged_district", district);

    int fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd < 0) return;
    chmod(path, 0644);

    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    char timebuf[64];
    strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", t);

    char line[512];
    int len = snprintf(line, sizeof(line), "%ld\t%s\t%s\t%s\t%s\n",
                       (long)now, timebuf, user, role, action);
    write(fd, line, len);
    close(fd);
}

void ensure_district(const char *district) {
    struct stat st;

    if (stat(district, &st) != 0) {
        if (mkdir(district) < 0) {
            fprintf(stderr, "ERROR: cannot create district '%s': %s\n",
                    district, strerror(errno));
            exit(1);
        }
        chmod(district, 0750);
    }

    char cfg[512];
    snprintf(cfg, sizeof(cfg), "%s/district.cfg", district);
    if (stat(cfg, &st) != 0) {
        int fd = open(cfg, O_WRONLY | O_CREAT | O_TRUNC, 0640);
        if (fd >= 0) {
            const char *def = "severity_threshold=1\n";
            write(fd, def, strlen(def));
            close(fd);
        }
        chmod(cfg, 0640);
    }

    char logf[512];
    snprintf(logf, sizeof(logf), "%s/logged_district", district);
    if (stat(logf, &st) != 0) {
        int fd = open(logf, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd >= 0) close(fd);
        chmod(logf, 0644);
    }

    char rpt[512];
    snprintf(rpt, sizeof(rpt), "%s/reports.dat", district);
    if (stat(rpt, &st) != 0) {
        int fd = open(rpt, O_WRONLY | O_CREAT | O_TRUNC, 0664);
        if (fd >= 0) close(fd);
        chmod(rpt, 0664);
    }

    char linkname[512], target[512];
    snprintf(linkname, sizeof(linkname), "active_reports-%s", district);
    snprintf(target, sizeof(target), "%s/reports.dat", district);

    struct stat lst;
    if (lstat(linkname, &lst) != 0) {
        if (symlink(target, linkname) < 0) {
            fprintf(stderr, "WARNING: could not create symlink '%s': %s\n",
                    linkname, strerror(errno));
        }
    } else if (!S_ISLNK(lst.st_mode)) {
        fprintf(stderr, "WARNING: '%s' exists but is not a symlink\n", linkname);
    }
}

int next_report_id(const char *district) {
    char path[512];
    snprintf(path, sizeof(path), "%s/reports.dat", district);
    struct stat st;
    if (stat(path, &st) < 0) return 1;
    return (int)(st.st_size / sizeof(Report)) + 1;
}

int parse_condition(const char *input, char *field, char *op, char *value) {
    if (!input || !field || !op || !value) return 0;

    const char *p1 = strchr(input, ':');
    if (!p1) return 0;

    const char *p2 = strchr(p1 + 1, ':');
    if (!p2) return 0;

    size_t flen = (size_t)(p1 - input);
    if (flen == 0 || flen >= 32) return 0;
    strncpy(field, input, flen);
    field[flen] = '\0';

    size_t olen = (size_t)(p2 - p1 - 1);
    if (olen == 0 || olen >= 4) return 0;
    strncpy(op, p1 + 1, olen);
    op[olen] = '\0';

    const char *valid_ops[] = {"==", "!=", "<", "<=", ">", ">="};
    int valid = 0;
    for (int i = 0; i < 6; i++) {
        if (strcmp(op, valid_ops[i]) == 0) { valid = 1; break; }
    }
    if (!valid) return 0;

    const char *vstart = p2 + 1;
    size_t vlen = strlen(vstart);
    if (vlen == 0 || vlen >= 128) return 0;
    strncpy(value, vstart, vlen);
    value[vlen] = '\0';

    return 1;
}

int match_condition(Report *r, const char *field, const char *op, const char *value) {
    if (!r || !field || !op || !value) return 0;

#define STR_CMP(a, b, oper) \
    (strcmp((oper), "==") == 0 ? strcmp((a), (b)) == 0 : \
     strcmp((oper), "!=") == 0 ? strcmp((a), (b)) != 0 : 0)

#define INT_CMP(a, b, oper) \
    (strcmp((oper), "==") == 0 ? (a) == (b) : \
     strcmp((oper), "!=") == 0 ? (a) != (b) : \
     strcmp((oper), "<")  == 0 ? (a) <  (b) : \
     strcmp((oper), "<=") == 0 ? (a) <= (b) : \
     strcmp((oper), ">")  == 0 ? (a) >  (b) : \
     strcmp((oper), ">=") == 0 ? (a) >= (b) : 0)

    if (strcmp(field, "severity") == 0) {
        char *endp;
        long v = strtol(value, &endp, 10);
        if (*endp != '\0') return 0;
        return INT_CMP(r->severity, (int)v, op);
    }

    if (strcmp(field, "category") == 0)
        return STR_CMP(r->category, value, op);

    if (strcmp(field, "inspector") == 0)
        return STR_CMP(r->inspector, value, op);

    if (strcmp(field, "timestamp") == 0) {
        char *endp;
        long long v = strtoll(value, &endp, 10);
        if (*endp != '\0') return 0;
        return INT_CMP((long long)r->timestamp, v, op);
    }

#undef STR_CMP
#undef INT_CMP

    fprintf(stderr, "WARNING: unknown filter field '%s'\n", field);
    return 0;
}

void cmd_add(const char *district, const char *role, const char *user) {
    ensure_district(district);

    if (!role_may(role, "write", "reports.dat")) {
        fprintf(stderr, "ERROR: role '%s' cannot write reports.dat\n", role);
        return;
    }

    char path[512];
    snprintf(path, sizeof(path), "%s/reports.dat", district);

    if (!check_perms(path, 0664)) {
        fprintf(stderr, "ERROR: aborting add due to permission mismatch on reports.dat\n");
        return;
    }

    Report r;
    memset(&r, 0, sizeof(r));
    r.id = next_report_id(district);
    strncpy(r.inspector, user, NAME_LEN - 1);
    r.timestamp = time(NULL);

    printf("X: ");
    if (scanf("%lf", &r.latitude) != 1) { fprintf(stderr, "ERROR: bad latitude\n"); return; }
    printf("Y: ");
    if (scanf("%lf", &r.longitude) != 1) { fprintf(stderr, "ERROR: bad longitude\n"); return; }

    char cat_input[64];
    printf("Category (road/lighting/flooding/other): ");
    if (scanf("%63s", cat_input) != 1) { fprintf(stderr, "ERROR: bad category\n"); return; }
    strncpy(r.category, cat_input, CATEGORY_LEN - 1);

    printf("Severity level (1/2/3): ");
    if (scanf("%d", &r.severity) != 1 || r.severity < 1 || r.severity > 3) {
        fprintf(stderr, "ERROR: severity must be 1, 2, or 3\n");
        return;
    }

    { int c; while ((c = getchar()) != '\n' && c != EOF); }

    printf("Description: ");
    if (!fgets(r.description, DESC_LEN, stdin)) {
        fprintf(stderr, "ERROR: bad description\n");
        return;
    }
    size_t dl = strlen(r.description);
    if (dl > 0 && r.description[dl - 1] == '\n') r.description[dl - 1] = '\0';

    int fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0664);
    if (fd < 0) {
        fprintf(stderr, "ERROR: cannot open '%s': %s\n", path, strerror(errno));
        return;
    }
    chmod(path, 0664);

    ssize_t written = write(fd, &r, sizeof(r));
    close(fd);

    if (written != (ssize_t)sizeof(r)) {
        fprintf(stderr, "ERROR: incomplete write to '%s'\n", path);
        return;
    }

    printf("Report #%d added to district '%s'\n", r.id, district);
    log_action(district, role, user, "add");
}

void cmd_list(const char *district, const char *role, const char *user) {
    if (!role_may(role, "read", "reports.dat")) {
        fprintf(stderr, "ERROR: role '%s' cannot read reports.dat\n", role);
        return;
    }

    char path[512];
    snprintf(path, sizeof(path), "%s/reports.dat", district);

    struct stat st;
    if (stat(path, &st) < 0) {
        fprintf(stderr, "ERROR: district '%s' not found or reports.dat missing\n", district);
        return;
    }

    char perm_str[10];
    mode_to_str(st.st_mode & 0777, perm_str);

    char timebuf[64];
    struct tm *tm_info = localtime(&st.st_mtime);
    strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", tm_info);

    printf("File: %s | Permissions: %s | Size: %lld bytes | Last modified: %s\n",
           path, perm_str, (long long)st.st_size, timebuf);

    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "ERROR: cannot open '%s': %s\n", path, strerror(errno));
        return;
    }

    Report r;
    int count = 0;
    while (read(fd, &r, sizeof(r)) == (ssize_t)sizeof(r)) {
        char ts[64];
        struct tm *t = localtime(&r.timestamp);
        strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", t);
        printf("  [%d] Inspector: %-16s | GPS: (%.4f, %.4f) | Cat: %-12s | Sev: %d | %s\n",
               r.id, r.inspector, r.latitude, r.longitude, r.category, r.severity, ts);
        count++;
    }
    close(fd);

    if (count == 0)
        printf("  (no reports in district '%s')\n", district);
    else
        printf("  Total: %d report(s)\n", count);

    log_action(district, role, user, "list");
}

void cmd_view(const char *district, int report_id, const char *role, const char *user) {
    if (!role_may(role, "read", "reports.dat")) {
        fprintf(stderr, "ERROR: role '%s' cannot read reports.dat\n", role);
        return;
    }

    char path[512];
    snprintf(path, sizeof(path), "%s/reports.dat", district);

    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "ERROR: cannot open '%s': %s\n", path, strerror(errno));
        return;
    }

    Report r;
    int found = 0;
    while (read(fd, &r, sizeof(r)) == (ssize_t)sizeof(r)) {
        if (r.id == report_id) {
            found = 1;
            break;
        }
    }
    close(fd);

    if (!found) {
        fprintf(stderr, "ERROR: report #%d not found in district '%s'\n", report_id, district);
        return;
    }

    char ts[64];
    struct tm *t = localtime(&r.timestamp);
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", t);

    printf("=== Report #%d ===\n", r.id);
    printf("Inspector  : %s\n", r.inspector);
    printf("GPS        : (%.6f, %.6f)\n", r.latitude, r.longitude);
    printf("Category   : %s\n", r.category);
    printf("Severity   : %d\n", r.severity);
    printf("Timestamp  : %s\n", ts);
    printf("Description: %s\n", r.description);

    log_action(district, role, user, "view");
}

void cmd_remove_report(const char *district, int report_id, const char *role, const char *user) {
    if (strcmp(role, "manager") != 0) {
        fprintf(stderr, "ERROR: only managers can remove reports\n");
        return;
    }

    char path[512];
    snprintf(path, sizeof(path), "%s/reports.dat", district);

    if (!check_perms(path, 0664)) return;

    int fd = open(path, O_RDWR);
    if (fd < 0) {
        fprintf(stderr, "ERROR: cannot open '%s': %s\n", path, strerror(errno));
        return;
    }

    struct stat st;
    fstat(fd, &st);
    int total = (int)(st.st_size / sizeof(Report));

    int target_idx = -1;
    for (int i = 0; i < total; i++) {
        Report r;
        lseek(fd, (off_t)(i * sizeof(Report)), SEEK_SET);
        if (read(fd, &r, sizeof(r)) == (ssize_t)sizeof(r)) {
            if (r.id == report_id) { target_idx = i; break; }
        }
    }

    if (target_idx < 0) {
        fprintf(stderr, "ERROR: report #%d not found in '%s'\n", report_id, district);
        close(fd);
        return;
    }

    for (int i = target_idx + 1; i < total; i++) {
        Report r;
        lseek(fd, (off_t)(i * sizeof(Report)), SEEK_SET);
        read(fd, &r, sizeof(r));
        lseek(fd, (off_t)((i - 1) * sizeof(Report)), SEEK_SET);
        write(fd, &r, sizeof(r));
    }

    off_t new_size = (off_t)((total - 1) * sizeof(Report));
    ftruncate(fd, new_size);
    close(fd);

    printf("Report #%d removed from district '%s'\n", report_id, district);
    log_action(district, role, user, "remove_report");
}

void cmd_update_threshold(const char *district, int threshold, const char *role, const char *user) {
    if (strcmp(role, "manager") != 0) {
        fprintf(stderr, "ERROR: only managers can update threshold\n");
        return;
    }

    char path[512];
    snprintf(path, sizeof(path), "%s/district.cfg", district);

    if (!check_perms(path, 0640)) {
        fprintf(stderr, "ERROR: aborting update_threshold — permissions changed on district.cfg\n");
        return;
    }

    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0640);
    if (fd < 0) {
        fprintf(stderr, "ERROR: cannot open '%s': %s\n", path, strerror(errno));
        return;
    }
    chmod(path, 0640);

    char buf[64];
    int len = snprintf(buf, sizeof(buf), "severity_threshold=%d\n", threshold);
    write(fd, buf, len);
    close(fd);

    printf("Threshold updated to %d in district '%s'\n", threshold, district);
    log_action(district, role, user, "update_threshold");
}

void cmd_filter(const char *district, const char *role, const char *user,
                char **conditions, int num_conditions) {
    if (!role_may(role, "read", "reports.dat")) {
        fprintf(stderr, "ERROR: role '%s' cannot read reports.dat\n", role);
        return;
    }

    char fields[16][32], ops[16][8], values[16][128];
    if (num_conditions > 16) {
        fprintf(stderr, "ERROR: too many conditions (max 16)\n");
        return;
    }

    for (int i = 0; i < num_conditions; i++) {
        if (!parse_condition(conditions[i], fields[i], ops[i], values[i])) {
            fprintf(stderr, "ERROR: invalid condition '%s'\n", conditions[i]);
            return;
        }
    }

    char path[512];
    snprintf(path, sizeof(path), "%s/reports.dat", district);

    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "ERROR: cannot open '%s': %s\n", path, strerror(errno));
        return;
    }

    Report r;
    int found = 0;
    while (read(fd, &r, sizeof(r)) == (ssize_t)sizeof(r)) {
        int match = 1;
        for (int i = 0; i < num_conditions; i++) {
            if (!match_condition(&r, fields[i], ops[i], values[i])) {
                match = 0;
                break;
            }
        }
        if (match) {
            char ts[64];
            struct tm *t = localtime(&r.timestamp);
            strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", t);
            printf("[%d] %-16s GPS:(%.4f,%.4f) %-12s sev=%d %s | %s\n",
                   r.id, r.inspector, r.latitude, r.longitude,
                   r.category, r.severity, ts, r.description);
            found++;
        }
    }
    close(fd);

    if (found == 0)
        printf("(no reports match the given conditions)\n");
    else
        printf("(%d report(s) matched)\n", found);

    log_action(district, role, user, "filter");
}

void check_symlinks(void) {
    DIR *d = opendir(".");
    if (!d) return;
    struct dirent *entry;
    while ((entry = readdir(d)) != NULL) {
        if (strncmp(entry->d_name, "active_reports-", 15) != 0) continue;
        struct stat lst, st;
        if (lstat(entry->d_name, &lst) < 0) continue;
        if (!S_ISLNK(lst.st_mode)) continue;
        if (stat(entry->d_name, &st) < 0)
            fprintf(stderr, "WARNING: dangling symlink detected: %s\n", entry->d_name);
    }
    closedir(d);
}

static void usage(const char *prog) {
    fprintf(stderr,
        "Usage:\n"
        "  %s --role <manager|inspector> --user <n> --add <district>\n"
        "  %s --role <role> --user <n> --list <district>\n"
        "  %s --role <role> --user <n> --view <district> <report_id>\n"
        "  %s --role manager --user <n> --remove_report <district> <report_id>\n"
        "  %s --role manager --user <n> --update_threshold <district> <value>\n"
        "  %s --role <role> --user <n> --filter <district> <cond> [<cond>...]\n",
        prog, prog, prog, prog, prog, prog);
}

int main(int argc, char *argv[]) {
    char *role     = NULL;
    char *user     = NULL;
    char *command  = NULL;
    char *district = NULL;

    int i;
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--role") == 0 && i + 1 < argc) {
            role = argv[++i];
        } else if (strcmp(argv[i], "--user") == 0 && i + 1 < argc) {
            user = argv[++i];
        } else if (argv[i][0] == '-' && argv[i][1] == '-') {
            command = argv[i] + 2;
            if (i + 1 < argc && argv[i + 1][0] != '-')
                district = argv[++i];
            break;
        }
    }

    if (!role || !user || !command) {
        usage(argv[0]);
        return 1;
    }

    if (strcmp(role, "manager") != 0 && strcmp(role, "inspector") != 0) {
        fprintf(stderr, "ERROR: role must be 'manager' or 'inspector'\n");
        return 1;
    }

    check_symlinks();

    if (strcmp(command, "add") == 0) {
        if (!district) { fprintf(stderr, "ERROR: --add requires <district>\n"); return 1; }
        cmd_add(district, role, user);

    } else if (strcmp(command, "list") == 0) {
        if (!district) { fprintf(stderr, "ERROR: --list requires <district>\n"); return 1; }
        cmd_list(district, role, user);

    } else if (strcmp(command, "view") == 0) {
        if (!district || i + 1 >= argc) {
            fprintf(stderr, "ERROR: --view requires <district> <report_id>\n");
            return 1;
        }
        cmd_view(district, atoi(argv[i + 1]), role, user);

    } else if (strcmp(command, "remove_report") == 0) {
        if (!district || i + 1 >= argc) {
            fprintf(stderr, "ERROR: --remove_report requires <district> <report_id>\n");
            return 1;
        }
        cmd_remove_report(district, atoi(argv[i + 1]), role, user);

    } else if (strcmp(command, "update_threshold") == 0) {
        if (!district || i + 1 >= argc) {
            fprintf(stderr, "ERROR: --update_threshold requires <district> <value>\n");
            return 1;
        }
        cmd_update_threshold(district, atoi(argv[i + 1]), role, user);

    } else if (strcmp(command, "filter") == 0) {
        if (!district) {
            fprintf(stderr, "ERROR: --filter requires <district> <condition(s)>\n");
            return 1;
        }
        char **conds = &argv[i + 1];
        int nconds = argc - (i + 1);
        if (nconds < 1) {
            fprintf(stderr, "ERROR: --filter requires at least one condition\n");
            return 1;
        }
        cmd_filter(district, role, user, conds, nconds);

    } else {
        fprintf(stderr, "ERROR: unknown command '--%s'\n", command);
        usage(argv[0]);
        return 1;
    }

    return 0;
}
