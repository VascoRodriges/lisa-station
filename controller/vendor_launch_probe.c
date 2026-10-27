/* Fixed-target startup qualification, NOT an installed mode controller.
 * Administrative-only: caller must first stop/freeze stock launcher under a
 * separately verified bounded rollback. No arbitrary executable or shell input.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "vendor_identity.h"

#define VENDOR_GID 57342

int main(int argc, char **argv) {
    if (argc != 2 || strcmp(argv[1], "--quasar") || geteuid()) return 2;
    int fd = open("/proc/device-tree/compatible", O_RDONLY | O_CLOEXEC);
    char data[512];
    if (fd < 0) return 3;
    ssize_t size = read(fd, data, sizeof(data)); close(fd);
    const char model[] = "yandex,station-midi"; int supported = 0;
    for (ssize_t i = 0; i + (ssize_t)sizeof(model) <= size; ++i)
        if ((!i || !data[i-1]) && !memcmp(data + i, model, sizeof(model))) supported = 1;
    if (!supported || access("/data/opt/lisa-lab/trial.lock", F_OK)) return 3;
    /* Logs go to /dev/null in the trial; don't inherit an administrative socket. */
    for (int descriptor = 0; descriptor < 3; ++descriptor) {
        struct stat info;
        if (fstat(descriptor, &info) || S_ISSOCK(info.st_mode)) return 4;
    }
    struct rlimit limit;
    if (getrlimit(RLIMIT_NOFILE, &limit) || limit.rlim_cur > 65536) return 4;
    for (unsigned long descriptor = 3; descriptor < limit.rlim_cur; ++descriptor) close((int)descriptor);
    struct rlimit files = {10240, 10240};
    struct rlimit stack = {1024 * 1024, 1024 * 1024};
    if (setrlimit(RLIMIT_NOFILE, &files) || setrlimit(RLIMIT_STACK, &stack) || chdir("/data/quasar")) return 4;
    if (setenv("CA_CERTIFICATES", "/system/vendor/quasar/ca-certificates.crt", 1) ||
        setenv("LD_LIBRARY_PATH", "/system/vendor/quasar/libs", 1) ||
        setenv("GST_PLUGIN_PATH", "/system/vendor/quasar/libs", 1) ||
        setenv("PATH", "/system/vendor/quasar:/usr/bin:/bin:/usr/sbin:/sbin", 1)) return 4;
    if (vendor_identity_prepare(VENDOR_GID)) return 5;
    execl("/system/vendor/quasar/quasar_launcher2", "quasar_launcher2",
          "/system/vendor/quasar/launch.json", (char *)NULL);
    return 6;
}
