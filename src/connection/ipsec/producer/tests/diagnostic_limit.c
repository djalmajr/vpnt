#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <sys/resource.h>
#include <unistd.h>

#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "fixture check failed at line %d (errno %d)\n", __LINE__, errno); \
        return 1; \
    } \
} while (0)

int main(int argc, char **argv)
{
    const rlim_t cap = 8 * 1024 * 1024;
    struct rlimit limit;
    struct sigaction action;
    char block[8192] = {0};
    CHECK(argc == 2);
    CHECK(getrlimit(RLIMIT_FSIZE, &limit) == 0);
    CHECK(limit.rlim_cur == cap && limit.rlim_max == cap);
    CHECK(sigaction(SIGXFSZ, NULL, &action) == 0);
    CHECK(action.sa_handler == SIG_IGN);
    int fd = open(argv[1], O_WRONLY | O_APPEND | O_NOFOLLOW);
    CHECK(fd >= 0);
    for (rlim_t size = 0; size < cap - sizeof(block); size += sizeof(block)) {
        CHECK(write(fd, block, sizeof(block)) == sizeof(block));
    }
    CHECK(write(fd, block, sizeof(block) - 17) == sizeof(block) - 17);
    /* Exercise a partial write at the boundary, then repeated failed writes. */
    CHECK(write(fd, block, sizeof(block)) == 17);
    for (int attempt = 0; attempt < 3; attempt++) {
        errno = 0;
        CHECK(write(fd, block, sizeof(block)) == -1 && errno == EFBIG);
    }
    CHECK(close(fd) == 0);
    puts("alive after repeated EFBIG");
    return 0;
}
