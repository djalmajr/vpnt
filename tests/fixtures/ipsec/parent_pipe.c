/* Ordinary child used only by the focused Rust process test.
 *
 * It is not charon and contains no parent-watch logic: it asserts the stdio
 * contract of ManagedChild::spawn_charon (anonymous read-only FIFO on fd 0,
 * /dev/null on fd 1 and 2), records readiness in a private audit file, then
 * blocks until the only writer closes and reports EOF.
 */
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int record(const char *path, const char *text) {
    int fd = open(path, O_WRONLY | O_APPEND | O_CREAT, 0600);
    if (fd == -1) {
        return 1;
    }
    ssize_t length = (ssize_t)strlen(text);
    ssize_t written = write(fd, text, (size_t)length);
    int closed = close(fd);
    return (written == length && closed == 0) ? 0 : 1;
}

int main(int argc, char **argv) {
    struct stat null_device, descriptor;
    if (argc != 2) {
        return 2;
    }
    if (stat("/dev/null", &null_device) != 0) {
        return 10;
    }
    if (fstat(0, &descriptor) != 0 || !S_ISFIFO(descriptor.st_mode) ||
        descriptor.st_nlink != 0) {
        return 11;
    }
    int flags = fcntl(0, F_GETFL);
    if (flags == -1 || (flags & O_ACCMODE) != O_RDONLY) {
        return 12;
    }
    for (int fd = 1; fd < 3; fd++) {
        if (fstat(fd, &descriptor) != 0 || !S_ISCHR(descriptor.st_mode) ||
            descriptor.st_rdev != null_device.st_rdev) {
            return 13;
        }
    }
    if (record(argv[1], "ready\n") != 0) {
        return 14;
    }
    /* Bounded so a leaked writer cannot leave a child behind forever. */
    alarm(20);
    for (;;) {
        char byte;
        ssize_t length = read(0, &byte, 1);
        if (length == 0) {
            return record(argv[1], "eof\n") == 0 ? 0 : 15;
        }
        if (length > 0) {
            /* 16: payload correctly rejected; 18: the audit record failed. */
            return record(argv[1], "data\n") == 0 ? 16 : 18;
        }
        if (errno != EINTR) {
            return 17;
        }
    }
}
