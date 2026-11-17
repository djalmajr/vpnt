/* Ordinary child fixture for the private FD3 datagram capability.
 *
 * It is not charon and contains no VPN logic. In channel modes it validates the
 * inherited stdio/FD3 contract, records readiness in a private audit file, sends
 * exactly the requested descriptor payload, then waits for EOF on the peer ends
 * it kept. EOF proves the helper closed every delivered descriptor; a leaked
 * reference would time out (alarm) and report a nonzero exit.
 * Mode "scan" lists inherited descriptors > 2 for the spawn-guard test.
 * Mode "many" sends six descriptors: with the full-size ancillary buffer all
 * six are reported, so the receiver must close every one of them.
 * Mode "closed-after" sends one valid message and then closes FD3, as the real
 * plugin does; the receiver must admit the first message.
 * Mode "extra-closed" queues a second valid message before closing FD3; the
 * receiver must still refuse the extra datagram.
 * Mode "max" sends the same SOCK_STREAM writer 254 times (the accepted kernel
 * maximum), then closes the original once; EOF on the peer proves every imported
 * reference was closed by the helper.
 */
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#define INHERITED 3
#define RIGHTS_MAX 254

static int append(const char *path, const char *text) {
    int fd = open(path, O_WRONLY | O_APPEND | O_CREAT, 0600);
    if (fd == -1) return 1;
    ssize_t length = (ssize_t)strlen(text);
    ssize_t written = write(fd, text, (size_t)length);
    int closed = close(fd);
    return (written == length && closed == 0) ? 0 : 1;
}

static void payload_for(unsigned char out[8], const char *mode) {
    static const unsigned char base[8] = {0x56, 0x50, 0x55, 0x46, 1, 0, 0, 0};
    memcpy(out, base, sizeof(base));
    if (strcmp(mode, "bad-magic") == 0) out[0] = 0x57;
    else if (strcmp(mode, "bad-version") == 0) out[4] = 2;
    else if (strcmp(mode, "bad-reserved") == 0) out[7] = 1;
}

static int send_rights(int socket, const unsigned char *data, size_t length,
                       const int *fds, size_t count) {
    struct msghdr message;
    struct iovec iov = {(void *)data, length};
    char control[CMSG_SPACE(RIGHTS_MAX * sizeof(int))];
    memset(&message, 0, sizeof(message));
    memset(control, 0, sizeof(control));
    message.msg_iov = &iov;
    message.msg_iovlen = 1;
    if (count > 0) {
        struct cmsghdr *cmsg;
        message.msg_control = control;
        message.msg_controllen = CMSG_SPACE(count * sizeof(int));
        cmsg = CMSG_FIRSTHDR(&message);
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SCM_RIGHTS;
        cmsg->cmsg_len = CMSG_LEN(count * sizeof(int));
        memcpy(CMSG_DATA(cmsg), fds, count * sizeof(int));
    }
    return sendmsg(socket, &message, 0) == (ssize_t)length ? 0 : 1;
}

static int wait_eof(int *peers, int count) {
    for (;;) {
        int remaining = 0;
        for (int index = 0; index < count; index++) {
            struct pollfd ready;
            if (peers[index] < 0) continue;
            remaining++;
            ready.fd = peers[index];
            ready.events = POLLIN;
            ready.revents = 0;
            int result = poll(&ready, 1, 100);
            if (result < 0) {
                if (errno == EINTR) continue;
                return 19;
            }
            if (result > 0) {
                char byte;
                ssize_t read_length;
                /* A closed datagram peer reports hangup, not readable data. */
                if (ready.revents & (POLLHUP | POLLERR | POLLNVAL)) {
                    close(peers[index]);
                    peers[index] = -1;
                    continue;
                }
                if (!(ready.revents & POLLIN)) continue;
                read_length = read(peers[index], &byte, 1);
                /* A closed AF_UNIX datagram peer reports ECONNRESET, while a
                 * closed SOCK_STREAM peer reports end of file. */
                if (read_length == 0 ||
                    (read_length < 0 && (errno == ECONNRESET || errno == ENOTCONN || errno == EPIPE))) {
                    close(peers[index]);
                    peers[index] = -1;
                } else if (read_length > 0) {
                    return 20;
                } else if (errno != EINTR && errno != EAGAIN) {
                    return 21;
                }
            }
        }
        if (remaining == 0) return 0;
    }
}

static int channel(const char *mode, const char *audit) {
    struct stat null_device, state;
    int flags;
    if (stat("/dev/null", &null_device) != 0) return 10;
    if (fstat(0, &state) != 0 || !S_ISFIFO(state.st_mode) || state.st_nlink != 0) return 11;
    if (fstat(1, &state) != 0 || !S_ISCHR(state.st_mode) || state.st_rdev != null_device.st_rdev) return 12;
    if (fstat(2, &state) != 0 || !S_ISCHR(state.st_mode) || state.st_rdev != null_device.st_rdev) return 13;
    if (fstat(INHERITED, &state) != 0 || !S_ISSOCK(state.st_mode)) return 14;
    int kind = 0;
    socklen_t kind_length = sizeof(kind);
    if (getsockopt(INHERITED, SOL_SOCKET, SO_TYPE, &kind, &kind_length) != 0 ||
        kind != SOCK_DGRAM || kind_length != sizeof(kind)) return 15;
    flags = fcntl(INHERITED, F_GETFD);
    if (flags < 0 || (flags & FD_CLOEXEC) != 0) return 16;
    if (append(audit, "ready\n") != 0) return 18;
    alarm(10);
    if (strcmp(mode, "exit") == 0) return 0;
    if (strcmp(mode, "hold") == 0) { for (;;) pause(); }

    unsigned char data[16];
    memset(data, 0, sizeof(data));
    payload_for(data, mode);
    size_t length = strcmp(mode, "short") == 0 ? 3 : strcmp(mode, "long") == 0 ? 9 : 8;
    if (strcmp(mode, "zero") == 0) {
        int channel[1];
        if (send_rights(INHERITED, data, length, NULL, 0) != 0) return 20;
        channel[0] = INHERITED;
        int result = wait_eof(channel, 1);
        if (result != 0) return result;
        return append(audit, "closed\n") == 0 ? 0 : 25;
    }
    if (strcmp(mode, "closed-after") == 0) {
        int pair[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) != 0) return 28;
        if (send_rights(INHERITED, data, 8, &pair[0], 1) != 0) return 29;
        close(pair[0]);
        close(INHERITED);
        int result = wait_eof(&pair[1], 1);
        if (result != 0) return result;
        return append(audit, "closed\n") == 0 ? 0 : 25;
    }
    if (strcmp(mode, "extra-closed") == 0) {
        int pair[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) != 0) return 30;
        if (send_rights(INHERITED, data, 8, &pair[0], 1) != 0) return 31;
        if (send_rights(INHERITED, data, 8, &pair[0], 1) != 0) return 32;
        close(pair[0]);
        close(INHERITED);
        int result = wait_eof(&pair[1], 1);
        if (result != 0) return result;
        return append(audit, "closed\n") == 0 ? 0 : 25;
    }
    if (strcmp(mode, "max") == 0) {
        int pair[2];
        int sent[RIGHTS_MAX];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) != 0) return 26;
        for (int index = 0; index < RIGHTS_MAX; index++) sent[index] = pair[0];
        if (send_rights(INHERITED, data, 8, sent, RIGHTS_MAX) != 0) return 27;
        close(pair[0]);
        int result = wait_eof(&pair[1], 1);
        if (result != 0) return result;
        return append(audit, "closed\n") == 0 ? 0 : 25;
    }
    int pairs[3][2];
    int sent[6];
    int peers[7];
    int count = 0;
    int pair_count = strcmp(mode, "many") == 0 ? 3 : strcmp(mode, "two") == 0 ? 2 : 1;
    for (int index = 0; index < pair_count; index++) {
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, pairs[index]) != 0) return 21;
    }
    if (strcmp(mode, "two") == 0) {
        for (int index = 0; index < 2; index++) { sent[index] = pairs[index][0]; peers[index] = pairs[index][1]; }
        count = 2;
    } else if (strcmp(mode, "many") == 0) {
        for (int index = 0; index < 3; index++) {
            sent[index * 2] = pairs[index][0];
            sent[index * 2 + 1] = dup(pairs[index][0]);
            peers[index * 2] = pairs[index][1];
            peers[index * 2 + 1] = -1;
        }
        count = 6;
    } else {
        sent[0] = pairs[0][0];
        peers[0] = pairs[0][1];
        count = 1;
    }
    if (strcmp(mode, "extra") == 0) {
        if (send_rights(INHERITED, data, 8, sent, 1) != 0) return 22;
        if (send_rights(INHERITED, data, 8, sent, 1) != 0) return 23;
    } else if (send_rights(INHERITED, data, length, sent, (size_t)count) != 0) {
        return 24;
    }
    for (int index = 0; index < count; index++) close(sent[index]);
    peers[count] = INHERITED;
    int result = wait_eof(peers, count + 1);
    if (result != 0) return result;
    return append(audit, "closed\n") == 0 ? 0 : 25;
}

static int scan(const char *audit) {
    char report[1024];
    size_t used = 0;
    /* Pre-scan marker: the helper's guard test uses it to prove no fork ran
     * while the pending descriptor was still inheritable. */
    if (append(audit, "started\n") != 0) return 1;
    for (int fd = 3; fd < 64; fd++) {
        if (fcntl(fd, F_GETFD) < 0) continue;
        int written = snprintf(report + used, sizeof(report) - used, "fd=%d\n", fd);
        if (written < 0 || (size_t)written >= sizeof(report) - used) return 2;
        used += (size_t)written;
    }
    report[used] = 0;
    return append(audit, report);
}

int main(int argc, char **argv) {
    if (argc != 3) return 2;
    if (strcmp(argv[1], "scan") == 0) {
        /* scan inspects before opening the audit file, so it lists only
         * descriptors inherited from the helper. */
        return scan(argv[2]);
    }
    return channel(argv[1], argv[2]);
}
