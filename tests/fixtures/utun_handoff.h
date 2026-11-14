#ifndef VPNT_LIBIPSEC_FIXTURE_H
#define VPNT_LIBIPSEC_FIXTURE_H

#include <stdbool.h>
#include <stdio.h>
#include <sys/types.h>
#include <plugins/plugin.h>

extern plugin_t *kernel_libipsec_plugin_create(void);

/* The fixture prints through libc, not strongSwan's printf hook. */
#undef printf
#undef fprintf
#undef poll

extern bool g_retain;
extern bool g_up_result;
extern bool g_mtu_result;
extern int g_up_calls;
extern int g_mtu_calls;
extern int g_destroy_calls;
extern int g_published;
extern int g_tun_fd;
extern int g_receiver;
extern int g_up_saw_datagram;
extern int g_peer_closed;
extern int g_libipsec_initialized;
extern const char *g_test;

void reset_fixture(void);
void reserve_fd3(void);
int make_dgram_pair(int sv[2]);
int make_stream_pair(int sv[2]);
int make_tun_pipe(int pipefd[2]);
void install_channel(int fd);
void close_fd(int *fd);
int recv_handoff(int receiver, int *fd, unsigned char payload[8], int *fds,
				 int *ctrunc);

int test_default_off(void);
int test_enabled_success(void);
int test_stream_channel(void);
int test_non_unix_channel(void);
int test_closed_channel(void);
int test_peer_closed(void);
int test_up_failure(void);
int test_mtu_failure(void);

#define CHECK(cond) do { if (!(cond)) { \
	fprintf(stderr, "FAIL %s: %s (line %d)\n", g_test, #cond, __LINE__); \
	return 1; } } while (0)

#endif
