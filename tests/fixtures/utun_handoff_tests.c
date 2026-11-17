/* Focused constructor tests over the real patched original TU. */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "utun_handoff.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

static int prepare(int sv[2], int pipefd[2])
{
	reset_fixture();
	reserve_fd3();
	if (make_dgram_pair(sv) != 0)
	{
		return 1;
	}
	if (make_tun_pipe(pipefd) != 0)
	{
		return 1;
	}
	install_channel(sv[1]);
	close(sv[1]);
	g_receiver = sv[0];
	return 0;
}

int test_default_off(void)
{
	int sv[2], pipefd[2], flags;
	unsigned char payload[8];
	int fd = -1, fds = 0, ctrunc = 0;
	plugin_t *plugin;

	g_retain = FALSE;
	if (prepare(sv, pipefd))
	{
		return 1;
	}
	plugin = kernel_libipsec_plugin_create();
	CHECK(plugin != NULL);
	CHECK(g_published == 1);
	CHECK(g_destroy_calls == 0);
	flags = fcntl(pipefd[0], F_GETFD);
	CHECK(flags >= 0);
	CHECK((flags & FD_CLOEXEC) == 0);
	flags = fcntl(3, F_GETFD);
	CHECK(flags >= 0);
	CHECK((flags & FD_CLOEXEC) == 0);
	CHECK(recv_handoff(sv[0], &fd, payload, &fds, &ctrunc) < 0);
	CHECK(fd == -1 && fds == 0);
	plugin->destroy(plugin);
	close(sv[0]);
	close(pipefd[0]);
	close(pipefd[1]);
	return 0;
}

int test_enabled_success(void)
{
	int sv[2], pipefd[2], flags;
	int fd = -1, fds = 0, ctrunc = 0;
	int second = -1, second_fds = 0, second_ctrunc = 0;
	ssize_t length;
	unsigned char payload[8];
	char byte;
	plugin_t *plugin;

	if (prepare(sv, pipefd))
	{
		return 1;
	}
	g_retain = TRUE;
	plugin = kernel_libipsec_plugin_create();
	CHECK(plugin != NULL);
	CHECK(g_mtu_calls == 1 && g_up_calls == 1);
	CHECK(g_up_saw_datagram == 0);
	CHECK(g_published == 1);
	flags = fcntl(pipefd[0], F_GETFD);
	CHECK(flags >= 0);
	CHECK((flags & FD_CLOEXEC) != 0);
	flags = fcntl(3, F_GETFD);
	CHECK(flags < 0 && errno == EBADF);
	length = recv_handoff(sv[0], &fd, payload, &fds, &ctrunc);
	CHECK(length == 8);
	CHECK(fds == 1);
	CHECK(ctrunc == 0);
	CHECK(fd >= 0);
	CHECK(payload[0] == 0x56 && payload[1] == 0x50 && payload[2] == 0x55 &&
		  payload[3] == 0x46 && payload[4] == 1 && payload[5] == 0 &&
		  payload[6] == 0 && payload[7] == 0);
	CHECK(write(pipefd[1], "z", 1) == 1);
	CHECK(read(fd, &byte, 1) == 1 && byte == 'z');
	close(pipefd[1]);
	pipefd[1] = -1;
	CHECK(read(fd, &byte, 1) == 0);
	CHECK(recv_handoff(sv[0], &second, payload, &second_fds,
					   &second_ctrunc) < 0);
	CHECK(second == -1 && second_fds == 0);
	close(fd);
	plugin->destroy(plugin);
	close(sv[0]);
	close(pipefd[0]);
	return 0;
}

int test_stream_channel(void)
{
	int sv[2], pipefd[2];
	unsigned char payload[8];
	int fd = -1, fds = 0, ctrunc = 0;
	char byte;
	plugin_t *plugin;

	reset_fixture();
	reserve_fd3();
	g_retain = TRUE;
	CHECK(make_stream_pair(sv) == 0);
	CHECK(make_tun_pipe(pipefd) == 0);
	install_channel(sv[1]);
	close(sv[1]);
	g_receiver = sv[0];
	plugin = kernel_libipsec_plugin_create();
	CHECK(plugin == NULL);
	CHECK(g_destroy_calls == 1);
	CHECK(g_published == 0);
	CHECK(fcntl(3, F_GETFD) < 0 && errno == EBADF);
	CHECK(recv(sv[0], &byte, 1, MSG_DONTWAIT) <= 0);
	CHECK(recv_handoff(sv[0], &fd, payload, &fds, &ctrunc) <= 0);
	close(sv[0]);
	close(pipefd[0]);
	close(pipefd[1]);
	return 0;
}

int test_non_unix_channel(void)
{
	int channel, pipefd[2];
	struct sockaddr_in address;
	unsigned char payload[8];
	int fd = -1, fds = 0, ctrunc = 0;
	plugin_t *plugin;

	reset_fixture();
	reserve_fd3();
	g_retain = TRUE;
	CHECK(make_tun_pipe(pipefd) == 0);
	channel = socket(AF_INET, SOCK_DGRAM, 0);
	CHECK(channel >= 0);
	memset(&address, 0, sizeof(address));
	address.sin_family = AF_INET;
	address.sin_port = htons(9);
	address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	CHECK(connect(channel, (struct sockaddr*)&address, sizeof(address)) == 0);
	install_channel(channel);
	close(channel);
	plugin = kernel_libipsec_plugin_create();
	CHECK(plugin == NULL);
	CHECK(g_destroy_calls == 1);
	CHECK(g_published == 0);
	CHECK(fcntl(3, F_GETFD) < 0 && errno == EBADF);
	CHECK(recv_handoff(3, &fd, payload, &fds, &ctrunc) < 0);
	close(pipefd[0]);
	close(pipefd[1]);
	return 0;
}

int test_closed_channel(void)
{
	int pipefd[2];
	plugin_t *plugin;

	reset_fixture();
	reserve_fd3();
	g_retain = TRUE;
	CHECK(make_tun_pipe(pipefd) == 0);
	close(3);
	plugin = kernel_libipsec_plugin_create();
	CHECK(plugin == NULL);
	CHECK(g_destroy_calls == 0);
	CHECK(g_published == 0);
	CHECK(g_libipsec_initialized == 0);
	close(pipefd[0]);
	close(pipefd[1]);
	return 0;
}

int test_peer_closed(void)
{
	int sv[2], pipefd[2];
	unsigned char payload[8];
	int fd = -1, fds = 0, ctrunc = 0;
	plugin_t *plugin;

	reset_fixture();
	reserve_fd3();
	g_retain = TRUE;
	g_peer_closed = 1;
	CHECK(make_dgram_pair(sv) == 0);
	CHECK(make_tun_pipe(pipefd) == 0);
	close(sv[0]);
	install_channel(sv[1]);
	close(sv[1]);
	plugin = kernel_libipsec_plugin_create();
	CHECK(plugin == NULL);
	CHECK(g_destroy_calls == 1);
	CHECK(g_published == 0);
	CHECK(fcntl(3, F_GETFD) < 0 && errno == EBADF);
	CHECK(recv_handoff(3, &fd, payload, &fds, &ctrunc) < 0);
	close(pipefd[0]);
	close(pipefd[1]);
	return 0;
}

int test_up_failure(void)
{
	int sv[2], pipefd[2];
	unsigned char payload[8];
	int fd = -1, fds = 0, ctrunc = 0;
	plugin_t *plugin;

	if (prepare(sv, pipefd))
	{
		return 1;
	}
	g_retain = TRUE;
	g_up_result = FALSE;
	plugin = kernel_libipsec_plugin_create();
	CHECK(plugin == NULL);
	CHECK(g_up_calls == 1);
	CHECK(g_destroy_calls == 1);
	CHECK(g_published == 0);
	CHECK(fcntl(3, F_GETFD) < 0 && errno == EBADF);
	CHECK(recv_handoff(sv[0], &fd, payload, &fds, &ctrunc) < 0);
	close(sv[0]);
	close(pipefd[0]);
	close(pipefd[1]);
	return 0;
}

int test_mtu_failure(void)
{
	int sv[2], pipefd[2];
	unsigned char payload[8];
	int fd = -1, fds = 0, ctrunc = 0;
	plugin_t *plugin;

	if (prepare(sv, pipefd))
	{
		return 1;
	}
	g_retain = TRUE;
	g_mtu_result = FALSE;
	plugin = kernel_libipsec_plugin_create();
	CHECK(plugin == NULL);
	CHECK(g_mtu_calls == 1);
	CHECK(g_destroy_calls == 1);
	CHECK(g_published == 0);
	CHECK(fcntl(3, F_GETFD) < 0 && errno == EBADF);
	CHECK(recv_handoff(sv[0], &fd, payload, &fds, &ctrunc) < 0);
	close(sv[0]);
	close(pipefd[0]);
	close(pipefd[1]);
	return 0;
}
