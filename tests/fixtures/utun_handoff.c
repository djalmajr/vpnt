/* Independent SDK fixture for the patched original kernel-libipsec TU. */
#include <daemon.h>
#include <library.h>
#include <kernel/kernel_ipsec.h>
#include <networking/tun_device.h>
#include <plugins/plugin.h>
#include <settings/settings.h>
#include <utils/capabilities.h>

#include "kernel_libipsec_esp_handler.h"
#include "kernel_libipsec_ipsec.h"
#include "kernel_libipsec_router.h"
#include "utun_handoff.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

library_t *lib;
daemon_t *charon;
bool g_retain, g_up_result, g_mtu_result;
int g_up_calls, g_mtu_calls, g_destroy_calls, g_published;
int g_tun_fd, g_receiver, g_up_saw_datagram, g_peer_closed;
int g_libipsec_initialized;
const char *g_test = "?";

static settings_t settings;
static capabilities_t caps;
static library_t library;
static daemon_t daemon_stub;
static bus_t bus_stub;

static void fixture_bus_log(bus_t *this, debug_t group, level_t level,
							char *format, ...)
{
	(void)this; (void)group; (void)level; (void)format;
}

static bool fixture_get_bool(settings_t *this, char *key, int def, ...)
{
	(void)this;
	if (strstr(key, "vpnt_retain_utun"))
	{
		return g_retain;
	}
	if (strstr(key, "raw_esp"))
	{
		return FALSE;
	}
	return def != 0;
}

static void fixture_set_str(settings_t *this, char *key, char *value, ...)
{ (void)this; (void)key; (void)value; }

static bool fixture_caps_check(capabilities_t *this, u_int cap)
{ (void)this; (void)cap; return TRUE; }

static bool fixture_lib_set(library_t *this, char *name, void *object)
{
	(void)this;
	if (strcmp(name, "kernel-libipsec-tun") == 0 && object) g_published++;
	return TRUE;
}

static bool fake_set_mtu(tun_device_t *this, int mtu)
{ (void)this; (void)mtu; g_mtu_calls++; return g_mtu_result; }

static bool fake_up(tun_device_t *this)
{
	struct pollfd pfd;

	(void)this;
	g_up_calls++;
	if (g_receiver >= 0 && !g_peer_closed)
	{
		pfd.fd = g_receiver;
		pfd.events = POLLIN;
		pfd.revents = 0;
		if (poll(&pfd, 1, 0) > 0 && (pfd.revents & POLLIN))
		{
			g_up_saw_datagram = 1;
		}
	}
	return g_up_result;
}

static char *fake_name(tun_device_t *this) { (void)this; return "ipsec0"; }
static int fake_fd(tun_device_t *this) { (void)this; return g_tun_fd; }
static void fake_destroy(tun_device_t *this)
{ g_destroy_calls++; free(this); }

tun_device_t *tun_device_create(const char *name)
{
	tun_device_t *tun = calloc(1, sizeof(*tun));

	(void)name;
	if (tun)
	{
		tun->set_mtu = fake_set_mtu;
		tun->up = fake_up;
		tun->get_name = fake_name;
		tun->get_fd = fake_fd;
		tun->destroy = fake_destroy;
	}
	return tun;
}

bool kernel_ipsec_register(plugin_t *plugin, plugin_feature_t *feature,
						   bool reg, void *data)
{ (void)plugin; (void)feature; (void)reg; (void)data; return TRUE; }

kernel_libipsec_ipsec_t *kernel_libipsec_ipsec_create() { return NULL; }
kernel_libipsec_router_t *kernel_libipsec_router_create() { return NULL; }
kernel_libipsec_esp_handler_t *kernel_libipsec_esp_handler_create()
{
	return NULL;
}

bool libipsec_init() { g_libipsec_initialized = 1; return TRUE; }

void libipsec_deinit()
{
	if (!g_libipsec_initialized)
	{
		fprintf(stderr, "FAIL %s: libipsec_deinit before init (oracle)\n", g_test);
		exit(1);
	}
	g_libipsec_initialized = 0;
}
void reset_fixture(void)
{
	g_retain = FALSE;
	g_up_result = TRUE;
	g_mtu_result = TRUE;
	g_up_calls = 0;
	g_mtu_calls = 0;
	g_destroy_calls = 0;
	g_published = 0;
	g_tun_fd = -1;
	g_receiver = -1;
	g_up_saw_datagram = 0;
	g_peer_closed = 0;
	g_libipsec_initialized = 0;
}

void reserve_fd3(void)
{
	int fd = open("/dev/null", O_RDONLY);

	if (fd < 0)
	{
		exit(2);
	}
	if (fd != 3 && dup2(fd, 3) != 3)
	{
		exit(2);
	}
	if (fd != 3)
	{
		close(fd);
	}
}

int make_dgram_pair(int sv[2])
{ return socketpair(AF_UNIX, SOCK_DGRAM, 0, sv); }

int make_stream_pair(int sv[2])
{ return socketpair(AF_UNIX, SOCK_STREAM, 0, sv); }

int make_tun_pipe(int pipefd[2])
{
	int result = pipe(pipefd);

	if (result == 0)
	{
		g_tun_fd = pipefd[0];
	}
	return result;
}

void install_channel(int fd)
{
	if (dup2(fd, 3) != 3)
	{
		exit(2);
	}
	fcntl(3, F_SETFD, 0);
}

void close_fd(int *fd)
{
	if (fd && *fd >= 0)
	{
		close(*fd);
		*fd = -1;
	}
}

int recv_handoff(int receiver, int *fd, unsigned char payload[8], int *fds,
				 int *ctrunc)
{
	struct msghdr message;
	struct iovec iov;
	unsigned char control[CMSG_SPACE(sizeof(int) * 4)];
	struct cmsghdr *cmsg;
	ssize_t length;
	int count = 0;

	if (fd) *fd = -1;
	if (fds) *fds = 0;
	memset(&message, 0, sizeof(message));
	iov.iov_base = payload;
	iov.iov_len = 8;
	message.msg_iov = &iov;
	message.msg_iovlen = 1;
	message.msg_control = control;
	message.msg_controllen = sizeof(control);
	length = recvmsg(receiver, &message, MSG_DONTWAIT);
	if (ctrunc) *ctrunc = (message.msg_flags & MSG_CTRUNC) != 0;
	if (length < 0) return -errno;
	for (cmsg = CMSG_FIRSTHDR(&message); cmsg;
		 cmsg = CMSG_NXTHDR(&message, cmsg))
	{
		if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS)
		{
			int *data = (int*)CMSG_DATA(cmsg);
			size_t total = (cmsg->cmsg_len - CMSG_LEN(0)) / sizeof(int);
			size_t index;
			for (index = 0; index < total; index++)
			{
				if (count == 0 && fd) *fd = data[index];
				else close(data[index]);
				count++;
			}
		}
	}
	if (fds) *fds = count;
	return (int)length;
}

static void setup_globals(void)
{
	settings.get_bool = fixture_get_bool;
	settings.set_str = fixture_set_str;
	caps.check = fixture_caps_check;
	library.set = fixture_lib_set;
	library.ns = "fixture";
	library.settings = &settings;
	library.caps = &caps;
	bus_stub.log = fixture_bus_log;
	daemon_stub.bus = &bus_stub;
	lib = &library;
	charon = &daemon_stub;
}

int main(int argc, char **argv)
{
	struct { const char *name; int (*run)(void); } tests[] = {
		{ "default_off_leaves_channel_untouched", test_default_off },
		{ "enabled_sends_after_up_once", test_enabled_success },
		{ "stream_channel_fails_before_publication", test_stream_channel },
		{ "non_unix_channel_fails_before_publication", test_non_unix_channel },
		{ "closed_channel_fails_before_publication", test_closed_channel },
		{ "peer_closed_send_failure_destroys", test_peer_closed },
		{ "up_failure_sends_nothing", test_up_failure },
		{ "mtu_failure_sends_nothing", test_mtu_failure },
	};
	size_t index;
	int failures = 0;

	setup_globals();
	for (index = 0; index < sizeof(tests) / sizeof(tests[0]); index++)
	{
		if (argc > 1 && strcmp(argv[1], tests[index].name) != 0)
		{
			continue;
		}
		g_test = tests[index].name;
		if (tests[index].run())
		{
			failures++;
		}
		else
		{
			printf("ok %s\n", tests[index].name);
		}
	}
	return failures ? 1 : 0;
}
