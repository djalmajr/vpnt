/* Whole-TU fixture for the patched socket-default protected UDP candidate. */
#define _GNU_SOURCE
#define __APPLE_USE_RFC_3542
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/pfkeyv2.h>
#include <netinet6/ipsec.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <daemon.h>
#include <library.h>
#include <kernel/kernel_interface.h>
#include <settings/settings.h>
#include <utils/capabilities.h>

#include "protected_udp.h"

int vpnt_test_setsockopt(int, int, int, const void*, socklen_t);
int vpnt_test_bind(int, const struct sockaddr*, socklen_t);
int vpnt_test_close(int);
#define setsockopt vpnt_test_setsockopt
#define bind vpnt_test_bind
#define close vpnt_test_close
#include "socket_default_socket.c"
#undef setsockopt
#undef bind
#undef close

#undef strerror
const char *strerror_safe(int errnum)
{
	return strerror(errnum);
}

bool g_protect;
int g_ifindex, g_policy_fail, g_bypass_calls, g_boundif_calls, g_boundif_index;
int g_boundif_level, g_boundif_opt, g_policy_count, g_bind_calls, g_bind_order;
int g_close_count, g_order, g_notrun;
int g_closed_fds[8];
struct vpnt_policy_record g_policies[8];
const char *g_test = "?";

library_t *lib;
daemon_t *charon;
static settings_t settings;
static capabilities_t caps;
static library_t library;
static daemon_t daemon_stub;
static bus_t bus_stub;
static kernel_interface_t kernel_stub;

static void fixture_bus_log(bus_t *this, debug_t group, level_t level,
							char *format, ...)
{ (void)this; (void)group; (void)level; (void)format; }

static bool fixture_get_bool(settings_t *this, char *key, int def, ...)
{
	(void)this;
	if (strstr(key, "vpnt_protect_transport"))
	{
		return g_protect;
	}
	return def != 0;
}

static int fixture_get_int(settings_t *this, char *key, int def, ...)
{
	(void)this;
	if (strstr(key, "vpnt_ifindex"))
	{
		return g_ifindex;
	}
	return def;
}

static bool fixture_caps_check(capabilities_t *this, u_int cap)
{ (void)this; (void)cap; return TRUE; }

static bool fixture_bypass(kernel_interface_t *this, int fd, int family)
{ (void)this; (void)fd; (void)family; g_bypass_calls++; return TRUE; }

static bool fixture_decap(kernel_interface_t *this, int fd, int family, uint16_t port)
{ (void)this; (void)fd; (void)family; (void)port; return TRUE; }

int vpnt_test_setsockopt(int skt, int level, int opt, const void *value,
						 socklen_t len)
{
	if ((level == IPPROTO_IP && opt == IP_IPSEC_POLICY) ||
		(level == IPPROTO_IPV6 && opt == IPV6_IPSEC_POLICY))
	{
		const struct sadb_x_policy *policy = value;
		struct vpnt_policy_record *record;
		int index = g_policy_count++;

		if (!policy || len != sizeof(*policy) || index >= 8)
		{
			return -1;
		}
		record = &g_policies[index];
		record->fd = skt;
		record->family = level == IPPROTO_IP ? AF_INET : AF_INET6;
		record->dir = policy->sadb_x_policy_dir;
		record->type = policy->sadb_x_policy_type;
		record->exttype = policy->sadb_x_policy_exttype;
		record->len = policy->sadb_x_policy_len;
		record->order = ++g_order;
		if (g_policy_fail && policy->sadb_x_policy_dir == g_policy_fail)
		{
			return -1;
		}
		return 0; /* never install a real BYPASS */
	}
	if ((level == IPPROTO_IP && opt == IP_BOUND_IF) ||
		(level == IPPROTO_IPV6 && opt == IPV6_BOUND_IF))
	{
		if (value && len == sizeof(unsigned int))
		{
			g_boundif_index = *(const unsigned int*)value;
			g_boundif_level = level;
			g_boundif_opt = opt;
			g_boundif_calls++;
			(void)++g_order;
		}
	}
	return setsockopt(skt, level, opt, value, len);
}

int vpnt_test_bind(int skt, const struct sockaddr *address, socklen_t len)
{
	g_bind_calls++;
	g_bind_order = ++g_order;
	return bind(skt, address, len);
}

int vpnt_test_close(int fd)
{
	if (g_close_count < 8)
	{
		g_closed_fds[g_close_count] = fd;
	}
	g_close_count++;
	(void)++g_order;
	return close(fd);
}

int fixture_open_socket(int family, uint16_t *port)
{
	private_socket_default_socket_t state;

	memset(&state, 0, sizeof(state));
	return open_socket(&state, family, port);
}

void reset_fixture(void)
{
	g_protect = FALSE;
	g_ifindex = 1;
	g_policy_fail = 0;
	g_bypass_calls = 0;
	g_boundif_calls = 0;
	g_boundif_index = 0;
	g_boundif_level = 0;
	g_boundif_opt = 0;
	g_policy_count = 0;
	g_bind_calls = 0;
	g_bind_order = 0;
	g_close_count = 0;
	g_order = 0;
	g_notrun = 0;
	memset(g_closed_fds, 0, sizeof(g_closed_fds));
	memset(g_policies, 0, sizeof(g_policies));
}

void fixture_init(void)
{
	memset(&settings, 0, sizeof(settings));
	memset(&caps, 0, sizeof(caps));
	memset(&library, 0, sizeof(library));
	memset(&daemon_stub, 0, sizeof(daemon_stub));
	memset(&bus_stub, 0, sizeof(bus_stub));
	memset(&kernel_stub, 0, sizeof(kernel_stub));
	settings.get_bool = fixture_get_bool;
	settings.get_int = fixture_get_int;
	caps.check = fixture_caps_check;
	library.settings = &settings;
	library.caps = &caps;
	library.ns = "fixture";
	bus_stub.log = fixture_bus_log;
	kernel_stub.bypass_socket = fixture_bypass;
	kernel_stub.enable_udp_decap = fixture_decap;
	daemon_stub.bus = &bus_stub;
	daemon_stub.kernel = &kernel_stub;
	lib = &library;
	charon = &daemon_stub;
}
