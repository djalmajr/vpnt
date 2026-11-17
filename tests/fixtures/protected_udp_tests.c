/* Focused tests for the patched whole socket-default TU; ordinary UDP loopback. */
#include <net/if.h>
#include <net/pfkeyv2.h>
#include <netinet/in.h>
#include <netinet6/ipsec.h>
#include <sys/socket.h>

#include "protected_udp.h"

#include <fcntl.h>
#include <string.h>
#include <unistd.h>

static int ipv6_available(void)
{
	int fd = socket(AF_INET6, SOCK_DGRAM, 0);

	if (fd < 0)
	{
		return 0;
	}
	close(fd);
	return 1;
}

static int test_ifindex(void)
{
	unsigned int index = if_nametoindex("lo0");

	if (!index)
	{
		index = if_nametoindex("en0");
	}
	return (int)index;
}

static int check_protected(int family)
{
	uint16_t port = 0;
	int fd, index = test_ifindex();
	int expected_policy = family == AF_INET ? 2 : 2;

	CHECK(index > 0);
	reset_fixture();
	g_protect = true;
	g_ifindex = index;
	fd = fixture_open_socket(family, &port);
	CHECK(fd >= 0);
	CHECK((fcntl(fd, F_GETFD) & FD_CLOEXEC) != 0);
	CHECK(g_bypass_calls == 0);
	CHECK(g_boundif_calls == 1);
	CHECK(g_boundif_index == index);
	CHECK(g_boundif_level == (family == AF_INET ? IPPROTO_IP : IPPROTO_IPV6));
	CHECK(g_boundif_opt == (family == AF_INET ? IP_BOUND_IF : IPV6_BOUND_IF));
	CHECK(g_policy_count == expected_policy);
	CHECK(g_bind_calls == 1);
	CHECK(g_policies[0].fd == fd && g_policies[1].fd == fd);
	CHECK(g_policies[0].family == family && g_policies[1].family == family);
	CHECK(g_policies[0].dir == IPSEC_DIR_OUTBOUND);
	CHECK(g_policies[1].dir == IPSEC_DIR_INBOUND);
	CHECK(g_policies[0].type == IPSEC_POLICY_BYPASS);
	CHECK(g_policies[1].type == IPSEC_POLICY_BYPASS);
	CHECK(g_policies[0].exttype == SADB_X_EXT_POLICY);
	CHECK(g_policies[1].exttype == SADB_X_EXT_POLICY);
	CHECK(g_policies[0].len == (int)(sizeof(struct sadb_x_policy) / sizeof(uint64_t)));
	CHECK(g_policies[1].len == (int)(sizeof(struct sadb_x_policy) / sizeof(uint64_t)));
	CHECK(g_policies[0].order < g_bind_order);
	CHECK(g_policies[1].order < g_bind_order);
	close(fd);
	return 0;
}

int test_default_off(void)
{
	uint16_t port = 0;
	int fd;

	reset_fixture();
	g_protect = false;
	fd = fixture_open_socket(AF_INET, &port);
	CHECK(fd >= 0);
	CHECK((fcntl(fd, F_GETFD) & FD_CLOEXEC) == 0);
	CHECK(g_bypass_calls == 1);
	CHECK(g_boundif_calls == 0);
	CHECK(g_policy_count == 0);
	CHECK(g_bind_calls == 1);
	close(fd);
	if (ipv6_available())
	{
		port = 0;
		reset_fixture();
		g_protect = false;
		fd = fixture_open_socket(AF_INET6, &port);
		CHECK(fd >= 0);
		CHECK((fcntl(fd, F_GETFD) & FD_CLOEXEC) == 0);
		CHECK(g_bypass_calls == 1);
		CHECK(g_boundif_calls == 0);
		CHECK(g_policy_count == 0);
		close(fd);
	}
	return 0;
}

int test_protected_ipv4(void)
{
	return check_protected(AF_INET);
}

int test_protected_ipv6(void)
{
	if (!ipv6_available())
	{
		printf("NOTRUN protected_ipv6: IPv6 unavailable\n");
		g_notrun = 1;
		return 0;
	}
	return check_protected(AF_INET6);
}

int test_invalid_index(void)
{
	static const int values[] = { 0, -1, 65536 };
	size_t i;
	uint16_t port;

	for (i = 0; i < sizeof(values) / sizeof(values[0]); i++)
	{
		port = 0;
		reset_fixture();
		g_protect = true;
		g_ifindex = values[i];
		CHECK(fixture_open_socket(AF_INET, &port) == -1);
		CHECK(g_policy_count == 0);
		CHECK(g_boundif_calls == 0);
		CHECK(g_bind_calls == 0);
		CHECK(g_close_count == 1);
		CHECK(fcntl(g_closed_fds[0], F_GETFD) < 0);
	}
	return 0;
}

int test_boundif_failure(void)
{
	uint16_t port = 0;

	reset_fixture();
	g_protect = true;
	g_ifindex = 65000; /* in range, but not an interface */
	CHECK(fixture_open_socket(AF_INET, &port) == -1);
	CHECK(g_boundif_calls == 1);
	CHECK(g_boundif_index == 65000);
	CHECK(g_policy_count == 0);
	CHECK(g_bind_calls == 0);
	CHECK(g_close_count == 1);
	CHECK(fcntl(g_closed_fds[0], F_GETFD) < 0);
	return 0;
}

int test_outbound_failure(void)
{
	uint16_t port = 0;
	int index = test_ifindex();

	CHECK(index > 0);
	reset_fixture();
	g_protect = true;
	g_ifindex = index;
	g_policy_fail = IPSEC_DIR_OUTBOUND;
	CHECK(fixture_open_socket(AF_INET, &port) == -1);
	CHECK(g_policy_count == 1);
	CHECK(g_policies[0].dir == IPSEC_DIR_OUTBOUND);
	CHECK(g_bind_calls == 0);
	CHECK(g_close_count == 1);
	CHECK(fcntl(g_closed_fds[0], F_GETFD) < 0);
	return 0;
}

int test_inbound_failure(void)
{
	uint16_t port = 0;
	int index = test_ifindex();

	CHECK(index > 0);
	reset_fixture();
	g_protect = true;
	g_ifindex = index;
	g_policy_fail = IPSEC_DIR_INBOUND;
	CHECK(fixture_open_socket(AF_INET, &port) == -1);
	CHECK(g_policy_count == 2);
	CHECK(g_policies[0].dir == IPSEC_DIR_OUTBOUND);
	CHECK(g_policies[1].dir == IPSEC_DIR_INBOUND);
	CHECK(g_bind_calls == 0);
	CHECK(g_close_count == 1);
	CHECK(fcntl(g_closed_fds[0], F_GETFD) < 0);
	return 0;
}

int main(int argc, char **argv)
{
	struct { const char *name; int (*run)(void); } tests[] = {
		{ "default_off_preserves_upstream", test_default_off },
		{ "protected_ipv4", test_protected_ipv4 },
		{ "protected_ipv6", test_protected_ipv6 },
		{ "invalid_index_matrix", test_invalid_index },
		{ "boundif_failure", test_boundif_failure },
		{ "outbound_policy_failure", test_outbound_failure },
		{ "inbound_policy_failure", test_inbound_failure },
	};
	size_t index;
	int failures = 0;

	fixture_init();
	for (index = 0; index < sizeof(tests) / sizeof(tests[0]); index++)
	{
		if (argc > 1 && strcmp(argv[1], tests[index].name) != 0)
		{
			continue;
		}
		g_test = tests[index].name;
		g_notrun = 0;
		if (tests[index].run())
		{
			failures++;
		}
		else if (g_notrun)
		{
			printf("NOTRUN %s\n", tests[index].name);
		}
		else
		{
			printf("ok %s\n", tests[index].name);
		}
	}
	return failures ? 1 : 0;
}
