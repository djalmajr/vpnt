#ifndef VPNT_PROTECTED_UDP_PERMANENT_GATE_H
#define VPNT_PROTECTED_UDP_PERMANENT_GATE_H

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

extern bool g_protect;
extern int g_ifindex;
extern int g_policy_fail;
extern int g_bypass_calls;
extern int g_boundif_calls;
extern int g_boundif_index;
extern int g_boundif_level;
extern int g_boundif_opt;
extern int g_policy_count;
extern int g_bind_calls;
extern int g_bind_order;
extern int g_close_count;
extern int g_closed_fds[8];
extern int g_order;
extern int g_notrun;
extern const char *g_test;

struct vpnt_policy_record {
	int fd;
	int family;
	int dir;
	int type;
	int exttype;
	int len;
	int order;
};
extern struct vpnt_policy_record g_policies[8];

void reset_fixture(void);
void fixture_init(void);
int fixture_open_socket(int family, uint16_t *port);

int test_default_off(void);
int test_protected_ipv4(void);
int test_protected_ipv6(void);
int test_invalid_index(void);
int test_boundif_failure(void);
int test_outbound_failure(void);
int test_inbound_failure(void);

#define CHECK(cond) do { if (!(cond)) { \
	fprintf(stderr, "FAIL %s: %s (line %d)\n", g_test, #cond, __LINE__); \
	return 1; } } while (0)

#endif
