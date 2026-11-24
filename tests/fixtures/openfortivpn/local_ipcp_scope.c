/*
 * Pure fixture for the VPT-29 local-IPCP scope helper (no gateway, no pppd,
 * no privileges, no sockets). It uses only the production API declared in
 * src/vpnt_ipcp_policy.h and linked from src/vpnt_ipcp_policy.c of the source
 * tree prepared by the Arch PKGBUILD.
 *
 * IPCP layout (pppd v2.5.4): the buffer starts at the 2-octet PPP Protocol
 * field (0x8021), followed by code, id, big-endian length and options.
 * The option lengths include the type and length bytes. CI_ADDRS is 10
 * bytes; its first address belongs to the Configure-Request sender.
 * CI_ADDR is 6 bytes; in a gateway Configure-Request it is the gateway's
 * own address. A gateway Configure-Ack or Configure-Nak refers to our request.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "vpnt_ipcp_policy.h"

struct parse_case {
	const char *text;
	uint32_t network; /* host byte order, per the contract */
	uint8_t prefix;
	bool valid;
};

struct frame_case {
	const char *label;
	const uint8_t *data;
	size_t len;
	bool expected;
};

/* Modern CI_ADDR: technical peer in ConfReq, local address in Ack/Nak. */
static const uint8_t req_modern_peer[] = {
	0x80, 0x21, 0x01, 0x2a, 0x00, 0x0a, 0x03, 0x06, 169, 254, 2, 1
};
static const uint8_t ack_modern_in[] = {
	0x80, 0x21, 0x02, 0x2b, 0x00, 0x0a, 0x03, 0x06, 10, 20, 30, 7
};
static const uint8_t nak_modern_in[] = {
	0x80, 0x21, 0x03, 0x2c, 0x00, 0x0a, 0x03, 0x06, 10, 20, 30, 7
};

/* Legacy CI_ADDRS: its address order depends on the request sender. */
static const uint8_t req_legacy_in[] = {
	0x80, 0x21, 0x01, 0x2d, 0x00, 0x0e, 0x01, 0x0a,
	169, 254, 2, 1, 10, 20, 30, 7
};
static const uint8_t ack_legacy_in[] = {
	0x80, 0x21, 0x02, 0x2e, 0x00, 0x0e, 0x01, 0x0a,
	10, 20, 30, 7, 169, 254, 2, 1
};
static const uint8_t nak_legacy_in[] = {
	0x80, 0x21, 0x03, 0x2f, 0x00, 0x0e, 0x01, 0x0a,
	10, 20, 30, 7, 169, 254, 2, 1
};

/* Allocated address outside 10.20.30.0/24. */
static const uint8_t ack_modern_out[] = {
	0x80, 0x21, 0x02, 0x30, 0x00, 0x0a, 0x03, 0x06, 203, 0, 113, 9
};
static const uint8_t nak_modern_out[] = {
	0x80, 0x21, 0x03, 0x31, 0x00, 0x0a, 0x03, 0x06, 203, 0, 113, 9
};
static const uint8_t req_legacy_out[] = {
	0x80, 0x21, 0x01, 0x32, 0x00, 0x0e, 0x01, 0x0a,
	169, 254, 2, 1, 203, 0, 113, 9
};
static const uint8_t ack_legacy_out[] = {
	0x80, 0x21, 0x02, 0x33, 0x00, 0x0e, 0x01, 0x0a,
	203, 0, 113, 9, 169, 254, 2, 1
};

static const uint8_t nak_legacy_out[] = {
	0x80, 0x21, 0x03, 0x3d, 0x00, 0x0e, 0x01, 0x0a,
	203, 0, 113, 9, 10, 20, 30, 7
};

/* The legacy peer field is inside the scope; the local field is not. */
static const uint8_t req_legacy_peer_inside[] = {
	0x80, 0x21, 0x01, 0x34, 0x00, 0x0e, 0x01, 0x0a,
	10, 20, 30, 7, 203, 0, 113, 9
};

/* Neighbour of the exact /32 and neighbour of the /24. */
static const uint8_t ack_modern_neighbour32[] = {
	0x80, 0x21, 0x02, 0x35, 0x00, 0x0a, 0x03, 0x06, 10, 20, 30, 8
};
static const uint8_t ack_modern_neighbour24[] = {
	0x80, 0x21, 0x02, 0x36, 0x00, 0x0a, 0x03, 0x06, 10, 20, 31, 7
};

/* Traffic that does not change the local address must pass unchanged. */
static const uint8_t dns_only[] = {
	0x80, 0x21, 0x01, 0x37, 0x00, 0x0a, 0x81, 0x06, 192, 0, 2, 1
};
static const uint8_t lcp_echo[] = {
	0xc0, 0x21, 0x09, 0x01, 0x00, 0x08, 0x12, 0x34, 0x56, 0x78
};

/* Ambiguous or malformed IPCP must not be mistaken for an allowed local. */
static const uint8_t truncated_option[] = {
	0x80, 0x21, 0x01, 0x38, 0x00, 0x0a, 0x03, 0x06, 10, 20
};
static const uint8_t length_mismatch[] = {
	0x80, 0x21, 0x01, 0x39, 0x00, 0x0c, 0x01, 0x0a,
	169, 254, 2, 1, 10, 20, 30, 7
};
static const uint8_t two_local_options[] = {
	0x80, 0x21, 0x02, 0x3a, 0x00, 0x10,
	0x03, 0x06, 10, 20, 30, 7, 0x03, 0x06, 10, 20, 30, 7
};
static const uint8_t bad_option_length[] = {
	0x80, 0x21, 0x01, 0x3b, 0x00, 0x09, 0x03, 0x05, 10, 20, 30, 7, 0
};
static const uint8_t short_frame[] = { 0x80, 0x21, 0x01, 0x3c };

static int checks;
static int failures;

static void report(bool ok, const char *label, const char *detail)
{
	checks++;
	if (ok) {
		printf("PASS %s: %s\n", label, detail);
		return;
	}
	failures++;
	printf("FAIL %s: %s\n", label, detail);
}

static const char *yn(bool value)
{
	return value ? "true" : "false";
}

static void check_parse(void)
{
	static const struct parse_case cases[] = {
		{ "10.20.30.0/24", 0x0a141e00u, 24, true },
		{ "10.20.30.7/32", 0x0a141e07u, 32, true },
		{ "10.20.30.1/24", 0, 0, false }, /* host bits set */
		{ "10.20.30.0/33", 0, 0, false },
		{ "10.20.30.0/-1", 0, 0, false },
		{ "999.20.30.0/24", 0, 0, false },
		{ "10.20.30.0", 0, 0, false },
		{ "10.20.30.0/24junk", 0, 0, false },
		{ "", 0, 0, false },
	};
	size_t i;

	for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		struct vpnt_ipcp_local_scope scope = { 0, 0 };
		bool got = vpnt_ipcp_local_scope_parse(cases[i].text, &scope);
		char detail[192];
		char label[96];

		snprintf(label, sizeof(label), "parse %zu", i + 1);
		snprintf(detail, sizeof(detail), "text=%s expected=%s got=%s",
			 cases[i].text, yn(cases[i].valid), yn(got));
		report(got == cases[i].valid, label, detail);
		if (cases[i].valid && got) {
			snprintf(detail, sizeof(detail),
				 "text=%s network=0x%08x expected=0x%08x prefix=%u expected=%u",
				 cases[i].text, (unsigned)scope.network,
				 (unsigned)cases[i].network, (unsigned)scope.prefix,
				 (unsigned)cases[i].prefix);
			report(scope.network == cases[i].network &&
			       scope.prefix == cases[i].prefix, label, detail);
		}
	}
}

static void check_allows(const struct vpnt_ipcp_local_scope *scope,
			 const char *scope_text, const struct frame_case *cases,
			 size_t count)
{
	size_t i;

	for (i = 0; i < count; i++) {
		bool got = vpnt_ipcp_local_scope_allows(scope, cases[i].data,
							 cases[i].len);
		char detail[192];

		snprintf(detail, sizeof(detail),
			 "scope=%s expected=%s got=%s bytes=%zu", scope_text,
			 yn(cases[i].expected), yn(got), cases[i].len);
		report(got == cases[i].expected, cases[i].label, detail);
	}
}

int main(void)
{
	static const struct frame_case frames24[] = {
		{ "modern ConfReq, technical peer is not a local offer", req_modern_peer,
		  sizeof(req_modern_peer), true },
		{ "modern ConfAck, local in scope", ack_modern_in,
		  sizeof(ack_modern_in), true },
		{ "modern ConfNak, local in scope", nak_modern_in,
		  sizeof(nak_modern_in), true },
		{ "legacy ConfReq, local at ciaddr2", req_legacy_in,
		  sizeof(req_legacy_in), true },
		{ "legacy ConfAck, local at ciaddr1", ack_legacy_in,
		  sizeof(ack_legacy_in), true },
		{ "legacy ConfNak, local at ciaddr1", nak_legacy_in,
		  sizeof(nak_legacy_in), true },
		{ "modern ConfAck, local outside", ack_modern_out,
		  sizeof(ack_modern_out), false },
		{ "modern ConfNak, local outside", nak_modern_out,
		  sizeof(nak_modern_out), false },
		{ "legacy ConfReq, local outside", req_legacy_out,
		  sizeof(req_legacy_out), false },
		{ "legacy ConfAck, local outside", ack_legacy_out,
		  sizeof(ack_legacy_out), false },
		{ "legacy ConfNak, peer inside / local outside", nak_legacy_out,
		  sizeof(nak_legacy_out), false },
		{ "legacy ConfReq, peer inside / local outside",
		  req_legacy_peer_inside, sizeof(req_legacy_peer_inside), false },
		{ "neighbour /24 outside", ack_modern_neighbour24,
		  sizeof(ack_modern_neighbour24), false },
		{ "DNS-only IPCP transit", dns_only, sizeof(dns_only), true },
		{ "LCP echo transit", lcp_echo, sizeof(lcp_echo), true },
		{ "truncated address option", truncated_option,
		  sizeof(truncated_option), false },
		{ "IPCP length mismatch", length_mismatch,
		  sizeof(length_mismatch), false },
		{ "two local candidates", two_local_options,
		  sizeof(two_local_options), false },
		{ "bad CI_ADDR length", bad_option_length,
		  sizeof(bad_option_length), false },
		{ "short frame", short_frame, sizeof(short_frame), false },
	};
	static const struct frame_case frames32[] = {
		{ "exact /32 accepts its address", ack_modern_in,
		  sizeof(ack_modern_in), true },
		{ "exact /32 refuses neighbour", ack_modern_neighbour32,
		  sizeof(ack_modern_neighbour32), false },
	};
	struct vpnt_ipcp_local_scope scope24 = { 0, 0 };
	struct vpnt_ipcp_local_scope scope32 = { 0, 0 };

	printf("fixture: local_ipcp_scope (production API only)\n");
	check_parse();
	if (vpnt_ipcp_local_scope_parse("10.20.30.0/24", &scope24)) {
		check_allows(&scope24, "10.20.30.0/24", frames24,
			     sizeof(frames24) / sizeof(frames24[0]));
	} else {
		report(false, "scope /24 setup", "parse(\"10.20.30.0/24\") returned false");
	}
	if (vpnt_ipcp_local_scope_parse("10.20.30.7/32", &scope32)) {
		check_allows(&scope32, "10.20.30.7/32", frames32,
			     sizeof(frames32) / sizeof(frames32[0]));
	} else {
		report(false, "scope /32 setup", "parse(\"10.20.30.7/32\") returned false");
	}
	printf("checks=%d failures=%d\n", checks, failures);
	if (failures == 0) {
		printf("RESULT: all cases behave as required\n");
		return 0;
	}
	printf("RESULT: %d case(s) failed\n", failures);
	return 1;
}
