/*
 * Boundary and hostile-frame cases for the VPT-29 local-IPCP scope helper, on
 * top of local_ipcp_scope.c. Pure and synthetic (no gateway, no pppd, no
 * privileges, no sockets). It links the production helper
 * src/vpnt_ipcp_policy.c of the source tree prepared by the Arch PKGBUILD and
 * is built with the address and undefined-behaviour sanitizers by
 * scripts/linux/check-openfortivpn-local-cidr.sh, so an option that reads past
 * the frame fails here even when the bytes beyond happen to look harmless.
 *
 * Every frame is copied into its own heap buffer of exactly its length before
 * it is inspected, so the sanitizer sees the real frame boundary.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "vpnt_ipcp_policy.h"

static int checks;
static int failures;

static void report(bool ok, const char *label, const char *detail)
{
	checks++;
	if (!ok)
		failures++;
	printf("%s %s: %s\n", ok ? "PASS" : "FAIL", label, detail);
}

static const char *yn(bool value)
{
	return value ? "true" : "false";
}

static bool allows_exact(const struct vpnt_ipcp_local_scope *scope,
			 const uint8_t *frame, size_t len)
{
	uint8_t *copy = malloc(len ? len : 1);
	bool allowed;

	if (!copy) {
		fprintf(stderr, "out of memory\n");
		exit(2);
	}
	if (len)
		memcpy(copy, frame, len);
	allowed = vpnt_ipcp_local_scope_allows(scope, copy, len);
	free(copy);
	return allowed;
}

static void parse_case(const char *text, bool valid, uint32_t network,
		       unsigned prefix)
{
	struct vpnt_ipcp_local_scope scope = { 0, 0 };
	bool got = vpnt_ipcp_local_scope_parse(text, &scope);
	char detail[160];

	snprintf(detail, sizeof(detail), "text=\"%s\" expected=%s got=%s", text,
		 yn(valid), yn(got));
	report(got == valid, "parse", detail);
	if (valid && got) {
		snprintf(detail, sizeof(detail),
			 "text=\"%s\" network=0x%08x prefix=%u", text,
			 (unsigned)scope.network, (unsigned)scope.prefix);
		report(scope.network == network && scope.prefix == prefix,
		       "parse value", detail);
	}
	if (!valid) {
		snprintf(detail, sizeof(detail),
			 "text=\"%s\" left the scope untouched", text);
		report(scope.network == 0 && scope.prefix == 0, "parse reject",
		       detail);
	}
}

static void frame_case(const struct vpnt_ipcp_local_scope *scope,
		       const char *label, const uint8_t *frame, size_t len,
		       bool expected)
{
	bool got = allows_exact(scope, frame, len);
	char detail[160];

	snprintf(detail, sizeof(detail), "expected=%s got=%s bytes=%zu",
		 yn(expected), yn(got), len);
	report(got == expected, label, detail);
}

#define FRAME(name, ...) static const uint8_t name[] = { __VA_ARGS__ }
#define CASE(scope, name, expected) \
	frame_case(scope, #name, name, sizeof(name), expected)

/* Duplicated or mixed address options: ambiguous, never a local offer. */
FRAME(two_legacy_options, 0x80, 0x21, 0x02, 0x01, 0x00, 0x18,
      0x01, 0x0a, 10, 20, 30, 7, 169, 254, 2, 1,
      0x01, 0x0a, 10, 20, 30, 7, 169, 254, 2, 1);
FRAME(modern_then_legacy, 0x80, 0x21, 0x02, 0x02, 0x00, 0x14,
      0x03, 0x06, 10, 20, 30, 7,
      0x01, 0x0a, 10, 20, 30, 7, 169, 254, 2, 1);
FRAME(legacy_then_modern, 0x80, 0x21, 0x03, 0x03, 0x00, 0x14,
      0x01, 0x0a, 10, 20, 30, 7, 169, 254, 2, 1,
      0x03, 0x06, 10, 20, 30, 7);
/* An address in scope followed by a malformed option: the whole frame fails. */
FRAME(address_then_malformed_dns, 0x80, 0x21, 0x02, 0x04, 0x00, 0x0f,
      0x03, 0x06, 10, 20, 30, 7, 0x81, 0x05, 192, 0, 2);

/* Option framing. */
FRAME(option_length_zero, 0x80, 0x21, 0x01, 0x05, 0x00, 0x08,
      0x03, 0x00, 10, 20);
FRAME(option_length_one, 0x80, 0x21, 0x01, 0x06, 0x00, 0x08,
      0x03, 0x01, 10, 20);
FRAME(lone_option_type_byte, 0x80, 0x21, 0x01, 0x07, 0x00, 0x05, 0x03);
FRAME(modern_overruns_by_one, 0x80, 0x21, 0x02, 0x08, 0x00, 0x09,
      0x03, 0x06, 10, 20, 30);
FRAME(legacy_overruns_by_one, 0x80, 0x21, 0x02, 0x09, 0x00, 0x0d,
      0x01, 0x0a, 10, 20, 30, 7, 169, 254, 2);
FRAME(legacy_wrong_length, 0x80, 0x21, 0x02, 0x0a, 0x00, 0x0c,
      0x01, 0x08, 10, 20, 30, 7, 169, 254);
FRAME(dns_wrong_length, 0x80, 0x21, 0x02, 0x0b, 0x00, 0x09,
      0x81, 0x05, 192, 0, 2);
FRAME(unknown_option_then_in_scope, 0x80, 0x21, 0x02, 0x0c, 0x00, 0x0c,
      0x7e, 0x02, 0x03, 0x06, 10, 20, 30, 7);
FRAME(unknown_option_then_outside, 0x80, 0x21, 0x02, 0x0d, 0x00, 0x0c,
      0x7e, 0x02, 0x03, 0x06, 203, 0, 113, 9);
FRAME(empty_confreq, 0x80, 0x21, 0x01, 0x0e, 0x00, 0x04);
FRAME(ipcp_length_below_header, 0x80, 0x21, 0x01, 0x0f, 0x00, 0x03);
FRAME(ipcp_length_beyond_frame, 0x80, 0x21, 0x01, 0x10, 0x00, 0x20);
FRAME(header_only_three_bytes, 0x80, 0x21, 0x01);

/* Frames that are not IPCP address negotiation pass unchanged. */
FRAME(conf_reject_is_not_an_offer, 0x80, 0x21, 0x04, 0x11, 0x00, 0x0a,
      0x03, 0x06, 203, 0, 113, 9);
FRAME(terminate_request, 0x80, 0x21, 0x05, 0x12, 0x00, 0x04);
FRAME(ip_datagram_compressed_protocol, 0x21, 0x45, 0x00, 0x00, 0x14);
FRAME(ip_datagram_full_protocol, 0x00, 0x21, 0x45, 0x00, 0x00, 0x14);
FRAME(ipv6cp, 0x80, 0x57, 0x01, 0x13, 0x00, 0x04);
FRAME(lcp_with_address_like_bytes, 0xc0, 0x21, 0x01, 0x14, 0x00, 0x0a,
      0x03, 0x06, 203, 0, 113, 9);
/* HDLC Address/Control never reach this layer; do not guess past them. */
FRAME(hdlc_address_control_prefix, 0xff, 0x03, 0x80, 0x21, 0x02, 0x15,
      0x00, 0x0a, 0x03, 0x06, 203, 0, 113, 9);
FRAME(protocol_second_byte_even, 0x80, 0x20, 0x01, 0x16, 0x00, 0x04);

/* ConfReq: CI_ADDR is the gateway's own address, outside the scope is fine. */
FRAME(confreq_modern_peer_outside, 0x80, 0x21, 0x01, 0x17, 0x00, 0x0a,
      0x03, 0x06, 203, 0, 113, 9);
/* Legacy ConfReq with an unspecified destination address. */
FRAME(confreq_legacy_destination_zero, 0x80, 0x21, 0x01, 0x18, 0x00, 0x0e,
      0x01, 0x0a, 169, 254, 2, 1, 0, 0, 0, 0);
FRAME(confnak_modern_zero, 0x80, 0x21, 0x03, 0x19, 0x00, 0x0a,
      0x03, 0x06, 0, 0, 0, 0);
/* Addresses at the scope edge (10.20.30.0/24). */
FRAME(ack_first_address, 0x80, 0x21, 0x02, 0x1a, 0x00, 0x0a,
      0x03, 0x06, 10, 20, 30, 0);
FRAME(ack_last_address, 0x80, 0x21, 0x02, 0x1b, 0x00, 0x0a,
      0x03, 0x06, 10, 20, 30, 255);
FRAME(ack_below_scope, 0x80, 0x21, 0x02, 0x1c, 0x00, 0x0a,
      0x03, 0x06, 10, 20, 29, 255);
FRAME(ack_above_scope, 0x80, 0x21, 0x02, 0x1d, 0x00, 0x0a,
      0x03, 0x06, 10, 20, 31, 0);
FRAME(nak_edge_outside_after_ack, 0x80, 0x21, 0x03, 0x1e, 0x00, 0x0a,
      0x03, 0x06, 10, 20, 31, 7);

/* The accepted local address and DNS are the ones the client must use. */
FRAME(ack_with_dns, 0x80, 0x21, 0x02, 0x1f, 0x00, 0x16,
      0x03, 0x06, 10, 20, 30, 7, 0x81, 0x06, 192, 0, 2, 1,
      0x83, 0x06, 192, 0, 2, 2);
FRAME(ack_legacy_with_dns, 0x80, 0x21, 0x02, 0x20, 0x00, 0x14,
      0x01, 0x0a, 10, 20, 30, 7, 169, 254, 2, 1,
      0x81, 0x06, 192, 0, 2, 1);
FRAME(nak_with_dns, 0x80, 0x21, 0x03, 0x21, 0x00, 0x10,
      0x03, 0x06, 10, 20, 30, 7, 0x81, 0x06, 192, 0, 2, 1);

static void check_ack(const struct vpnt_ipcp_local_scope *scope)
{
	struct vpnt_ipcp_ack ack;
	uint8_t *copy;
	char detail[160];

	copy = malloc(sizeof(ack_with_dns));
	memcpy(copy, ack_with_dns, sizeof(ack_with_dns));
	memset(&ack, 0xaa, sizeof(ack));
	snprintf(detail, sizeof(detail), "ConfAck, modern, with DNS");
	report(vpnt_ipcp_check(scope, copy, sizeof(ack_with_dns), &ack) &&
	       ack.local == 0x0a141e07u && ack.dns1 == 0xc0000201u &&
	       ack.dns2 == 0xc0000202u, "ack values", detail);
	free(copy);

	copy = malloc(sizeof(ack_legacy_with_dns));
	memcpy(copy, ack_legacy_with_dns, sizeof(ack_legacy_with_dns));
	memset(&ack, 0xaa, sizeof(ack));
	snprintf(detail, sizeof(detail), "ConfAck, legacy, one DNS");
	report(vpnt_ipcp_check(scope, copy, sizeof(ack_legacy_with_dns), &ack) &&
	       ack.local == 0x0a141e07u && ack.dns1 == 0xc0000201u &&
	       ack.dns2 == 0, "ack values legacy", detail);
	free(copy);

	/* Only a ConfAck commits an address; a ConfNak is a suggestion. */
	copy = malloc(sizeof(nak_with_dns));
	memcpy(copy, nak_with_dns, sizeof(nak_with_dns));
	memset(&ack, 0xaa, sizeof(ack));
	snprintf(detail, sizeof(detail), "ConfNak commits nothing");
	report(vpnt_ipcp_check(scope, copy, sizeof(nak_with_dns), &ack) &&
	       ack.local == 0 && ack.dns1 == 0 && ack.dns2 == 0,
	       "nak commits nothing", detail);
	free(copy);

	/* A refused frame must not leave a half-parsed result behind. */
	copy = malloc(sizeof(ack_above_scope));
	memcpy(copy, ack_above_scope, sizeof(ack_above_scope));
	memset(&ack, 0xaa, sizeof(ack));
	snprintf(detail, sizeof(detail), "refused frame clears the result");
	report(!vpnt_ipcp_check(scope, copy, sizeof(ack_above_scope), &ack) &&
	       ack.local == 0 && ack.dns1 == 0 && ack.dns2 == 0,
	       "refusal clears result", detail);
	free(copy);
}

int main(void)
{
	struct vpnt_ipcp_local_scope scope24 = { 0, 0 };
	struct vpnt_ipcp_local_scope scope8 = { 0, 0 };
	struct vpnt_ipcp_local_scope none = { 0, 0 };
	struct vpnt_ipcp_local_scope too_long = { 0x0a141e00u, 33 };

	printf("fixture: local_ipcp_scope_boundaries (production API only)\n");

	/* Prefix boundaries 8..32 and the shapes the policy refuses. */
	parse_case("10.0.0.0/8", true, 0x0a000000u, 8);
	parse_case("10.20.0.0/16", true, 0x0a140000u, 16);
	parse_case("10.0.0.0/32", true, 0x0a000000u, 32);
	parse_case("9.255.255.255/32", true, 0x09ffffffu, 32);
	parse_case("169.253.0.0/16", true, 0xa9fd0000u, 16);
	parse_case("8.0.0.0/7", false, 0, 0);
	parse_case("10.0.0.0/0", false, 0, 0);
	parse_case("10.0.0.0/08", false, 0, 0);
	parse_case("10.0.0.0/ 8", false, 0, 0);
	parse_case("10.0.0.0/+8", false, 0, 0);
	parse_case("10.0.0.0/8 ", false, 0, 0);
	parse_case(" 10.0.0.0/8", false, 0, 0);
	parse_case("10.0.0.0/100", false, 0, 0);
	parse_case("10.0.0.0//8", false, 0, 0);
	parse_case("/8", false, 0, 0);
	parse_case("10.0.0/8", false, 0, 0);
	parse_case("10.0.0.0.0/8", false, 0, 0);
	parse_case("010.0.0.0/8", false, 0, 0);
	parse_case("::1/8", false, 0, 0);
	parse_case("10.0.0.0/8\n", false, 0, 0);
	parse_case("0.0.0.0/8", false, 0, 0);
	parse_case("0.0.0.0/32", false, 0, 0);
	parse_case("127.0.0.0/8", false, 0, 0);
	parse_case("127.0.0.1/32", false, 0, 0);
	parse_case("169.254.0.0/16", false, 0, 0);
	parse_case("169.254.2.1/32", false, 0, 0);
	parse_case("224.1.0.0/16", false, 0, 0);
	parse_case("240.0.0.0/8", false, 0, 0);
	parse_case("255.255.255.255/32", false, 0, 0);

	if (!vpnt_ipcp_local_scope_parse("10.20.30.0/24", &scope24) ||
	    !vpnt_ipcp_local_scope_parse("10.0.0.0/8", &scope8)) {
		report(false, "scope setup", "could not parse the fixture scopes");
		printf("checks=%d failures=%d\n", checks, failures);
		return 1;
	}

	CASE(&scope24, two_legacy_options, false);
	CASE(&scope24, modern_then_legacy, false);
	CASE(&scope24, legacy_then_modern, false);
	CASE(&scope24, address_then_malformed_dns, false);
	CASE(&scope24, option_length_zero, false);
	CASE(&scope24, option_length_one, false);
	CASE(&scope24, lone_option_type_byte, false);
	CASE(&scope24, modern_overruns_by_one, false);
	CASE(&scope24, legacy_overruns_by_one, false);
	CASE(&scope24, legacy_wrong_length, false);
	CASE(&scope24, dns_wrong_length, false);
	CASE(&scope24, unknown_option_then_in_scope, true);
	CASE(&scope24, unknown_option_then_outside, false);
	CASE(&scope24, empty_confreq, true);
	CASE(&scope24, ipcp_length_below_header, false);
	CASE(&scope24, ipcp_length_beyond_frame, false);
	CASE(&scope24, header_only_three_bytes, false);
	CASE(&scope24, conf_reject_is_not_an_offer, true);
	CASE(&scope24, terminate_request, true);
	CASE(&scope24, ip_datagram_compressed_protocol, true);
	CASE(&scope24, ip_datagram_full_protocol, true);
	CASE(&scope24, ipv6cp, true);
	CASE(&scope24, lcp_with_address_like_bytes, true);
	CASE(&scope24, hdlc_address_control_prefix, false);
	CASE(&scope24, protocol_second_byte_even, false);
	CASE(&scope24, confreq_modern_peer_outside, true);
	CASE(&scope24, confreq_legacy_destination_zero, false);
	CASE(&scope24, confnak_modern_zero, false);
	CASE(&scope24, ack_first_address, true);
	CASE(&scope24, ack_last_address, true);
	CASE(&scope24, ack_below_scope, false);
	CASE(&scope24, ack_above_scope, false);
	CASE(&scope24, nak_edge_outside_after_ack, false);
	CASE(&scope8, ack_below_scope, true);
	CASE(&scope8, ack_with_dns, true);

	/* An unset or corrupt scope authorizes no local address at all. */
	CASE(&none, ack_with_dns, false);
	CASE(&none, ack_legacy_with_dns, false);
	CASE(&none, nak_with_dns, false);
	CASE(&none, empty_confreq, true);
	CASE(&none, ip_datagram_compressed_protocol, true);
	CASE(&too_long, ack_with_dns, false);

	check_ack(&scope24);

	printf("checks=%d failures=%d\n", checks, failures);
	if (failures == 0) {
		printf("RESULT: all boundary cases behave as required\n");
		return 0;
	}
	printf("RESULT: %d boundary case(s) failed\n", failures);
	return 1;
}
