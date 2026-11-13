/*
 * Synthetic SDK-struct cases for the production utun decoder, plus a child mode
 * used by the native own-child negative test.
 *
 * The production translation unit is included so these cases exercise the exact
 * static decode function and the exact public entry point; no test-only export
 * exists in the shim. The synthetic structs are built here, never by opening a
 * real utun or control socket.
 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>

#include "../../../native/utun_socket.c"

static int failures;

#define CHECK(condition)                                                       \
	do {                                                                    \
		if (!(condition)) {                                             \
			fprintf(stderr, "fail line %d: %s\n", __LINE__,          \
			    #condition);                                        \
			failures++;                                             \
		}                                                               \
	} while (0)

static struct socket_fdinfo utun_info(uint32_t unit)
{
	struct socket_fdinfo info;
	struct kern_ctl_info *ctl;

	memset(&info, 0, sizeof(info));
	info.psi.soi_family = AF_SYSTEM;
	info.psi.soi_type = SOCK_DGRAM;
	info.psi.soi_protocol = SYSPROTO_CONTROL;
	info.psi.soi_kind = SOCKINFO_KERN_CTL;
	info.psi.soi_so = UINT64_C(0x1111222233334444);
	info.psi.soi_pcb = UINT64_C(0x5555666677778888);
	ctl = &info.psi.soi_proto.pri_kern_ctl;
	strcpy(ctl->kcsi_name, UTUN_CONTROL_NAME);
	ctl->kcsi_unit = unit;
	return info;
}

static void check_match(void)
{
	struct socket_fdinfo info = utun_info(7);
	struct vpnt_utun_socket out;

	memset(&out, 0, sizeof(out));
	CHECK(vpnt_utun_decode(&info, &out) == VPNT_UTUN_MATCH);
	CHECK(out.status == VPNT_UTUN_MATCH);
	CHECK(out.unit == 7);
	CHECK(out.reserved == 0);
	CHECK(out.socket == UINT64_C(0x1111222233334444));
	CHECK(out.pcb == UINT64_C(0x5555666677778888));
}

static void check_reject(const struct socket_fdinfo *info)
{
	struct vpnt_utun_socket out;

	memset(&out, 0, sizeof(out));
	CHECK(vpnt_utun_decode(info, &out) == VPNT_UTUN_NOT_UTUN);
	CHECK(out.status == VPNT_UTUN_NOT_UTUN);
	CHECK(out.unit == 0);
	CHECK(out.socket == 0);
	CHECK(out.pcb == 0);
}

static void check_variants(void)
{
	struct socket_fdinfo info;
	struct kern_ctl_info *ctl;
	unsigned char canary[sizeof(struct vpnt_utun_socket) + 8];
	size_t i;

	info = utun_info(3);
	info.psi.soi_family = AF_INET;
	check_reject(&info);

	info = utun_info(3);
	info.psi.soi_type = SOCK_STREAM;
	check_reject(&info);

	info = utun_info(3);
	info.psi.soi_protocol = 0;
	check_reject(&info);

	info = utun_info(3);
	info.psi.soi_kind = SOCKINFO_GENERIC;
	check_reject(&info);

	info = utun_info(3);
	ctl = &info.psi.soi_proto.pri_kern_ctl;
	memset(ctl->kcsi_name, 0, sizeof(ctl->kcsi_name));
	strcpy(ctl->kcsi_name, "com.apple.net.utun_contro");
	check_reject(&info);

	info = utun_info(3);
	ctl = &info.psi.soi_proto.pri_kern_ctl;
	memset(ctl->kcsi_name, 0, sizeof(ctl->kcsi_name));
	strcpy(ctl->kcsi_name, UTUN_CONTROL_NAME "X");
	check_reject(&info);

	info = utun_info(0);
	check_reject(&info);

	/* The output-size boundary must fail before any write. */
	memset(canary, 0xA5, sizeof(canary));
	CHECK(vpnt_utun_socketinfo((int32_t)getpid(), -1,
	    (struct vpnt_utun_socket *)canary,
	    (uint32_t)(sizeof(struct vpnt_utun_socket) - 1)) == VPNT_UTUN_ABI);
	for (i = 0; i < sizeof(canary); i++) {
		CHECK(canary[i] == 0xA5);
	}
	CHECK(vpnt_utun_socketinfo((int32_t)getpid(), -1, NULL,
	    (uint32_t)sizeof(struct vpnt_utun_socket)) == VPNT_UTUN_ABI);

	/* Real proc path on this own process with an invalid FD. */
	{
		struct vpnt_utun_socket out;

		memset(&out, 0, sizeof(out));
		CHECK(vpnt_utun_socketinfo((int32_t)getpid(), -1, &out,
		    (uint32_t)sizeof(out)) == VPNT_UTUN_CHANGED);
		CHECK(out.version == VPNT_UTUN_ABI_VERSION);
		CHECK(out.size == sizeof(out));
		CHECK(out.unit == 0);
	}
}

static int child(void)
{
	int fd;
	char byte;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		return 2;
	}
	printf("%d\n", fd);
	fflush(stdout);
	while (read(STDIN_FILENO, &byte, 1) > 0) {
		if (byte == '\n') {
			break;
		}
	}
	close(fd);
	return 0;
}

int main(int argc, char **argv)
{
	if (argc == 2 && strcmp(argv[1], "child") == 0) {
		return child();
	}
	check_match();
	check_variants();
	if (failures == 0) {
		printf("synthetic ok\n");
	}
	return failures == 0 ? 0 : 1;
}
