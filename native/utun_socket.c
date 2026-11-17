/*
 * SDK-backed decoder for the owned child's utun-control socket.
 *
 * This translation unit is the only place that sees `struct socket_fdinfo` and
 * `struct kern_ctl_info`; it returns a private fixed-primitive ABI. Observation
 * only: no ownership, route or cleanup authority, no PID scan.
 */
#include <errno.h>
#include <stdint.h>
#include <string.h>

#include <libproc.h>
#include <net/if_utun.h>
#include <sys/proc_info.h>
#include <sys/socket.h>
#include <sys/sys_domain.h>

#define VPNT_UTUN_ABI_VERSION 1u

enum {
	VPNT_UTUN_MATCH = 0,
	VPNT_UTUN_NOT_UTUN = 1,
	VPNT_UTUN_CHANGED = 2,
	VPNT_UTUN_PERMISSION = 3,
	VPNT_UTUN_UNAVAILABLE = 4,
	VPNT_UTUN_ABI = 5,
};

/* Private ABI: fixed primitives only; no SDK struct or pointer crosses it. */
struct vpnt_utun_socket {
	uint32_t version;
	uint32_t size;
	int32_t status;
	uint32_t unit;
	uint32_t reserved;
	uint64_t socket;
	uint64_t pcb;
};

/* The constants copied into the Rust side are pinned here. */
_Static_assert(MAX_KCTL_NAME == 96, "kern_ctl_info name capacity changed");
_Static_assert(sizeof(((struct kern_ctl_info *)0)->kcsi_unit) == 4,
    "kcsi_unit width changed");
_Static_assert(sizeof(((struct socket_info *)0)->soi_so) == 8,
    "soi_so width changed");
_Static_assert(sizeof(((struct socket_info *)0)->soi_pcb) == 8,
    "soi_pcb width changed");
_Static_assert(SOCKINFO_KERN_CTL == 6, "kern-control kind changed");
_Static_assert(SYSPROTO_CONTROL == 2, "sysproto control changed");
_Static_assert(AF_SYSTEM == PF_SYSTEM, "system domain changed");
_Static_assert(SOCK_DGRAM == 2, "datagram type changed");
_Static_assert(PROC_PIDFDSOCKETINFO == 3, "socket flavor changed");
_Static_assert(sizeof(struct vpnt_utun_socket) == 40,
    "private ABI layout changed");

/*
 * Shared decode of an SDK socket record. The synthetic fixture includes this
 * translation unit and calls this function directly, so the tested selector is
 * exactly the one the production entry point uses.
 */
static int32_t vpnt_utun_decode(const struct socket_fdinfo *info,
    struct vpnt_utun_socket *out)
{
	const struct socket_info *si;
	const struct kern_ctl_info *ctl;
	const char *nul;
	size_t length;

	if (info == NULL || out == NULL) {
		return VPNT_UTUN_ABI;
	}
	si = &info->psi;
	ctl = &si->soi_proto.pri_kern_ctl;
	out->status = VPNT_UTUN_NOT_UTUN;
	out->unit = 0;
	out->reserved = 0;
	out->socket = 0;
	out->pcb = 0;

	if (si->soi_family != AF_SYSTEM ||
	    si->soi_type != SOCK_DGRAM ||
	    si->soi_protocol != SYSPROTO_CONTROL ||
	    si->soi_kind != SOCKINFO_KERN_CTL) {
		return out->status;
	}
	nul = memchr(ctl->kcsi_name, '\0', sizeof(ctl->kcsi_name));
	length = nul != NULL
	    ? (size_t)((const char *)nul - ctl->kcsi_name)
	    : sizeof(ctl->kcsi_name);
	/* Exact control name including its NUL, not a prefix match. */
	if (length != sizeof(UTUN_CONTROL_NAME) - 1 ||
	    memcmp(ctl->kcsi_name, UTUN_CONTROL_NAME,
	    sizeof(UTUN_CONTROL_NAME)) != 0) {
		return out->status;
	}
	if (ctl->kcsi_unit == 0) {
		return out->status;
	}
	out->status = VPNT_UTUN_MATCH;
	out->unit = ctl->kcsi_unit;
	out->reserved = 0;
	out->socket = si->soi_so;
	out->pcb = si->soi_pcb;
	return out->status;
}

/*
 * Decode one descriptor of the owned child. The caller supplies the child's
 * PID and FD from the producer handle; this function never scans other
 * processes and never dereferences or logs the kernel socket/PCB stamps.
 */
int32_t vpnt_utun_socketinfo(int32_t pid, int32_t fd,
    struct vpnt_utun_socket *out, uint32_t out_size)
{
	struct socket_fdinfo info;
	int result;
	int error;

	/* Validate the caller's buffer before touching it. */
	if (out == NULL || out_size < sizeof(*out)) {
		return VPNT_UTUN_ABI;
	}
	memset(out, 0, sizeof(*out));
	out->version = VPNT_UTUN_ABI_VERSION;
	out->size = (uint32_t)sizeof(*out);
	out->status = VPNT_UTUN_UNAVAILABLE;

	memset(&info, 0, sizeof(info));
	errno = 0;
	result = proc_pidfdinfo(pid, fd, PROC_PIDFDSOCKETINFO, &info,
	    (int)sizeof(info));
	error = errno;
	if (result != (int)sizeof(info)) {
		if (result > 0) {
			out->status = VPNT_UTUN_UNAVAILABLE;
		} else {
			switch (error) {
			case ESRCH:
			case EBADF:
			case ENOTSOCK:
				out->status = VPNT_UTUN_CHANGED;
				break;
			case EPERM:
			case EACCES:
				out->status = VPNT_UTUN_PERMISSION;
				break;
			default:
				out->status = VPNT_UTUN_UNAVAILABLE;
				break;
			}
		}
		return out->status;
	}
	return vpnt_utun_decode(&info, out);
}
