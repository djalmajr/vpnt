// Independent public-SDK consumer for the VIP alias encoding. Reads bytes on
// stdin only; no socket, no ioctl, no privileges.
#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet6/in6_var.h>
#include <netinet6/nd6.h>
#include <arpa/inet.h>

_Static_assert(SIOCAIFADDR == VPNT_ALIAS4, "IPv4 alias ioctl encoding");
_Static_assert(SIOCAIFADDR_IN6 == VPNT_ALIAS6, "IPv6 alias ioctl encoding");
_Static_assert(sizeof(struct ifaliasreq) == 64, "IPv4 alias size");
_Static_assert(sizeof(struct in6_aliasreq) == 128, "IPv6 alias size");

int main(void) {
    struct ifaliasreq v4;
    struct in6_aliasreq v6;
    assert(fread(&v4, sizeof(v4), 1, stdin) == 1);
    assert(fread(&v6, sizeof(v6), 1, stdin) == 1);
    assert(getchar() == EOF);

    assert(strcmp(v4.ifra_name, "utun6") == 0);
    struct sockaddr_in *address = (struct sockaddr_in *)&v4.ifra_addr;
    struct sockaddr_in *peer = (struct sockaddr_in *)&v4.ifra_broadaddr;
    struct sockaddr_in *mask = (struct sockaddr_in *)&v4.ifra_mask;
    assert(address->sin_family == AF_INET && address->sin_len == sizeof(*address));
    assert(address->sin_addr.s_addr == inet_addr("192.0.2.10"));
    assert(memcmp(peer, address, sizeof(*peer)) == 0);
    assert(mask->sin_addr.s_addr == 0xffffffff && mask->sin_port == 0);

    struct in6_addr expected, ones;
    assert(inet_pton(AF_INET6, "2001:db8::10", &expected) == 1);
    memset(&ones, 255, sizeof(ones));
    assert(strcmp(v6.ifra_name, "utun6") == 0);
    assert(v6.ifra_addr.sin6_family == AF_INET6);
    assert(v6.ifra_addr.sin6_len == sizeof(struct sockaddr_in6));
    assert(memcmp(&v6.ifra_addr.sin6_addr, &expected, sizeof(expected)) == 0);
    assert(v6.ifra_addr.sin6_scope_id == 0 && v6.ifra_addr.sin6_port == 0);
    struct sockaddr_in6 zero = {0};
    assert(memcmp(&v6.ifra_dstaddr, &zero, sizeof(zero)) == 0);
    assert(v6.ifra_prefixmask.sin6_family == AF_INET6);
    assert(memcmp(&v6.ifra_prefixmask.sin6_addr, &ones, sizeof(ones)) == 0);
    assert(v6.ifra_flags == IN6_IFF_NODAD);
    assert(v6.ifra_lifetime.ia6t_vltime == ND6_INFINITE_LIFETIME);
    assert(v6.ifra_lifetime.ia6t_pltime == ND6_INFINITE_LIFETIME);
    puts("vip ABI ok");
}
