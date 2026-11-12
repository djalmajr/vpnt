/* Consumer fixture for on_ppp_if_up; every route/DNS operation is intercepted.
 * The upstream C translation unit is supplied from the verified source archive.
 */
#include "tunnel.c"
#include <assert.h>
enum log_verbosity loglevel = OFV_LOG_INFO;
void do_log(int verbosity, const char *format, ...) { (void)verbosity; (void)format; }
static int dropped, routes, dns;
int ipv4_drop_wrong_route(struct tunnel *tunnel) { (void)tunnel; dropped++; return 0; }
int ipv4_set_tunnel_routes(struct tunnel *tunnel) { (void)tunnel; routes++; return 0; }
int ipv4_add_nameservers_to_resolv_conf(struct tunnel *tunnel) { (void)tunnel; dns++; return 0; }
int main(void) {
    struct vpn_config config = {0};
    struct tunnel tunnel = {.config=&config};
    on_ppp_if_up(&tunnel);
    assert(dropped == 0 && routes == 0 && dns == 0);
    config.set_routes=1;
    on_ppp_if_up(&tunnel);
    assert(dropped == 1 && routes == 1 && dns == 0);
    return 0;
}
