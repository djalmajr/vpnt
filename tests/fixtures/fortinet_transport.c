/* Execute the patched upstream TCP consumer. Only loopback sockets are opened;
 * DNS is intercepted and every proxy variable is cleared before connecting. */
#include <netdb.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
static int fail_binding, dns_calls;
static int fixture_dns(const char *host,const char *service,const struct addrinfo *hints,struct addrinfo **result) {
    (void)host;(void)service;(void)hints;(void)result;dns_calls++;return EAI_FAIL;
}
static int fixture_option(int fd,int level,int option,const void *value,socklen_t size) {
    if (fail_binding && level==IPPROTO_IP && option==IP_BOUND_IF) {errno=ENXIO;return -1;}
    return setsockopt(fd,level,option,value,size);
}
#define getaddrinfo fixture_dns
#define setsockopt fixture_option
#include "tunnel.c"
#undef getaddrinfo
#undef setsockopt
#include <poll.h>
enum log_verbosity loglevel = OFV_LOG_INFO;
void do_log(int verbosity,const char *format,...) {(void)verbosity;(void)format;}
int main(void) {
    assert(getuid()!=0 && geteuid()!=0);
    for (int i=0;i<4;i++) unsetenv((const char *[]){"https_proxy","HTTPS_PROXY","all_proxy","ALL_PROXY"}[i]);
    int listener=socket(AF_INET,SOCK_STREAM,0);assert(listener>=0);
    struct sockaddr_in local={.sin_len=sizeof(local),.sin_family=AF_INET,.sin_addr={.s_addr=htonl(INADDR_LOOPBACK)}};
    assert(bind(listener,(struct sockaddr *)&local,sizeof(local))==0 && listen(listener,4)==0);
    socklen_t size=sizeof(local);assert(getsockname(listener,(struct sockaddr *)&local,&size)==0);
    struct vpn_config config={0};struct tunnel tunnel={.config=&config};
    strcpy(config.gateway_host,"vpn.fixture.invalid");
    config.vpnt_gateway_ip=local.sin_addr;config.gateway_port=ntohs(local.sin_port);
    assert(get_gateway_host_ip(&tunnel)==0 && dns_calls==0);
    assert(config.gateway_ip.s_addr==local.sin_addr.s_addr && strcmp(config.gateway_host,"vpn.fixture.invalid")==0);
    strcpy(config.iface_name,"lo0");config.vpnt_ifindex=if_nametoindex("lo0");assert(config.vpnt_ifindex>0);
    int client=tcp_connect(&tunnel);assert(client>=0);
    unsigned int bound=0;size=sizeof(bound);assert(getsockopt(client,IPPROTO_IP,IP_BOUND_IF,&bound,&size)==0 && bound==config.vpnt_ifindex);
    assert(fcntl(client,F_GETFD)&FD_CLOEXEC);
    struct pollfd ready={.fd=listener,.events=POLLIN};assert(poll(&ready,1,1000)==1);
    int accepted=accept(listener,NULL,NULL);assert(accepted>=0);close(accepted);close(client);
    config.vpnt_ifindex++;assert(tcp_connect(&tunnel)==-1);config.vpnt_ifindex--;
    fail_binding=1;assert(tcp_connect(&tunnel)==-1);fail_binding=0;
    config.iface_name[0]=0;assert(tcp_connect(&tunnel)==-1);
    strcpy(config.iface_name,"vpt-missing");assert(tcp_connect(&tunnel)==-1);
    ready.revents=0;assert(poll(&ready,1,10)==0);close(listener);
    puts("transport fixture: 6 scenarios passed (loopback only)");
    return 0;
}
