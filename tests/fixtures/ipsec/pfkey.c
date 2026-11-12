#include <net/pfkeyv2.h>
#include <netinet6/ipsec.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#ifdef VPNT_ORIGINAL_NATT
#include "original-natt.h"
#endif
#define demand(c) do { if (!(c)) { fprintf(stderr,"fixture line %d\n",__LINE__); exit(1); } } while (0)
static union { max_align_t align; unsigned char bytes[8192]; } storage;
static size_t length;
static void *reserve(size_t n) {
    demand(length+n<=sizeof(storage.bytes));
    void *p=storage.bytes+length; memset(p,0,n); length+=n; return p;
}
static void extension(unsigned type, size_t n) {
    struct sadb_ext *ext=(void*)(storage.bytes+length-n);
    ext->sadb_ext_len=(uint16_t)(n/8); ext->sadb_ext_type=(uint16_t)type;
}
static size_t socket_address(void *out, int family, const char *ip, unsigned port, unsigned scope) {
    if (family==AF_INET) {
        struct sockaddr_in *p=out; memset(p,0,sizeof(*p));
        p->sin_len=sizeof(*p); p->sin_family=AF_INET; p->sin_port=htons(port);
        demand(inet_pton(AF_INET,ip,&p->sin_addr)==1); return sizeof(*p);
    }
    struct sockaddr_in6 *p=out; memset(p,0,sizeof(*p));
    p->sin6_len=sizeof(*p); p->sin6_family=AF_INET6; p->sin6_port=htons(port); p->sin6_scope_id=scope;
    demand(inet_pton(AF_INET6,ip,&p->sin6_addr)==1); return sizeof(*p);
}
static void address(unsigned type,int family,const char *ip,unsigned prefix,unsigned protocol,unsigned port,unsigned scope) {
    size_t n=sizeof(struct sadb_address)+(family==AF_INET?sizeof(struct sockaddr_in):32);
    struct sadb_address *p=reserve(n); extension(type,n);
    p->sadb_address_prefixlen=prefix; p->sadb_address_proto=protocol;
    socket_address(p+1,family,ip,port,scope);
}
static void sad(int family,int scoped,int natt) {
    size_t n=sizeof(struct sadb_sa);
#ifdef VPNT_ORIGINAL_NATT
    if(natt)n=sizeof(struct sadb_sa_2);
#else
    demand(!natt);
#endif
    struct sadb_sa *sa=reserve(n); extension(SADB_EXT_SA,n);
    sa->sadb_sa_spi=htonl(0x1234abcd); sa->sadb_sa_state=SADB_SASTATE_MATURE;
    sa->sadb_sa_auth=SADB_AALG_SHA1HMAC; sa->sadb_sa_encrypt=SADB_X_EALG_AES;
#ifdef VPNT_ORIGINAL_NATT
    if(natt) { sa->sadb_sa_flags=SADB_X_EXT_NATT; vpnt_original_natt_port((struct sadb_sa_2*)sa,4500); }
#endif
    struct sadb_x_sa2 *sa2=reserve(sizeof(*sa2)); extension(SADB_X_EXT_SA2,sizeof(*sa2));
    sa2->sadb_x_sa2_reqid=0x10001; sa2->sadb_x_sa2_mode=IPSEC_MODE_TUNNEL;
    sa2->sadb_x_sa2_sequence=0x33221199; sa2->sadb_x_sa2_reserved2=0x3344;
    struct sadb_lifetime *life=reserve(sizeof(*life)); extension(SADB_EXT_LIFETIME_CURRENT,sizeof(*life));
    life->sadb_lifetime_allocations=0x40302010; life->sadb_lifetime_bytes=UINT64_C(0x0102030405060708);
    life->sadb_lifetime_addtime=42; life->sadb_lifetime_usetime=84;
    address(SADB_EXT_ADDRESS_SRC,family,family==AF_INET?"192.0.2.10":scoped?"fe80:7::1":"2001:db8::1",family==AF_INET?32:128,IPSEC_ULPROTO_ANY,4501,scoped?7:0);
    address(SADB_EXT_ADDRESS_DST,family,family==AF_INET?"198.51.100.20":"2001:db8::2",family==AF_INET?32:128,IPSEC_ULPROTO_ANY,4500,0);
    struct sadb_key *key=reserve(sizeof(*key)+16); extension(SADB_EXT_KEY_AUTH,sizeof(*key)+16);
    key->sadb_key_bits=128; memcpy(key+1,"fake-sa-key-0001",16);
}
static void request(int family,int transport,int wildcard,unsigned protocol,unsigned reqid) {
    size_t n=sizeof(struct sadb_x_ipsecrequest);
    if(!transport && !wildcard)n+=2*(family==AF_INET?sizeof(struct sockaddr_in):sizeof(struct sockaddr_in6));
    struct sadb_x_ipsecrequest *p=reserve(n);
    p->sadb_x_ipsecrequest_len=n; p->sadb_x_ipsecrequest_proto=protocol;
    p->sadb_x_ipsecrequest_mode=transport?IPSEC_MODE_TRANSPORT:IPSEC_MODE_TUNNEL;
    p->sadb_x_ipsecrequest_level=IPSEC_LEVEL_UNIQUE; p->sadb_x_ipsecrequest_reqid=reqid;
    if(!transport && !wildcard) {
        unsigned char *at=(void*)(p+1);
        at+=socket_address(at,family,family==AF_INET?"192.0.2.10":"2001:db8::1",0,0);
        socket_address(at,family,family==AF_INET?"198.51.100.20":"2001:db8::2",0,0);
    }
}
static void spd(int family,const char *mode) {
    if(strcmp(mode,"range")==0) {
        address(SADB_X_EXT_ADDR_RANGE_SRC_START,family,"10.20.0.1",24,IPPROTO_TCP,8443,0);
        address(SADB_X_EXT_ADDR_RANGE_SRC_END,family,"10.20.0.99",24,IPPROTO_TCP,8444,0);
    } else address(SADB_EXT_ADDRESS_SRC,family,family==AF_INET?"10.20.0.7":"2001:db8:20::7",family==AF_INET?24:64,IPPROTO_TCP,8443,0);
    address(SADB_EXT_ADDRESS_DST,family,family==AF_INET?"10.30.0.9":"2001:db8:30::9",family==AF_INET?24:64,IPPROTO_TCP,443,0);
    size_t start=length; struct sadb_x_policy *p=reserve(sizeof(*p));
    p->sadb_x_policy_exttype=SADB_X_EXT_POLICY; p->sadb_x_policy_id=0x10203040;
    p->sadb_x_policy_type=strcmp(mode,"none")==0?IPSEC_POLICY_NONE:IPSEC_POLICY_IPSEC;
    p->sadb_x_policy_dir=IPSEC_DIR_OUTBOUND;
    if(strcmp(mode,"none")!=0) {
        request(family,strcmp(mode,"transport")==0,strcmp(mode,"wildcard")==0,IPPROTO_ESP,0x3fff);
        if(strcmp(mode,"multi")==0)request(family,1,0,IPPROTO_AH,0x4001);
    }
    p->sadb_x_policy_len=(uint16_t)((length-start)/8);
}
int main(int argc,char **argv) {
    demand(argc==2);
    if(strcmp(argv[1],"abi")==0) {
        printf("{\"header\":%zu,\"sa\":%zu,\"sa2\":%zu,\"address\":%zu,\"policy\":%zu,\"request\":%zu,\"lifetime\":%zu,\"reqid\":%zu,\"requestReqid\":%zu,\"v4\":%zu,\"v6\":%zu}\n",sizeof(struct sadb_msg),sizeof(struct sadb_sa),sizeof(struct sadb_x_sa2),sizeof(struct sadb_address),sizeof(struct sadb_x_policy),sizeof(struct sadb_x_ipsecrequest),sizeof(struct sadb_lifetime),offsetof(struct sadb_x_sa2,sadb_x_sa2_reqid),offsetof(struct sadb_x_ipsecrequest,sadb_x_ipsecrequest_reqid),sizeof(struct sockaddr_in),sizeof(struct sockaddr_in6));
        return 0;
    }
    const char *mode=argv[1]; int is_sa=strncmp(mode,"sa",2)==0 || strncmp(mode,"natt",4)==0;
    struct sadb_msg *h=reserve(sizeof(*h));
    h->sadb_msg_version=PF_KEY_V2; h->sadb_msg_type=is_sa?SADB_DUMP:SADB_X_SPDDUMP;
    h->sadb_msg_satype=is_sa?SADB_SATYPE_ESP:SADB_SATYPE_UNSPEC;
    h->sadb_msg_seq=7; h->sadb_msg_pid=4242; h->sadb_msg_reserved=37;
    if(strcmp(mode,"error")==0)h->sadb_msg_errno=ENOENT;
    else if(is_sa)sad(strchr(mode,'6')?AF_INET6:AF_INET,strstr(mode,"scoped")!=NULL,strncmp(mode,"natt",4)==0);
    else spd(strchr(mode,'6')?AF_INET6:AF_INET,mode);
    h->sadb_msg_len=length/8;
    demand(fwrite(storage.bytes,1,length,stdout)==length); return 0;
}
