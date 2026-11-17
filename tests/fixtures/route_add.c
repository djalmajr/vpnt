/* Independent consumer of the Darwin routing ABI. FD 3 is a private AF_UNIX
 * datagram supplied by the test; this process never opens a route socket. */
#include <assert.h>
#include <arpa/inet.h>
#include <errno.h>
#include <net/if_dl.h>
#include <net/route.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
_Static_assert(VPNT_ATTACH == _IOW('t',61,int), "PPPIOCATTACH ABI");
_Static_assert(VPNT_GET_UNIT == _IOR('t',86,int), "PPPIOCGUNIT ABI");
static void send_frame(const void *bytes,size_t length) {assert(send(3,bytes,length,0)==(ssize_t)length);}
int main(int argc,char **argv) {
    assert(getuid()!=0 && geteuid()!=0 && argc==2);
    send_frame("READY",5);
    unsigned char bytes[65536];ssize_t length=recv(3,bytes,sizeof(bytes),0);assert(length>=(ssize_t)sizeof(struct rt_msghdr));
    struct rt_msghdr header;memcpy(&header,bytes,sizeof(header));
    assert(header.rtm_msglen==length && header.rtm_version==RTM_VERSION && header.rtm_type==RTM_ADD);
    assert(header.rtm_pid==getppid() && header.rtm_seq>0 && header.rtm_index==234);
    assert(header.rtm_addrs==(RTA_DST|RTA_GATEWAY|RTA_NETMASK|RTA_IFP|RTA_IFA));
    assert((header.rtm_flags&(RTF_UP|RTF_STATIC))==(RTF_UP|RTF_STATIC));
    assert(!(header.rtm_flags&(RTF_GATEWAY|RTF_IFSCOPE)));
    int linklocal=!strcmp(argv[1],"v6link");
    int ipv6=!strcmp(argv[1],"v6") || !strcmp(argv[1],"blackhole") || linklocal;
    int host=!strcmp(argv[1],"host");
    int blackhole=!strcmp(argv[1],"blackhole");
    assert(!!(header.rtm_flags&RTF_HOST)==host);
    assert(!!(header.rtm_flags&RTF_BLACKHOLE)==blackhole);
    size_t offset=sizeof(header);const struct sockaddr *parts[8]={0};
    for (int bit=0;bit<8;bit++) if(header.rtm_addrs&(1<<bit)) {
        assert(offset+2<=(size_t)length);parts[bit]=(const struct sockaddr *)(bytes+offset);
        size_t n=parts[bit]->sa_len;assert(n>=2 && offset+n<=(size_t)length);offset+=(n+3)&~3;
    }
    assert(offset==(size_t)length);
    for(int bit=RTAX_GATEWAY;bit<=RTAX_IFP;bit+=RTAX_IFP-RTAX_GATEWAY) {
        assert(parts[bit]->sa_family==AF_LINK && parts[bit]->sa_len==sizeof(struct sockaddr_dl));
        struct sockaddr_dl link;memcpy(&link,parts[bit],sizeof(link));
        assert(link.sdl_index==234 && link.sdl_nlen==0 && link.sdl_alen==0);
    }
    const char *destination=host?"198.51.100.2":ipv6?(blackhole?"::":"2001:db8:42::"):"10.40.0.0";
    const char *source=ipv6?(linklocal?"fe80::2":"2001:db8::2"):"10.20.0.2";
    unsigned char expected[16]={0};int family=ipv6?AF_INET6:AF_INET;
    int start=ipv6?8:4,width=ipv6?16:4,prefix=host?32:ipv6?(blackhole?1:64):16;
    assert(parts[RTAX_DST]->sa_family==family && parts[RTAX_IFA]->sa_family==family);
    assert(parts[RTAX_DST]->sa_len==(ipv6?sizeof(struct sockaddr_in6):sizeof(struct sockaddr_in)));
    assert(parts[RTAX_IFA]->sa_len==parts[RTAX_DST]->sa_len);
    assert(inet_pton(family,destination,expected)==1 && !memcmp((const unsigned char *)parts[RTAX_DST]+start,expected,width));
    assert(inet_pton(family,source,expected)==1 && !memcmp((const unsigned char *)parts[RTAX_IFA]+start,expected,width));
    if(ipv6) {struct sockaddr_in6 source_address;memcpy(&source_address,parts[RTAX_IFA],sizeof(source_address));assert(source_address.sin6_scope_id==(linklocal?234:0));}
    assert(parts[RTAX_NETMASK]->sa_family==0 && parts[RTAX_NETMASK]->sa_len==parts[RTAX_DST]->sa_len);
    for(int bit=0;bit<width*8;bit++) assert(!!(((const unsigned char *)parts[RTAX_NETMASK])[start+bit/8]&(1<<(7-bit%8)))==(bit<prefix));
    if(!strcmp(argv[1],"lost")) return 0;
    if(!strcmp(argv[1],"silent")) {struct timespec pause={.tv_sec=1,.tv_nsec=200000000};nanosleep(&pause,NULL);return 0;}
    if(!strcmp(argv[1],"foreign")) {
        struct rt_msghdr wrong=header;wrong.rtm_pid++;wrong.rtm_errno=EACCES;memcpy(bytes,&wrong,sizeof(wrong));send_frame(bytes,length);
        wrong=header;wrong.rtm_seq++;wrong.rtm_errno=EACCES;memcpy(bytes,&wrong,sizeof(wrong));send_frame(bytes,length);
    }
    if(!strcmp(argv[1],"exists")) header.rtm_errno=EEXIST;
    memcpy(bytes,&header,sizeof(header));
    if(!strcmp(argv[1],"changed")) ((unsigned char *)parts[RTAX_IFA])[start+width-1]^=1;
    send_frame(bytes,(size_t)length-(!strcmp(argv[1],"truncated")?1:0));
    return 0;
}
