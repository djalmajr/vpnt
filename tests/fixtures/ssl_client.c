/* A process fixture, not a VPN: checks the driver's real argv/environment and
 * inherited secret channel, then emits deliberately untrusted client output. */
#include <arpa/inet.h>
#include <assert.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <net/if.h>
#include <unistd.h>
static void exact(int fd, void *value, size_t count) {
    unsigned char *bytes=value;
    while (count) {ssize_t n=read(fd,bytes,count);assert(n>0);bytes+=n;count-=(size_t)n;}
}
int main(int argc,char **argv) {
    assert(argc==15 || argc==16);
    const char *fixed[]={"--config=/dev/null","--no-routes","--no-dns","--pppd-no-peerdns","--pppd-accept-remote=0","--persistent=0","--username=fixture-user","--pinentry=/Library/PrivilegedHelperTools/dev.vpnt.pinentry"};
    for (int i=0;i<8;i++) assert(strcmp(argv[i+1],fixed[i])==0);
    assert(strncmp(argv[9],"--ca-file=",10)==0);
    assert(strcmp(argv[10],"--ifname=lo0")==0);
    char expected[64];snprintf(expected,sizeof(expected),"--vpnt-ifindex=%u",if_nametoindex("lo0"));
    assert(strcmp(argv[11],expected)==0);
    assert(strcmp(argv[12],"--vpnt-gateway-ip=127.0.0.1")==0);
    if (argc==16) assert(strncmp(argv[13],"--trusted-cert=",15)==0);
    assert(strcmp(argv[argc-2],"--")==0);
    for(int i=0;i<argc;i++) assert(strstr(argv[i],"fixture-driver-password")==NULL);
    assert(strcmp(getenv("OPENSSL_CONF"),"/dev/null")==0);
    assert(strcmp(getenv("OPENSSL_MODULES"),RUNTIME_PREFIX "/lib/ossl-modules")==0);
    assert(strcmp(getenv("SSL_CERT_FILE"),RUNTIME_PREFIX "/certs/ca-bundle.pem")==0);
    assert(getenv("DYLD_LIBRARY_PATH")==NULL && getenv("DYLD_INSERT_LIBRARIES")==NULL);
    assert(fcntl(4,F_GETFD)>=0); /* independent supervision capability */
    unsigned char request[8]={'V','P','T','1'};
    uint32_t pid=htonl((uint32_t)getpid());memcpy(request+4,&pid,4);
    assert(write(3,request,8)==8 && shutdown(3,SHUT_WR)==0);
    uint16_t length;exact(3,&length,2);length=ntohs(length);
    assert(length<=256);char password[257]={0};exact(3,password,length);
    assert(strcmp(password,"fixture-driver-password")==0);
    printf("DEBUG:  %s\n",password);memset(password,0,sizeof(password));
    if (strcmp(argv[argc-1],"auth.fixture.invalid:443")==0) {
        puts("ERROR:  Could not authenticate to gateway. Please check the password, client certificate, etc.");return 1;
    }
    if (strcmp(argv[argc-1],"timeout.fixture.invalid:443")==0) {
        puts("ERROR:  connect: Operation timed out");return 1;
    }
    for(int i=0;i<5000;i++) putchar('x');
    puts("INFO:   Interface ppp999 is UP.");
    puts("INFO:   Interface ppp123 is UP.");fflush(stdout);
    for(;;) pause();
}
