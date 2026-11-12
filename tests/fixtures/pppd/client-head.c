// Includes the unmodified pppd_run and argv builder extracted from the pinned
// openfortivpn archive. Only the surrounding client/config/network are fixtures.
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>
#include <util.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <sys/socket.h>
#ifdef VPNT_PINENTRY_FIXTURE
static void secret_input(void) {
    unsigned char request[8]={'V','P','T','1'};
    uint32_t pid=htonl((uint32_t)getpid());memcpy(request+4,&pid,4);
    assert(write(3,request,8)==8 && shutdown(3,SHUT_WR)==0);
    unsigned char reply[2];assert(read(3,reply,2)==2);
    size_t length=((size_t)reply[0]<<8)|reply[1];assert(length==21);
    char password[22]={0};size_t used=0;
    while(used<length) { ssize_t got=read(3,password+used,length-used);assert(got>0);used+=(size_t)got; }
    assert(strcmp(password,"fixture-host-password")==0);memset(password,0,sizeof(password));
}
#endif
#define HAVE_USR_SBIN_PPPD 1
#define HAVE_USR_SBIN_PPP 0
#define HAVE_STRUCT_TERMIOS 1
#define ARRAY_SIZE(x) (sizeof(x)/sizeof(*(x)))
#define log_error(...) do {} while(0)
#define log_warn(...) do {} while(0)
#define log_debug(...) do {} while(0)
struct config {
    char *pppd_call,*pppd_log,*pppd_plugin,*pppd_ipparam,*pppd_ifname;
    int pppd_accept_remote,pppd_use_peerdns;
};
struct tunnel { struct config *config;int ssl_socket;pid_t pppd_pid;int pppd_pty; };
