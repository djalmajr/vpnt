// Fictional PPP payload. No network, interface, route or privileged operation.
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
int main(int argc,char **argv) {
    static const char *expected[]={
        "230400", ":169.254.2.1", "noipdefault", "ipcp-accept-local", "noaccomp",
        "noauth", "default-asyncmap", "nopcomp", "receive-all", "nodefaultroute",
        "nodetach", "lcp-max-configure", "40", "mru", "1354", "logfd", "2",
        "noacsp", "no-use-dhcp", "no-intercept-dhcp", "noproxyarp", "nopersist"
    };
    assert(argc==3+(int)(sizeof(expected)/sizeof(expected[0])));
    for(int i=3;i<argc;i++) assert(strcmp(argv[i],expected[i-3])==0);
    assert(isatty(STDIN_FILENO) && isatty(STDOUT_FILENO));
    assert(fcntl(3,F_GETFD)==-1 && errno==EBADF);
    assert(fcntl(4,F_GETFD)==-1 && errno==EBADF);
    assert(getenv("VPNT_MUST_NOT_REACH_PPP")==NULL);
    assert(strcmp(getenv("LANG"),"C")==0);
    if(strcmp(argv[1],"ignore-term")==0) signal(SIGTERM,SIG_IGN);
    if(strcmp(argv[1],"orphan")==0) { signal(SIGHUP,SIG_IGN);signal(SIGTERM,SIG_IGN); }
    FILE *marker=fopen(argv[2],"w");assert(marker);
    fprintf(marker,"%d\n",getpid());assert(fclose(marker)==0);
    puts("fixture PPP payload ready");fflush(stdout);
    if(strcmp(argv[1],"normal")==0) return 0;
    if(strcmp(argv[1],"orphan")==0) { usleep(1000000);return 0; }
    while(1) pause();
}
