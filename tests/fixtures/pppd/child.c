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
    assert(argc==3);
    assert(isatty(STDIN_FILENO) && isatty(STDOUT_FILENO));
    assert(fcntl(3,F_GETFD)==-1 && errno==EBADF);
    assert(fcntl(4,F_GETFD)==-1 && errno==EBADF);
    assert(getenv("VPNT_MUST_NOT_REACH_PPP")==NULL);
    assert(strcmp(getenv("LANG"),"C")==0);
    if(strcmp(argv[1],"ignore-term")==0) signal(SIGTERM,SIG_IGN);
    FILE *marker=fopen(argv[2],"w");assert(marker);
    fprintf(marker,"%d\n",getpid());assert(fclose(marker)==0);
    puts("fixture PPP payload ready");fflush(stdout);
    if(strcmp(argv[1],"normal")==0) return 0;
    while(1) pause();
}
