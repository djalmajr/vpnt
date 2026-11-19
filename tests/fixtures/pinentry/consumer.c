#include "userinput.h"
#include "log.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
enum log_verbosity loglevel = OFV_LOG_MUTE;
void do_log(int verbosity, const char *format, ...) { (void)verbosity; (void)format; }
int main(int argc, char **argv) {
    if (argc != 3) return 2;
    char password[257] = {0}, expected[257] = {0};
    int fixture = atoi(argv[2]);
    if (fixture == 3 || fixture == 4 || fixture == 6) {
        unsigned char request[16] = {'V','P','T','1'};
        uint32_t pid = htonl((uint32_t)getpid() + (fixture == 3));
        memcpy(request+4,&pid,4);memcpy(request+8,request,8);
        if (fixture == 6) request[0]='X';
        if (fixture == 4) {
            /* Report which step rejected this 16-byte extra-data request. */
            ssize_t written = write(3,request,16);
            if (written != 16) {
                int saved = errno;
                fprintf(stderr,"case 4 write: ret=%zd errno=%d\n",written,saved);
                return 2;
            }
            int shut = shutdown(3,SHUT_WR);
            /* A peer that already rejected the extra byte may be gone before
             * this call; EOF below still has to prove the channel is closed. */
            if (shut != 0 && errno != ENOTCONN) {
                int saved = errno;
                fprintf(stderr,"case 4 shutdown: ret=%d errno=%d\n",shut,saved);
                return 2;
            }
            unsigned char response[260];
            ssize_t got = read(3,response,sizeof(response));
            if (got != 0) {
                int saved = errno;
                fprintf(stderr,"case 4 read: ret=%zd errno=%d bytes=",got,saved);
                for (ssize_t i=0;i<got && i<8;i++) fprintf(stderr,"%02x",response[i]);
                fputc('\n',stderr);
                return 1;
            }
            return 0;
        }
        /* Same peer-close race as case 4: a rejected request may already
         * have closed the server side before shutdown(3, SHUT_WR). */
        ssize_t sent = write(3,request,8);
        if (sent != 8) {
            fprintf(stderr,"case %d write: ret=%zd errno=%d\n",fixture,sent,errno);
            return 2;
        }
        int shut = shutdown(3,SHUT_WR);
        if (shut != 0 && errno != ENOTCONN) {
            fprintf(stderr,"case %d shutdown: ret=%d errno=%d\n",fixture,shut,errno);
            return 2;
        }
        unsigned char response[260];
        return read(3,response,sizeof(response)) == 0 ? 0 : 1;
    }
    if (fixture == 5 || fixture == 9) {
        if (write(1,"ready\n",6)!=6) return 2;
        unsigned char response[260];
        if (fixture == 5) fprintf(stderr,"READING\n");
        ssize_t got = read(3,response,sizeof(response));
        if (fixture == 5) {
            if (got == 0) fprintf(stderr,"REVOKED\n");
            else fprintf(stderr,"REVOKE-FAILED ret=%zd errno=%d\n",got,errno);
        }
        return got == 0 ? 0 : 1;
    }
    if (fixture == 0) strcpy(expected, " %fixture+\xc3\xa9 ");
    else if (fixture == 1) memset(expected, 'x', 256);
    else if (fixture == 2) for (int i=0; i<256; i+=2) { expected[i]=(char)0xc3; expected[i+1]=(char)0xa9; }
    else if (fixture != 7 && fixture != 8) return 2;
    read_password(argv[1], "fictional-hint", "Password:", password, 256);
    int result = strcmp(password, expected) == 0 ? 0 : 1;
    volatile char *p = password; for (int i=0; i<257; i++) p[i]=0;
    return result;
}
