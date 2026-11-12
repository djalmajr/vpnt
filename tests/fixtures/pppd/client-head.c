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
