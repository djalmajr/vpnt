#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <sys/select.h>
#include <unistd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#ifndef RUNTIME_PREFIX
#error RUNTIME_PREFIX required
#endif
static volatile sig_atomic_t stopping;
static void stop(int sig) { (void)sig; stopping=1; }
#define demand(yes) do { if(!(yes)) _exit(__LINE__); } while(0)
static void read_file(const char *path,char *out,size_t cap) {
    struct stat st; demand(lstat(path,&st)==0 && S_ISREG(st.st_mode) && (st.st_mode&07777)==0600 && st.st_nlink==1);
    FILE *file=fopen(path,"rb");demand(file!=NULL);
    size_t n=fread(out,1,cap-1,file);demand(!ferror(file) && feof(file));out[n]=0;fclose(file);
}
static void setting(const char *config,const char *key,char *out,size_t cap) {
    const char *start=strstr(config,key);demand(start!=NULL);start+=strlen(key);
    const char *end=strchr(start,'"');demand(end!=NULL && (size_t)(end-start)<cap);
    memcpy(out,start,end-start);out[end-start]=0;
}
static int read_all(int fd,void *out,size_t n) {
    while(n) { ssize_t got=read(fd,out,n);if(got<=0)return 0;out=(char*)out+got;n-=(size_t)got; }return 1;
}
/* The lease directory rejects unknown entries, so the EOF audit lives in the
 * fixture root two levels above it. */
static void audit_named(const char *directory,const char *name,const char *text) {
    char path[1100];snprintf(path,sizeof(path),"%s/../../%s",directory,name);
    int fd=open(path,O_WRONLY|O_APPEND|O_CREAT,0600);if(fd<0)return;
    (void)write(fd,text,strlen(text));close(fd);
}
static void audit_closed(const char *directory) {
    char path[1100];snprintf(path,sizeof(path),"%s/../../retain.audit",directory);
    int fd=open(path,O_WRONLY|O_APPEND|O_CREAT,0600);if(fd<0)return;
    (void)write(fd,"closed\n",7);close(fd);
}
static void serve(const char *path,int watch,const char *directory) {
    int fd=socket(AF_UNIX,SOCK_STREAM,0);demand(fd>=0);
    struct sockaddr_un address;memset(&address,0,sizeof(address));address.sun_family=AF_UNIX;
    demand(strlen(path)<sizeof(address.sun_path));strcpy(address.sun_path,path);
    mode_t old=umask(0117);int bound=bind(fd,(struct sockaddr*)&address,sizeof(address));umask(old);demand(bound==0 && listen(fd,4)==0);
    while(!stopping) {
        int widest=watch>fd?watch:fd;
        fd_set ready;FD_ZERO(&ready);FD_SET(fd,&ready);if(watch>=0)FD_SET(watch,&ready);
        struct timeval timeout={0,50000};
        int rc=select(widest+1,&ready,NULL,NULL,&timeout);if(rc<=0)continue;
        if(watch>=0 && FD_ISSET(watch,&ready)) {
            unsigned char byte;ssize_t got=read(watch,&byte,1);
            if(got==0 || (got<0 && errno!=EINTR)) {audit_closed(directory);close(watch);watch=-1;}
        }
        if(!FD_ISSET(fd,&ready))continue;
        int client=accept(fd,NULL,NULL);if(client<0)continue;
        /* A client that never speaks must not stall the watch loop. */
        struct timeval wait={0,200000};
        (void)setsockopt(client,SOL_SOCKET,SO_RCVTIMEO,&wait,sizeof(wait));
        unsigned char header[4],body[32];
        if(read_all(client,header,4)) {
            size_t len=((size_t)header[0]<<24)|((size_t)header[1]<<16)|((size_t)header[2]<<8)|header[3];
            if(len<=sizeof(body) && read_all(client,body,len)) {
                demand(len==9 && memcmp(body,"\0\7version",9)==0);
                static const unsigned char reply[]="\1\3\6daemon\0\6charon\3\7version\0\5" "6.1.0";
                const unsigned char prefix[]={0,0,0,sizeof(reply)-1};
                (void)write(client,prefix,sizeof(prefix));(void)write(client,reply,sizeof(reply)-1);
            }
        }
        close(client);
    }
    close(fd);
}
int main(int argc,char **argv) {
    struct stat null_device,descriptor;demand(stat("/dev/null",&null_device)==0);
    /* fd0 is the private parent-liveness read end: anonymous, read-only. */
    demand(fstat(0,&descriptor)==0 && S_ISFIFO(descriptor.st_mode) && descriptor.st_nlink==0);
    int stdin_flags=fcntl(0,F_GETFL);demand(stdin_flags!=-1 && (stdin_flags&O_ACCMODE)==O_RDONLY);
    for(int fd=1;fd<3;fd++) demand(fstat(fd,&descriptor)==0 && S_ISCHR(descriptor.st_mode) && descriptor.st_rdev==null_device.st_rdev);
    char cwd[1024];demand(getcwd(cwd,sizeof(cwd)) && strcmp(cwd,"/")==0);
    const char *groups[]={"dmn","mgr","ike","chd","job","cfg","knl","net","asn","enc","tnc","imc","imv","pts","tls","esp","lib"};
    demand(argc==35);
    for(int i=0;i<17;i++) {char arg[32];snprintf(arg,sizeof(arg),"--debug-%s",groups[i]);demand(strcmp(argv[1+2*i],arg)==0 && strcmp(argv[2+2*i],"-1")==0);}
    demand(strcmp(getenv("PATH"),"/usr/bin:/bin:/usr/sbin:/sbin")==0);
    demand(strcmp(getenv("LANG"),"C")==0 && strcmp(getenv("LC_ALL"),"C")==0);
    demand(strcmp(getenv("OPENSSL_CONF"),"/dev/null")==0);
    demand(strcmp(getenv("OPENSSL_MODULES"),RUNTIME_PREFIX "/lib/ossl-modules")==0);
    demand(strcmp(getenv("OPENSSL_ENGINES"),RUNTIME_PREFIX "/lib/engines")==0);
    demand(strcmp(getenv("SSL_CERT_FILE"),RUNTIME_PREFIX "/certs/ca-bundle.pem")==0);
    demand(getenv("VPNT_FORBIDDEN")==NULL && getenv("CARGO_MANIFEST_DIR")==NULL && getenv("DYLD_LIBRARY_PATH")==NULL);
    const char *filename=getenv("STRONGSWAN_CONF");demand(filename!=NULL);
    char config[8192],claim[8192],directory[1024],pid[1024],socket_path[104],record[1024];
    read_file(filename,config,sizeof(config));
    demand(strstr(config,"install_routes = no") && strstr(config,"install_virtual_ip = no") && strstr(config,"port = 0") && strstr(config,"port_nat_t = 0"));
    demand(strstr(config,"kernel-libipsec") && strstr(config,"kernel-pfroute") && !strstr(config,"kernel-pfkey"));
    demand(strstr(config,"kernel-libipsec { vpnt_retain_utun = yes"));
    demand(!strstr(config,"} libipsec { vpnt_retain_utun = yes"));
    demand(strstr(config,"vpnt_parent_eof = yes"));
    strcpy(directory,filename);char *slash=strrchr(directory,'/');demand(slash!=NULL);*slash=0;
    struct stat st;demand(lstat(directory,&st)==0 && S_ISDIR(st.st_mode) && (st.st_mode&07777)==0700);
    snprintf(record,sizeof(record),"%s/claim.json",directory);read_file(record,claim,sizeof(claim));
    char binding[96];snprintf(binding,sizeof(binding),"\"controller\":{\"pid\":%d,",getppid());demand(strstr(claim,binding));
    if(strstr(claim,"\"stage\":\"starting\"")) {demand(strstr(claim,"\"child\":null"));}
    else {snprintf(binding,sizeof(binding),"\"child\":{\"pid\":%d,",getpid());demand(strstr(claim,"\"stage\":\"running\"") && strstr(claim,binding));}
    setting(config,"socket = \"unix://",socket_path,sizeof(socket_path));
    setting(config,"vpnt_pid_file = \"",pid,sizeof(pid));
    char expected[1100];snprintf(expected,sizeof(expected),"%s/v",directory);demand(strcmp(expected,socket_path)==0);
    snprintf(expected,sizeof(expected),"%s/pid",directory);demand(strcmp(expected,pid)==0);
    signal(SIGTERM,stop);signal(SIGINT,stop);signal(SIGALRM,stop);alarm(15);
    if(strstr(claim,"\"profile\":\"exit\""))return 0;
    /* Handoff silence: cancel must land during the reception itself. */
    if(strstr(claim,"\"profile\":\"handoff-silence\"")) {
        audit_named(directory,"handoff.ready","ready\n");
        while(!stopping)usleep(1000);
    }
    /* One handoff before serving VICI: fixed VPUF v1 plus one ordinary
     * descriptor. FD3 arrived inheritable so the helper could remap it; this
     * child marks it close-on-exec, sends once and closes the endpoint. The
     * peer stays here so a dropped descriptor is observed as EOF. */
    demand(fcntl(3,F_SETFD,FD_CLOEXEC)==0);
    int kind=0;socklen_t kind_len=sizeof(kind);
    demand(getsockopt(3,SOL_SOCKET,SO_TYPE,&kind,&kind_len)==0 && kind==SOCK_DGRAM);
    int retained[2];
    int retire_eof=strstr(claim,"\"profile\":\"retire-eof\"")!=NULL;
    if(retire_eof) {
        /* The test holds the peer; this child keeps its own stream until exit
         * so an EOF at the test proves the helper dropped the received one. */
        retained[0]=socket(AF_UNIX,SOCK_STREAM,0);demand(retained[0]>=0);
        struct sockaddr_un peer_address;memset(&peer_address,0,sizeof(peer_address));
        peer_address.sun_len=sizeof(peer_address);peer_address.sun_family=AF_UNIX;
        char retain_parent[1024],retain_root[1024];
        snprintf(retain_parent,sizeof(retain_parent),"%s/../..",directory);
        demand(realpath(retain_parent,retain_root)!=NULL);
        snprintf(peer_address.sun_path,sizeof(peer_address.sun_path),"%s/retain-peer.sock",retain_root);
        socklen_t peer_length=(socklen_t)(offsetof(struct sockaddr_un,sun_path)+strlen(peer_address.sun_path)+1);
        demand(connect(retained[0],(struct sockaddr*)&peer_address,peer_length)==0);
        retained[1]=-1;
    } else {
        demand(socketpair(AF_UNIX,SOCK_STREAM,0,retained)==0);
    }
    {
        unsigned char payload[8]={0x56,0x50,0x55,0x46,1,0,0,0};
        struct msghdr message;memset(&message,0,sizeof(message));
        struct iovec iov={payload,sizeof(payload)};
        char control[CMSG_SPACE(sizeof(int))];memset(control,0,sizeof(control));
        message.msg_iov=&iov;message.msg_iovlen=1;
        message.msg_control=control;message.msg_controllen=sizeof(control);
        struct cmsghdr *cmsg=CMSG_FIRSTHDR(&message);
        cmsg->cmsg_level=SOL_SOCKET;cmsg->cmsg_type=SCM_RIGHTS;cmsg->cmsg_len=CMSG_LEN(sizeof(int));
        memcpy(CMSG_DATA(cmsg),&retained[0],sizeof(int));
        demand(sendmsg(3,&message,0)==(ssize_t)sizeof(payload));
    }
    if(!retire_eof) close(retained[0]);
    close(3);
    FILE *pidfile=fopen(pid,"wx");demand(pidfile!=NULL);fprintf(pidfile,"%d\n",getpid());fclose(pidfile);
    /* VICI silence starts only after a real handoff and channel close. */
    if(strstr(claim,"\"profile\":\"silence\"")) {while(!stopping)usleep(1000);}
    else if(strstr(claim,"\"profile\":\"fork\"")) {
        pid_t child=fork();demand(child>=0);
        if(child==0) {serve(socket_path,retained[1],directory);_exit(0);}
        int status;
        while(!stopping && waitpid(child,&status,WNOHANG)==0)usleep(1000);
        if(stopping) {kill(child,SIGTERM);while(waitpid(child,&status,0)<0 && errno==EINTR){}}
    } else serve(socket_path,retained[1],directory);
    unlink(pid);
    return 0;
}
