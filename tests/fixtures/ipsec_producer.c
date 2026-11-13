#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <sys/select.h>
#include <unistd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
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
static void serve(const char *path) {
    int fd=socket(AF_UNIX,SOCK_STREAM,0);demand(fd>=0);
    struct sockaddr_un address;memset(&address,0,sizeof(address));address.sun_family=AF_UNIX;
    demand(strlen(path)<sizeof(address.sun_path));strcpy(address.sun_path,path);
    mode_t old=umask(0117);int bound=bind(fd,(struct sockaddr*)&address,sizeof(address));umask(old);demand(bound==0 && listen(fd,4)==0);
    while(!stopping) {
        fd_set ready;FD_ZERO(&ready);FD_SET(fd,&ready);struct timeval timeout={0,50000};
        int rc=select(fd+1,&ready,NULL,NULL,&timeout);if(rc<=0)continue;
        int client=accept(fd,NULL,NULL);if(client<0)continue;
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
    FILE *pidfile=fopen(pid,"wx");demand(pidfile!=NULL);fprintf(pidfile,"%d\n",getpid());fclose(pidfile);
    if(strstr(claim,"\"profile\":\"exit\""))return 0;
    if(strstr(claim,"\"profile\":\"silence\"")) {while(!stopping)usleep(1000);}
    else if(strstr(claim,"\"profile\":\"fork\"")) {
        pid_t child=fork();demand(child>=0);
        if(child==0) {serve(socket_path);_exit(0);}
        int status;
        while(!stopping && waitpid(child,&status,WNOHANG)==0)usleep(1000);
        if(stopping) {kill(child,SIGTERM);while(waitpid(child,&status,0)<0 && errno==EINTR){}}
    } else serve(socket_path);
    unlink(pid);
    return 0;
}
