int main(int argc,char **argv) {
    struct config config={0};
    if(argc>1 && strcmp(argv[1],"bad-argv")==0) config.pppd_call="fictional-profile";
    if(argc>1 && strcmp(argv[1],"extra-argv")==0) config.pppd_ipparam="fictional-extra";
    struct tunnel tunnel={ .config=&config,.ssl_socket=open("/dev/null",O_RDONLY),.pppd_pid=0,.pppd_pty=-1 };
    if(pppd_run(&tunnel)!=0) return 10;
    fcntl(STDIN_FILENO,F_SETFL,O_NONBLOCK);
    while(1) {
        char control;
        if(read(STDIN_FILENO,&control,1)==1 && control=='h') {
            close(tunnel.pppd_pty);tunnel.pppd_pty=-1;
        }
        char payload[1024];
        (void)read(tunnel.pppd_pty,payload,sizeof(payload));
        int status;
        pid_t waited=waitpid(tunnel.pppd_pid,&status,WNOHANG);
        if(waited==tunnel.pppd_pid) return WIFEXITED(status)?WEXITSTATUS(status):11;
        if(waited<0) return 12;
        usleep(1000);
    }
}
