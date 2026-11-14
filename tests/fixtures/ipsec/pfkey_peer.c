#define main vpnt_sdk_single_frame
#include "pfkey.c"
#undef main
#include <unistd.h>
static void emit(const struct sadb_msg *query,uint32_t sequence,unsigned ordinal,int error,int foreign) {
    length=0;struct sadb_msg *h=reserve(sizeof(*h));
    h->sadb_msg_version=PF_KEY_V2;h->sadb_msg_type=query->sadb_msg_type;
    h->sadb_msg_seq=sequence;h->sadb_msg_pid=query->sadb_msg_pid+(foreign==1);
    h->sadb_msg_errno=error;
    if(foreign==2)h->sadb_msg_type=SADB_ADD;
    else if(!error) {
        h->sadb_msg_satype=query->sadb_msg_type==SADB_DUMP?SADB_SATYPE_ESP:SADB_SATYPE_UNSPEC;
        if(query->sadb_msg_type==SADB_DUMP){sad(AF_INET,0,0);((struct sadb_sa*)(storage.bytes+16))->sadb_sa_spi=htonl(0x1234abcd+ordinal);}
        else {spd(AF_INET,"spd4");unsigned char *p=storage.bytes+16;while(((struct sadb_ext*)p)->sadb_ext_type!=SADB_X_EXT_POLICY)p+=((struct sadb_ext*)p)->sadb_ext_len*8;((struct sadb_x_policy*)p)->sadb_x_policy_id+=ordinal;}
    }
    h->sadb_msg_len=length/8;
    demand(send(0,storage.bytes,length,0)==(ssize_t)length);
}
int main(int argc,char **argv) {
    demand(argc==2);alarm(10);
    struct sadb_msg q;unsigned char input[64];ssize_t n=recv(0,input,sizeof(input),0);
    demand(n==sizeof(q));memcpy(&q,input,sizeof(q));
    demand(q.sadb_msg_version==PF_KEY_V2 && (q.sadb_msg_type==SADB_DUMP || q.sadb_msg_type==SADB_X_SPDDUMP));
    demand(q.sadb_msg_satype==SADB_SATYPE_UNSPEC && q.sadb_msg_errno==0 && q.sadb_msg_reserved==0 && q.sadb_msg_len==2 && q.sadb_msg_seq>0 && q.sadb_msg_pid==(uint32_t)getppid());
    const char *mode=argv[1];
    if(strcmp(mode,"empty")==0 || strcmp(mode,"bad-empty")==0)emit(&q,q.sadb_msg_seq+(strcmp(mode,"bad-empty")==0),0,ENOENT,0);
    else if(strcmp(mode,"denied")==0)emit(&q,q.sadb_msg_seq,0,EACCES,0);
    else if(strcmp(mode,"failed")==0)emit(&q,q.sadb_msg_seq,0,ENOBUFS,0);
    else if(strcmp(mode,"zero")==0)demand(send(0,"",0,0)==0);
    else if(strcmp(mode,"silence")==0){}
    else if(strcmp(mode,"huge")==0)emit(&q,4096,1,0,0);
    else if(strcmp(mode,"suffix")==0)emit(&q,0,1,0,0);
    else {
        emit(&q,1,90,0,1);emit(&q,0,91,0,2);
        emit(&q,strcmp(mode,"gap")==0?2:1,1,0,0);
        if(strcmp(mode,"partial")==0){}
        else if(strcmp(mode,"partial-error")==0)emit(&q,q.sadb_msg_seq,0,ENOENT,0);
        else if(strcmp(mode,"duplicate")==0)emit(&q,1,2,0,0);
        else if(strcmp(mode,"malformed")==0){unsigned char bad[16]={1};demand(send(0,bad,sizeof(bad),0)==sizeof(bad));}
        else {emit(&q,0,2,0,0);if(strcmp(mode,"extra")==0)emit(&q,0,3,0,0);}
    }
    demand(write(1,"R",1)==1);
    n=recv(0,input,sizeof(input),0);demand(n==7 && memcmp(input,"release",7)==0);
    return 0;
}
