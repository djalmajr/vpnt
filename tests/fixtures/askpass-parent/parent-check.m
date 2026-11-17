// Compile the actual adapter in this translation unit, replacing only the
// parent-observation syscalls. Its renamed GUI entry point is never called.
#import <AppKit/AppKit.h>
#include <libproc.h>
#include <sys/sysctl.h>
#include <sys/proc.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static const pid_t expected_pid=4242;
static pid_t direct_parent=4242;
static struct kinfo_proc observation;
static int syscall_result, path_result=13, parent_calls, change_on_parent_call;
static size_t returned_length=sizeof(struct kinfo_proc);
static BOOL change_during_sysctl, change_during_path, unterminated_path;
static const char *observed_path="/usr/bin/sudo";

static pid_t fixture_getppid(void) {
    parent_calls++;
    if (change_on_parent_call==parent_calls) direct_parent++;
    return direct_parent;
}
static int fixture_sysctl(int *mib, u_int count, void *output, size_t *length, void *input, size_t input_length) {
    assert(count==4 && mib[0]==CTL_KERN && mib[1]==KERN_PROC && mib[2]==KERN_PROC_PID && mib[3]==expected_pid);
    assert(*length==sizeof(observation) && input==NULL && input_length==0);
    // Even a failed/partial observation can leave plausible bytes behind.
    memcpy(output,&observation,sizeof(observation));
    *length=returned_length;
    if (change_during_sysctl) direct_parent++;
    return syscall_result;
}
static int fixture_proc_pidpath(int pid, void *output, uint32_t length) {
    assert(pid==expected_pid && length==PROC_PIDPATHINFO_MAXSIZE);
    if (unterminated_path) memset(output,'x',length);
    else snprintf(output,length,"%s",observed_path);
    if (change_during_path) direct_parent++;
    return path_result;
}

#define getppid fixture_getppid
#define sysctl fixture_sysctl
#define proc_pidpath fixture_proc_pidpath
#define main unused_adapter_main
#include "../../../scripts/macos/askpass.m"
#undef main
#undef proc_pidpath
#undef sysctl
#undef getppid

int main(int argc, const char *argv[]) {
    assert(argc==2);
    const char *scenario=argv[1];
    observation.kp_proc.p_pid=expected_pid;
    observation.kp_proc.p_stat=SRUN;
    observation.kp_proc.p_starttime.tv_sec=1794610225;
    observation.kp_proc.p_starttime.tv_usec=845022;
    struct kinfo_proc original;
    assert(parent_snapshot(expected_pid,&original));
    parent_calls=0;
    BOOL expected=NO;
    if (!strcmp(scenario,"positive")) expected=YES;
    else if (!strcmp(scenario,"changed-parent")) direct_parent++;
    else if (!strcmp(scenario,"changed-seconds")) observation.kp_proc.p_starttime.tv_sec++;
    else if (!strcmp(scenario,"changed-microseconds")) observation.kp_proc.p_starttime.tv_usec++;
    else if (!strcmp(scenario,"zombie")) observation.kp_proc.p_stat=SZOMB;
    else if (!strcmp(scenario,"unknown-status")) observation.kp_proc.p_stat=0;
    else if (!strcmp(scenario,"out-of-range-status")) observation.kp_proc.p_stat=127;
    else if (!strcmp(scenario,"sleeping")) { observation.kp_proc.p_stat=SSLEEP; expected=YES; }
    else if (!strcmp(scenario,"stopped")) { observation.kp_proc.p_stat=SSTOP; expected=YES; }
    else if (!strcmp(scenario,"wrong-pid")) observation.kp_proc.p_pid++;
    else if (!strcmp(scenario,"wrong-path")) observed_path="/tmp/sudo";
    else if (!strcmp(scenario,"path-suffix")) observed_path="/usr/bin/sudo-other";
    else if (!strcmp(scenario,"failed-path")) path_result=0;
    else if (!strcmp(scenario,"unterminated-path")) unterminated_path=YES;
    else if (!strcmp(scenario,"failed-sysctl")) syscall_result=-1;
    else if (!strcmp(scenario,"empty-sysctl")) returned_length=0;
    else if (!strcmp(scenario,"partial-sysctl")) returned_length--;
    else if (!strcmp(scenario,"oversized-sysctl")) returned_length++;
    else if (!strcmp(scenario,"zero-seconds")) observation.kp_proc.p_starttime.tv_sec=0;
    else if (!strcmp(scenario,"negative-seconds")) observation.kp_proc.p_starttime.tv_sec=-1;
    else if (!strcmp(scenario,"negative-microseconds")) observation.kp_proc.p_starttime.tv_usec=-1;
    else if (!strcmp(scenario,"overflow-microseconds")) observation.kp_proc.p_starttime.tv_usec=1000000;
    else if (!strcmp(scenario,"zero-microseconds")) {
        observation.kp_proc.p_starttime.tv_usec=0;
        original=observation;
        expected=YES;
    }
    else if (!strcmp(scenario,"reparent-during-sysctl")) change_during_sysctl=YES;
    else if (!strcmp(scenario,"reparent-during-path")) change_during_path=YES;
    else if (!strcmp(scenario,"reparent-after-path")) change_on_parent_call=3;
    else { fprintf(stderr,"unknown scenario: %s\n",scenario); return 2; }
    BOOL actual=parent_matches(expected_pid,&original);
    if (actual!=expected) {
        fprintf(stderr,"FAIL %s: parent_matches=%d expected=%d\n",scenario,actual,expected);
        return 1;
    }
    // Initial acquisition must reject the same bad kernel snapshots too.
    if (!strcmp(scenario,"failed-sysctl") || !strcmp(scenario,"empty-sysctl") ||
        !strcmp(scenario,"partial-sysctl") || !strcmp(scenario,"oversized-sysctl") ||
        !strcmp(scenario,"wrong-pid") || !strcmp(scenario,"zombie") ||
        !strcmp(scenario,"unknown-status") || !strcmp(scenario,"out-of-range-status") ||
        !strcmp(scenario,"zero-seconds") || !strcmp(scenario,"negative-seconds") ||
        !strcmp(scenario,"negative-microseconds") || !strcmp(scenario,"overflow-microseconds")) {
        assert(!parent_snapshot(expected_pid,&original));
    }
    if (expected) assert(parent_matches(expected_pid,&original));
    printf("PASS %s\n",scenario);
    return 0;
}
