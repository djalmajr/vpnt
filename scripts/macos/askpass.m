#import <AppKit/AppKit.h>
#include <libproc.h>
#include <sys/proc_info.h>
#include <sys/proc.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include "native-catalogs.h"

static uint64_t monotonic_ns(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0 || now.tv_sec < 0) return 0;
    return (uint64_t)now.tv_sec * 1000000000ULL + (uint64_t)now.tv_nsec;
}
static BOOL parent_matches(pid_t pid, const struct proc_bsdinfo *original) {
    struct proc_bsdinfo info;
    char path[PROC_PIDPATHINFO_MAXSIZE];
    if (getppid() != pid || proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, sizeof(info)) != sizeof(info)) return NO;
    if (info.pbi_start_tvsec != original->pbi_start_tvsec || info.pbi_start_tvusec != original->pbi_start_tvusec || info.pbi_status == SZOMB) return NO;
    return proc_pidpath(pid, path, sizeof(path)) > 0 && strcmp(path, "/usr/bin/sudo") == 0;
}
static BOOL write_all(const void *bytes, size_t length) {
    const char *at=bytes;
    while (length) {
        ssize_t written=write(STDOUT_FILENO,at,length);
        if (written<0 && errno==EINTR) continue;
        if (written<=0) return NO;
        at+=written;length-=(size_t)written;
    }
    return YES;
}
int main(int argc, const char *argv[]) {
    (void)argv;
    // The only stdout consumer is sudo's private askpass pipe. Refuse direct
    // invocation before creating NSApplication or displaying a password field.
    struct stat output;
    struct proc_bsdinfo parent;
    pid_t pid=getppid();
    if (argc!=2 || getuid()==0 || geteuid()!=getuid() || fstat(STDOUT_FILENO,&output)!=0 || !S_ISFIFO(output.st_mode)) return 1;
    if (proc_pidinfo(pid,PROC_PIDTBSDINFO,0,&parent,sizeof(parent))!=sizeof(parent) || !parent_matches(pid,&parent)) return 1;
    const char *raw=getenv("VPNT_AUTH_UNTIL_NS"),*locale=getenv("VPNT_AUTH_LOCALE");
    if (!raw || !*raw || !locale || (strcmp(locale,"pt-BR")!=0 && strcmp(locale,"en-US")!=0)) return 1;
    for (const char *p=raw;*p;p++) if (*p<'0'||*p>'9') return 1;
    errno=0;uint64_t until=strtoull(raw,NULL,10),now=monotonic_ns();
    if (errno || !now || until<=now || until-now>120000000000ULL) return 1;
    @autoreleasepool {
        NSData *catalogData=[NSData dataWithBytes:vpnt_native_catalogs length:sizeof(vpnt_native_catalogs)];
        NSDictionary *catalogs=[NSJSONSerialization JSONObjectWithData:catalogData options:0 error:NULL];
        NSDictionary *catalog=catalogs[[NSString stringWithUTF8String:locale]];
        for (NSString *key in @[@"authTitle",@"authPrompt",@"authConfirm",@"authCancel"]) if (![catalog[key] isKindOfClass:[NSString class]]) return 1;
        NSApplication *app=[NSApplication sharedApplication];
        [app setActivationPolicy:NSApplicationActivationPolicyAccessory];
        [app finishLaunching];
        NSAlert *alert=[[NSAlert alloc] init];
        [alert setMessageText:catalog[@"authTitle"]];
        [alert setInformativeText:catalog[@"authPrompt"]];
        [alert addButtonWithTitle:catalog[@"authConfirm"]];
        NSButton *cancel=[alert addButtonWithTitle:catalog[@"authCancel"]];[cancel setKeyEquivalent:@"\033"];
        NSSecureTextField *password=[[NSSecureTextField alloc] initWithFrame:NSMakeRect(0,0,280,24)];
        [password setAccessibilityLabel:catalog[@"authPrompt"]];
        [alert setAccessoryView:password];[[alert window] setInitialFirstResponder:password];
        NSTimer *timer=[NSTimer timerWithTimeInterval:0.1 repeats:YES block:^(NSTimer *t) {
            (void)t;
            uint64_t current=monotonic_ns();
            if (!current || current>=until || !parent_matches(pid,&parent)) {[app abortModal];[[alert window] orderOut:nil];}
        }];
        [[NSRunLoop mainRunLoop] addTimer:timer forMode:NSModalPanelRunLoopMode];
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
        [app activateIgnoringOtherApps:YES];
#pragma clang diagnostic pop
        NSModalResponse response=[alert runModal];[timer invalidate];
        NSMutableData *value=[[[password stringValue] dataUsingEncoding:NSUTF8StringEncoding] mutableCopy];
        [password setStringValue:@""];
        uint64_t current=monotonic_ns();
        BOOL accepted=response==NSAlertFirstButtonReturn && current && current<until && parent_matches(pid,&parent) && value.length>0 && value.length<=16384;
        if (memchr(value.bytes,'\n',value.length)||memchr(value.bytes,'\r',value.length)||memchr(value.bytes,0,value.length)) accepted=NO;
        BOOL written=accepted && write_all(value.bytes,value.length) && write_all("\n",1);
        volatile unsigned char *clear=value.mutableBytes;
        for (NSUInteger i=0;i<value.length;i++) clear[i]=0;
        return written?0:1;
    }
}
