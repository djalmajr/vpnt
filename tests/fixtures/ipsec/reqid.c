#include <sys/types.h>
#include <net/pfkeyv2.h>
#include <netinet6/ipsec.h>
#include <limits.h>
#include <stdio.h>

int main(void) {
    printf("{\"bits\":%zu,\"manualMax\":%u}\n",
        sizeof(((struct sadb_x_ipsecrequest *)0)->sadb_x_ipsecrequest_reqid) * CHAR_BIT,
        (unsigned)IPSEC_MANUAL_REQID_MAX);
    return 0;
}
