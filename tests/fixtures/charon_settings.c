// Link only libstrongswan's original parser; never load plugins or libcharon.
#include <library.h>
#include <settings/settings.h>
#include <stdio.h>
#include <string.h>
#define demand(yes) do { if (!(yes)) { fprintf(stderr, "settings assertion: line %d\n", __LINE__); return 1; } } while (0)
int main(int argc, char **argv) {
    demand(argc == 3);
    demand(library_init(argv[1], "vpnt-settings-fixture"));
    settings_t *settings = settings_create(NULL);
    demand(settings != NULL && settings->load_files(settings, argv[1], FALSE));
    demand(!settings->get_bool(settings, "charon.load_modular", TRUE));
    demand(settings->get_int(settings, "charon.port", -1) == 0);
    demand(settings->get_int(settings, "charon.port_nat_t", -1) == 0);
    demand(!settings->get_bool(settings, "charon.install_routes", TRUE));
    demand(!settings->get_bool(settings, "charon.install_virtual_ip", TRUE));
    demand(settings->get_bool(settings, "charon.vpnt_parent_eof", FALSE));
    char expected[1024];
    snprintf(expected, sizeof(expected), "%s/pid", argv[2]);
    demand(strcmp(settings->get_str(settings, "charon.vpnt_pid_file", "missing"), expected) == 0);
    snprintf(expected, sizeof(expected), "unix://%s/v", argv[2]);
    demand(strcmp(settings->get_str(settings, "charon.plugins.vici.socket", "missing"), expected) == 0);
    demand(strcmp(settings->get_str(settings, "charon.load", "missing"),
        "aes des sha1 sha2 md4 hmac kdf random nonce openssl eap-identity eap-mschapv2 kernel-libipsec kernel-pfroute socket-default vici") == 0);
    demand(settings->get_int(settings, "charon.filelog.stderr.default", 99) == -1);
    demand(settings->get_int(settings, "charon.syslog.daemon.default", 99) == -1);
    demand(settings->get_int(settings, "charon.syslog.auth.default", 99) == -1);
    settings->destroy(settings);
    library_deinit();
    puts("original settings parser admitted isolated configuration");
    return 0;
}
