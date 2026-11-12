# Patches do runtime

`charon-private-pid.patch` modifica apenas `src/charon/charon.c` do strongSwan
6.1.0. Acrescenta `charon.vpnt_pid_file` e preserva o caminho compilado como
padrão. O futuro driver deve produzir essa configuração em diretório privado
root; o valor não vem do IPC normal.

Fonte: <https://download.strongswan.org/strongswan-6.1.0.tar.bz2>, SHA-256
`fe6c97481298767213cfc2e9a1da29fdd8018d481ff4cb9cf0283099654f20d4`.
O build restaura a fonte do arquivo verificado antes de aplicar o patch e
registra seu hash no manifest. A admissão Rust confere esse hash.

O patch segue a licença GPL-2.0-or-later de `charon.c`. A cópia de `COPYING`
do strongSwan acompanha o runtime em `licenses/strongswan.txt`.

`openfortivpn-no-routes.patch` modifica `src/tunnel.c` do openfortivpn 1.24.1:
a chamada corretiva `ipv4_drop_wrong_route` também passa a respeitar
`set_routes`. O driver desativa essas escritas para que seu controlador cuide
das rotas autorizadas. Um fixture executa o callback C com todas as escritas
interceptadas, sem privilégio ou interface real.

Fonte: <https://github.com/adrienverge/openfortivpn/archive/refs/tags/v1.24.1.tar.gz>,
SHA-256 `c40d33acd97b89c2e943bfd839c19b69e5a7a5997052e2fc9a595602745c0465`.
O patch segue a GPL-3.0-or-later de `tunnel.c`. `LICENSE` e a exceção OpenSSL
originais acompanham o runtime. A admissão Rust exige seu hash no manifest.
