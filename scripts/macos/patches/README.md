# Patch do runtime strongSwan

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
