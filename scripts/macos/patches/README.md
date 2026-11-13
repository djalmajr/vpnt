# Patches do runtime

O runtime privado compila strongSwan 6.1.0 com o backend `kernel-libipsec`
(`--enable-libipsec --enable-kernel-libipsec`, `--disable-kernel-pfkey`) e
aplica exatamente cinco patches, nesta ordem:
`charon-private-pid.patch`, `strongswan-utun-framing.patch`,
`strongswan-libipsec-no-routes.patch`, `charon-parent-eof.patch`,
`strongswan-retain-utun.patch`. A fonte é
sempre reextraída do tarball verificado; o build não reutiliza árvore de build
gerada para outro backend ou outro conjunto de patches. O manifest declara
`strongswan.backend = "kernel-libipsec"` e o hash exato dos cinco patches, e a
admissão Rust recusa backend ausente/divergente, patch faltante ou hash
alterado.

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

`openfortivpn-bound-transport.patch` modifica `config.h`, `config.c`, `main.c`
e `tunnel.c` da mesma versão. Acrescenta os metadados privados `--vpnt-ifindex`
e `--vpnt-gateway-ip`. O IP já resolvido fixa o destino TCP; o hostname continua
intacto para validação TLS/SNI. No Darwin, `--ifname` passa a exigir
`IP_BOUND_IF`, além do bind da origem. Um índice divergente, erro de vínculo
ou mudança de índice/origem após o connect fecha o socket sem fallback.
O driver não permite que o peer de IPC forneça esses metadados: recebe um
token de saída produzido por consultas nativas de rota/interface.

O build executa o consumidor TCP C real com um listener em loopback. O script
`../check-transport-consumer.py` repete os seis cenários e três mutações numa
cópia descartável da fonte verificada; DNS é interceptado para que a mutação
não faça lookup externo. O mesmo licenciamento do openfortivpn se aplica.
O hash deste patch também é obrigatório na admissão do runtime.

`openfortivpn-ppp-supervisor.patch` modifica o `pppd_run` Apple em `tunnel.c`
da mesma versão: executa somente o caminho fixo
`/Library/PrivilegedHelperTools/dev.vpnt.pppd`, sem fallback para pppd direto.
Registra PID/PTY próprios antes de uma possível falha de fcntl. O supervisor
recebe o FD 4 herdado; seu receptor e o canal de senha FD 3 são preparados
juntos pelo driver. O hash deste terceiro patch do openfortivpn é obrigatório
no manifest e na admissão Rust. O mesmo licenciamento GPL-3.0-or-later se aplica.

`../check-ppp-supervisor.py` aplica o patch ao tarball verificado e troca apenas
o caminho do executável por um supervisor de fixture. Exercita o forkpty/argv
C real, um payload PPP fictício e tanto o receptor independente quanto o
produtivo. O runtime nativo foi recompilado e admitido com esse patch; não foi
instalado e nenhum pppd do sistema foi executado. A auditoria de configuração
global e scripts resultou num gate de recusa de arquivos ambientes no supervisor;
sua validação instalada/root com pppd real continua pendente.

`strongswan-utun-framing.patch` modifica `src/libstrongswan/networking/tun_device.c`
do mesmo 6.1.0. No Darwin, o frame do utun leva um prefixo de 4 bytes com a
família do protocolo; o código original assumia IPv4. O patch passa a escolher
`AF_INET`/`AF_INET6` pelo nibble de versão do pacote, recusa pacote vazio ou de
versão desconhecida e lê no máximo MTU + prefixo + 1 byte, recusando datagrama
maior em vez de truncá-lo em silêncio. O parser do pacote IP continua sendo o
do chamador. Limite: este patch não é exercitado por tráfego real nem cria
utun neste repositório; o fixture alimenta os bytes e confere o prefixo.

`strongswan-libipsec-no-routes.patch` modifica
`src/libcharon/plugins/kernel_libipsec/kernel_libipsec_ipsec.c` do mesmo 6.1.0.
O backend instalava rotas para políticas de saída ignorando
`charon.install_routes`; o patch faz `install_route` retornar sem escrever
quando a opção é falsa (o padrão continua verdadeiro, preservando o
comportamento upstream para quem não desativa). Com o runtime vpnt, o helper
instala e remove as rotas que autorizou. Limite: nenhuma rota real é escrita ou
verificada aqui; a alternativa de pré-adicionar a rota para obter
`ALREADY_DONE` continua sendo uma decisão de integração.

`charon-parent-eof.patch` modifica apenas `src/charon/charon.c`. Acrescenta a
opção privada `charon.vpnt_parent_eof` (padrão `false`), lida depois do parsing
de CLI e da admissão de settings, antes de `charon->initialize` — portanto antes
de plugins, utun ou SAs. Quando ligada, o FD 0 precisa ser um pipe anônimo,
somente leitura (`S_ISFIFO`, `st_nlink == 0`, `O_RDONLY`); o helper mantém a
única ponta de escrita, com `CLOEXEC`. Nenhum dado trafega: EOF, qualquer byte
ou erro de leitura encerram o processo com `_exit(não zero)`, sem init, sinais
ou `deinit`. Falha de admissão ou de criação da thread também encerra antes dos
plugins. A parada normal continua sendo VICI + o stop gracioso/forçado do
`ManagedChild`; este caminho abrupto existe só para a perda da capacidade
privada, e deixa PID/journal privados para a recuperação do helper. Limite: não
há teste com charon real, login item ou morte de processo pai neste repositório;
as provas atuais são de fixture, com filhos próprios e pipes anônimos.

`strongswan-retain-utun.patch` modifica apenas
`src/libcharon/plugins/kernel_libipsec/kernel_libipsec_plugin.c`. Acrescenta a
opção privada `charon.plugins.kernel-libipsec.vpnt_retain_utun` (padrão
`false`). Quando ligada, depois do `tun_device_create` + `set_mtu` + `up` e
antes de `lib->set`/publicação, envia o fd original do tun em um único
datagrama `AF_UNIX`/`SOCK_DGRAM` no FD 3 herdado (`SCM_RIGHTS`, payload VPUFv1
de 8 bytes), marca o fd do tun com `FD_CLOEXEC`, valida família/tipo/conexão e
fecha o fd 3 em toda saída habilitada. Canal inválido, falha de flags ou de
`sendmsg` destrói o tun e retorna `NULL` antes da publicação. Desligada, não
toca o fd 3 nem o fd do tun. A verificação do builder procura o literal
`.plugins.kernel-libipsec.vpnt_retain_utun` no `bin/charon`; o manifest inclui
o hash deste quinto patch. Limite: o fixture C valida o construtor e o handoff
com pipe/socketpair, sem charon ou UTUN real.
