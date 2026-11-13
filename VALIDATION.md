# Validação

Este contrato separa o protótipo estático, o host, os fluxos de demonstração
e a futura camada de VPN real. Nenhuma evidência de demonstração prova uma VPN.

## Código do app

Na raiz do repositório, após instalar as dependências da UI:

```bash
cd ui
bun run lint
bun run typecheck
bun test
bun run build
cd ..
bun scripts/design/check-tokens.ts
bun scripts/design/check-classes.ts
cargo fmt --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-targets --all-features
cargo test --locked --no-default-features
cargo build --locked
python3 scripts/macos/package-app.py --replace
python3 scripts/macos/build-askpass.py
```

O gate de tokens compara as 81 entradas mapeadas em `DESIGN.md` com o CSS.
O gate de classes ainda não tem classes proibidas configuradas; sua execução
não representa cobertura de estilos. O teste de CSS rejeita ciclos diretos em
variáveis, que podem anular medidas mesmo quando os nomes coincidem.

O checkpoint integrado final (`5222128`) passou fmt, clippy com `-D warnings`, build,
308 testes desktop e 292 core (dois ignored por suíte) e a matriz de 42
mutações do codec PF_KEY. Na UI, lint, typecheck, oito testes (114 assertions),
build e 81 tokens passaram; o gate de classes segue sem regras. O recibo em
`output/fixtures/final-checkpoint-receipt.json` registra `sourceUnchanged=true`,
`realVpn=false` e `privilegedInstall=false`; os logs `final-checkpoint-*` e
`final-ui-*` acompanham cada etapa e limite.

O teste de HTTP executa um processo filho do servidor de demonstração e usa
somente loopback. Precisa de permissão de socket. Ele verifica origem/Host,
rejeição de JSON ambíguo, sobrevivência a UTF-8 inválido e uma resposta posterior
válida. Os testes de sessão exercitam tokens de geração, cancelamento, reconexão
e classificação de resultados sem subprocessos de VPN.

O CI em `.github/workflows/check.yml` repete os checks de macOS e do núcleo
portável em Linux. Preparar o workflow e executar checks locais não equivale
a uma execução verde no GitHub; esta exige envio e execução no serviço.

## Persistência, chaveiro e protocolo

O broker normal já consome o protocolo e o chaveiro; o caminho instalado ainda
não foi exercitado. Para executar os testes isolados dessa camada no macOS:

```bash
cargo test --locked --no-default-features --test storage --test profiles --test secrets --test keychain --test helper_protocol --test runtime_policy --test vici
```

Storage usa somente `output/fixtures/`, com proprietário do processo para o
fixture. Produção usa proprietário root e uma árvore fixa por UID. Verificar
persistência/remoção, atualizações concorrentes, diretórios e arquivos privados,
links, arquivo especial que não possa bloquear a leitura, limites e dados
inválidos. O teste sem privilégio não substitui a validação do helper instalado
contra arquivos de proprietários diferentes.

No macOS, os testes criam ACLs descartáveis: uma permissão de escrita deve ser
rejeitada no executável mesmo com modo `0555`, e uma permissão de leitura deve
ser rejeitada no perfil mesmo com modo `0600`. ACLs que apenas negam acesso nos
ancestrais permanecem válidas. Nenhuma ACL pessoal é modificada.

O teste nativo de chaveiro cria uma base descartável com dados fictícios. Usa
esse handle para salvar, ler, atualizar, bloquear/desbloquear e remover; verifica
ao final que o chaveiro padrão e a lista de busca permanecem iguais. Não imprime
a lista pessoal. Pode precisar de execução fora do sandbox para acessar
Security.framework; uma falha de criação no sandbox não deve ser reportada como
teste nativo aprovado. O teste de segredos cobre redigir Debug e validar os
valores na fronteira de entrada dos clientes.

O protocolo normal oferece snapshot, conectar, desligar e testar por ID de
perfil/geração. O canal administrativo é separado e exige EOF após um único
documento antes de retornar uma operação executável. Testar mensagens
fragmentadas, limites, versões incompatíveis, ações/campos desconhecidos e
tentativas de cruzar os canais. Esses testes de codec não provam elevação,
processos de VPN ou instalação de sudoers.

## Preferências nativas e abertura no login (em integração)

```bash
cargo test --locked --no-default-features --test preferences --test bridge --test application
cargo test --locked --no-default-features --lib broker::preferences_tests
cargo test --locked --offline --all-features --lib broker::component::tests::lifecycle::preferences
cargo test --locked --offline --all-features --lib desktop::login_item
```

[PASS, portable contract] Sete testes públicos verificam os defaults da UI,
os intervalos inteiros 10/30/60, conversão e rejeição de campos desconhecidos,
ausentes ou mal tipados. Seis mutações foram detectadas em cópia isolada, com
baseline e restauração; o manifesto fica em
`output/fixtures/preferences-contract-commit-evidence.json` e os logs/drivers
em `output/fixtures/preferences-contract/`. Esse valor entrou no checkpoint
`cc2e837`; o intake, em `8e7b769`.

[PASS, bridge e broker] A ponte aceita o comando com o tipo validado e exige
objeto no campo de preferências: a forma posicional que o serde do valor também
aceita é recusada por um decodificador próprio da ponte, sem segundo schema. O
`Snapshot` sempre ecoa a escolha. O app de demonstração guarda os quatro valores
em memória, sem chaveiro, helper ou OS, e o app normal continua recusando
mutações não-demo. O broker guarda e ecoa a escolha depois dos gates de
expiração e de componente ocupado, e recusa `startup=true` com
`startup_unavailable` até o adaptador de login ser ligado, preservando os quatro
valores anteriores. Provas: dois testes de ponte, quatro privados do broker e um
no fixture real de componente (operação viva, `component_busy` sem alterar
escolhas, filho próprio concluído). Sete mutações nomeadas do intake e a que
isenta o comando do gate de componente falham no teste previsto; logs em
`output/fixtures/preferences-intake/` e
`output/fixtures/preferences-component-gate/`.

[PASS, adaptador de login preparado] O adaptador nativo usa somente
`SMAppService` (ServiceManagement, macOS 13+) e compila/liga no desktop, com
doze testes de lógica — inclusive a recusa do binário de teste sem bundle — e
doze mutações nomeadas na fonte final (checkpoint `5222128`), reproduzíveis com
`cargo test --locked --offline --all-features --lib desktop::login_item`; logs e
recibo em `output/fixtures/login-item-final/`. Ele não é chamado pela UI nem
pelo broker: nada registra, desregistra ou abre System Settings.

[NOT RUN, efeitos e serviço real] Helper, UI e persistência ainda não consomem
o comando; intervalo efetivo de probe, notificações, reconexão automática e
abertura no login não têm efeito ligado. `register`, `unregister`, `status`,
aprovação em System Settings e falha de assinatura de um login item real não
foram executados. O ramo macOS < 13 de `available!` continua NOT RUN: o guard
está presente e é a primeira instrução da admissão, sem seam artificial.

## IPsec: transporte de leitura PF_KEY (em integração)

```bash
cargo test --locked --no-default-features --lib connection::ipsec::pfkey::read
python3 scripts/macos/check-pfkey-reader.py
```

[PASS, native process/socket + memory fixtures] Nove testes exercitam o coletor
e send/recvmsg produtivos em AF_UNIX com peer C independente do SDK. O peer
valida o pedido fechado e permanece vivo até liberação explícita. SAD/SPD,
PID/tipo alheios, vazio/errno, prefixo incompleto, duplicação/lacuna, extra após
término, prazo, cancelamento e rebase de deadline depois do envio são cobertos.
Fixtures de memória verificam os limites de 4096 datagramas/16 MiB e a limpeza
do buffer antes de seu reuso. Gate UID negativo, flags CLOEXEC/NONBLOCK e
truncamento de payload são nativos; o formato de endereço AF_KEY positivo é
sintético. Nenhum PF_KEY real é aberto.

[PASS, negative oracles] Baseline e restauração 9/9; quarenta e uma mutações
detectadas por assertions previstas, cada uma no teste nomeado, e 261 hashes de
entrada conferidos. Recibo e logs em output/fixtures/pfkey-reader-oracles/.
O workflow inclui o comando, ainda sem execução remota. O buffer Zeroizing
também cobre descarte por erro; não há payload de chave no DTO. A proteção
MSG_CTRUNC não foi exercitada nativamente: o recvmsg sem buffer ancillary usado
aqui não reproduziu essa flag no macOS. A matriz anterior de 40 casos permanece
arquivada em output/fixtures/pfkey-reader-initial-40/, sem alteração.

[PASS, temp e admissão] Sob um TMPDIR 0755 do próprio usuário, o caso de
admissão (ordinary_uid_cannot_admit_a_reader...) prova o parent aceito e a
folha 0700; o caso de recvmsg apenas confirma que o caminho nativo não depende
de TMPDIR. Log em output/fixtures/pfkey-reader-tmp0755.log.

[PASS, checkpoint integrado] O leitor entrou no checkpoint a046191. A suíte
final passou 308 testes desktop e 292 core, dois ignored por suíte, com fmt,
clippy -D warnings e build; a matriz do codec PF_KEY de 42 mutações passou
baseline/restauração. O recibo integrado registra sourceUnchanged=true,
realVpn=false e privilegedInstall=false. A reescrita de lint equivalente
(matches!) no adaptador de login é posterior somente à matriz de 41 casos do
leitor — drift contextual registrado nessa reconciliação — e anterior aos gates
integrados finais, que já rodaram com a fonte final; as fontes do leitor seguem
idênticas.

[FAIL, historical] A primeira rodada core falhou em quatro fixtures existentes:
IPsec persistent_phase, dois casos de prazo SSL e pending claim Busy. O log
original foi preservado. Os quatro passaram isolados e no rerun limitado com
quatro threads; contenção é hipótese e as causas originais de Unavailable/Busy
não foram demonstradas. Nenhum teste, assertion ou deadline foi alterado; o job
macOS limita RUST_TEST_THREADS a 4 para reduzir a concorrência entre fixtures,
e testes de concorrência continuam criando seus próprios processos/threads.
A execução local anterior do leitor (281 testes) e a integração preliminar
(288/284) ficam registradas apenas como histórico, substituídas pelo checkpoint
integrado acima.

[NOT RUN, privileged/real] Abertura PF_KEY, origem real do kernel, tamanho do
buffer do socket e dump SAD/SPD reais não foram exercitados. Collection e
ProtocolEnd registram término observado; seq0 ou ENOENT não concedem completude,
propriedade, KernelClaims ou autoridade de cleanup. Antes do uso em runtime,
permanece pendente a atomicidade entre a criação do descritor PF_KEY e o spawn
de filhos. Recuperação, leases VIP/rotas, probe e dispatch IPsec continuam em
integração. Nenhum componente foi instalado, elevado, conectado ou publicado.
O .app preservado ainda é do checkpoint 692489d.

## IPsec: metadados PF_KEY Darwin (checkpoint 3bf9738)

```bash
cargo test --locked --no-default-features --lib connection::ipsec::pfkey
python3 scripts/macos/check-pfkey.py
```

[PASS, SDK/process fixture] Seis testes usam datagramas binários produzidos por
C independente compilado contra o SDK Darwin. Conferem ABI, SA/SA2/lifetime,
políticas e cadeias de requests, IPv4/IPv6, escopo KAME e seletores normais/range.
SPI e portas sockaddr são de rede; reqid SA2 conserva 32 bits nativos, sem
truncar para a faixa do allocator. O request de política tem tamanho em bytes,
enquanto frame/extensões usam unidades de oito. reserved/refcount não exige zero.

Frames completos passam por versão/tipo/satype/tamanho, duplicação e limites
de 64 extensões/requests; padding, prefixos, famílias, ranges e modos/protocolos
ambíguos são recusados. Extensões não interpretadas são marcadas por tipo.
Errno continua resposta explícita e não vira snapshot vazio. Chaves/identidades
e payloads desconhecidos não integram o DTO/Debug retornado. O codec apenas
empresta o input; o futuro leitor deve possuir e limpar o buffer bruto.

[PASS, original consumer] Declaração sadb_sa_2 e atribuição de porta extraídas
do strongSwan 6.1.0 com SHA fixado são compiladas com um host fictício. Dois
casos IPv4/IPv6 atravessam o codec produtivo e confirmam que a porta privada
NAT-T é nativa, diferente de sockaddr. O getter original retorna ntohs; isso
foi inspecionado, sem executar daemon. Entrada do consumidor Rust fica em
Zeroizing; o runner conserva assertions/logs, sem persistir datagramas brutos.

[PASS, negative oracles] Quarenta mutações detectadas por assertions nos seis
testes previstos e duas por assertions do consumidor original NAT-T, ambas
em IPv4/IPv6. Baselines/restaurações SDK e original passaram; 241 hashes de
entrada conferidos. Recibos/logs em output/fixtures/pfkey-codec-oracles/.
O workflow inclui esse gate, sem execução remota.

[PASS, local] 273 testes Rust com desktop e 269 sem desktop, em sequência;
dois ignored (runtime opcional e harness de crash exercitado pelo pai). Fmt,
clippy all-targets/all-features -D warnings, build dos binários e sintaxe
Python/YAML passaram.
Logs em output/fixtures/pfkey-codec-*. UI/catálogos/dependências/patches não
mudaram; provas visuais e consumidores existentes mantêm os checkpoints
anteriores. Matrizes de VICI/produtor/componente/C/PPP não foram repetidas nesta
mudança de codec. Sem benchmark de performance.

[NOT RUN] Nenhum socket PF_KEY aberto, dump/table do kernel lido, charon/plugin,
claim reconciliado, VIP/rota/probe, instalação ou VPN executados. Pacote validado
não é lote completo, ausência observada, propriedade ou autorização de cleanup.
Leitor/transporte, completude SAD/SPD, recuperação e integração B2/C continuam
necessários. UI/catálogos/dependências/patches e consumidores existentes não
mudaram; .app/payload preservados no checkpoint 692489d.

## IPsec: veto de componentes com admissões pendentes (f69a772)

```bash
cargo test --locked --no-default-features --lib install::engine::tests::pending
python3 scripts/macos/check-installation-engine.py
```

[PASS, native filesystem/process fixture] Dois testes atravessam activate/remove
do executor produtivo, em árvores privadas de usuário comum. Qualquer entrada
em state/ipsec bloqueia as operações antes de recuperar/coletar o journal,
mesmo com ControllerLock disponível. Prepared/Starting/Running/Stopped e dados
desconhecidos preservam componentes, recibos, políticas e journal; Stopped não
significa cleanup comprovado. Diretório ausente ou privado/admitido vazio
permite a operação. Não há leitura de PID, conteúdo ou alvo da entrada.

Arquivo/symlink no lugar do diretório, modo inseguro e ACL com grant são
recusados. FIFO dentro da árvore é presença pendente, sem abrir o nó. Os testes
comparam bytes/modos/inodes instalados e comprovam que a coleta do journal só
prossegue após remover a admissão fictícia por limpeza explícita do fixture.
Nenhuma limpeza de claim foi adicionada ao instalador.

[PASS, local] 267 testes Rust com desktop e 263 sem desktop, em sequência;
dois ignored (runtime opcional e harness de crash exercitado pelo pai). Fmt,
clippy all-targets/all-features -D warnings, build dos binários e sintaxe
Python/YAML passaram.
A matriz do executor detectou 32 mutações, incluindo oito oráculos do veto,
com quatro baselines/restaurações e 232 hashes de entrada conferidos. Dois
oráculos antigos do lock foram adaptados ao guard obrigatório; falha de
compilação não conta como detecção. Logs em output/fixtures/ipsec-pending-*;
recibo em output/fixtures/installation-engine-oracles/. O recibo anterior
foi preservado antes da reexecução. Sem benchmark de performance.

Parser strongSwan, consumidores C/PPP e matrizes de produtor/VICI mantêm o
checkpoint 28eb90a nos caminhos inalterados; não foram reexecutados nesta
mudança do executor. Os oito casos nativos do produtor também passaram nas
suítes Rust completas. O workflow já executa a matriz ampliada; CI remoto
continua sem execução.

[NOT RUN] Instalação/remoção elevadas, caminho root/PackageKit/PAM e VPN real.
Observador SAD/SPD, recuperação de claims, leases de VIP/rotas e integração
IPsec/SSL continuam necessários. Veto de componente não prova ausência de
recursos no kernel e não habilita IPsec. UI/catálogos/dependências/patches
inalterados; .app/payload preservados no checkpoint 692489d.

## IPsec: produtor nativo e admissão durável (B1, 28eb90a)

```bash
cargo test --locked --no-default-features --lib connection::ipsec
python3 scripts/macos/check-ipsec-producer.py
# Requer os artefatos locais verificados de build-runtime.py; não instala:
python3 scripts/macos/check-charon-config.py
```

[PASS, native process/socket/filesystem fixture] Oito testes do produtor usam
um executável Mach-O C fictício, sem charon ou VPN. NativeContext produtivo
recusa usuário comum antes de criar estado; somente cfg(test) admite o runtime
do fixture. Configuração conserva o selo da reserva. Claim privado e configuração
sem segredos são escritos e sincronizados antes do primeiro spawn. O observador
inclui claims não representados após recriar o contexto; Drop/exit não os apagam.
Isso prova retenção conservadora, sem implementar ainda recuperação após crash.

O produtor confere processo original por PID/nascimento/pai/UID/executável,
socket privado por inode/modo/ACL e peer PID/UID obtidos do kernel. O PIDfile
nunca autoriza sinais ou posse. Alteração de configuração, inode ou permissão
recusa IO, mas ainda encerra o próprio Child. Prazo/cancelamento mantêm esse
filho vivo até retirement explícito. O socket preexistente permanece intacto
e a admissão continua Prepared, sem filho. A máquina persistente não retorna
a uma tentativa anterior. Uma falha do gancho de conclusão durável conserva
a reserva; seu teste verifica a ordem stopped, observação nova, conclusão.
As observações SA/SPD/rotas/VIP ainda são injetadas, não leituras nativas.

[PASS, original settings parser] Dois casos compilam o renderer e validador
de caminhos produtivos, depois carregam a saída pelo parser da libstrongswan
6.1.0 preparada. O script confere o arquivo fonte fixado e registra hashes
da biblioteca estática/config.h/crypto preparados, sem carregar plugins ou
executar charon. Verifica caminhos com espaços, PID/socket próprios, portas
aleatórias, plugins fixos e ausência de rotas/VIP automáticos. Ausência dos
artefatos é erro, nunca skip silencioso. Gate local separado do workflow:
o job normal ainda não prepara essa biblioteca estática.

[PASS, pinned native consumers] A mudança em ManagedChild foi revalidada por
12 cenários do leitor C de senha e 25 cenários de supervisão PPP/forkpty/exec,
com valores e programas fictícios. Nenhum system pppd, interface ou rota criada.
Logs em output/fixtures/ipsec-producer-{pinentry,ppp,settings}.log.

[PASS, negative oracles] Trinta mutações detectadas por assertions executadas
nos testes previstos, com baseline/restauração em cópia descartável. Os 230
hashes de entrada conferem. A primeira rodada deixou escapar o gate do socket
preexistente; exigir Prepared/child ausente tornou a falha discriminante.
Recibos/logs finais em output/fixtures/ipsec-producer-oracles/; a primeira
rodada e a matriz anterior à barreira de cancelamento foram preservadas.
O workflow inclui a matriz do produtor, sem execução remota.

[PASS, local] 265 testes Rust com desktop e 261 sem desktop; dois ignored
(runtime opcional e harness de crash exercitado pelo pai). As suítes completas
passaram em sequência. A primeira execução simultânea falhou em arranque/prazo
do fixture; logs em ipsec-producer-{desktop,core}-concurrent-failure.log.
Os oito casos passaram isolados, e a barreira de cancelamento passou a esperar
a inicialização real do filho fictício. O teste explícito de prazo continua
em 150 ms sobre esse mesmo filho, sem reiniciar a tentativa. Fmt/clippy
all-targets/all-features -D warnings, build Rust e sintaxe Python/YAML passaram. Logs em
output/fixtures/ipsec-producer-*; nenhum benchmark de performance executado.
UI/tokens/catálogos mantêm os checkpoints anteriores, sem nova prova visual;
as matrizes A1/A2/transporte não foram repetidas nesta B1.

[NOT RUN] Daemon charon, observador SAD/SPD nativo, recuperação/conclusão de
claims após crash, leases de VIP/rotas, origem/probe e Factory/dispatch IPsec.
Antes de habilitar IPsec, instalação/remoção também deve recusar claims
pendentes, inclusive após perda do controlador. install_virtual_ip=no deixa
o endereço sob responsabilidade futura do helper; não foi provado um VIP.
Nenhuma instalação, elevação, configuração de VPN ou publicação. O .app/payload
conservado continua em 692489d; UI/catálogos/dependências/patches não mudaram.

## IPsec: controle VICI e snapshots (checkpoint A2, bb01b21)

```bash
cargo test --locked --no-default-features --lib connection::ipsec
python3 scripts/macos/check-ipsec-control.py
```

[PASS, process/socket fixture] Dez testes novos exercitam Control pelo cliente
VICI produtivo contra um processo Python independente. O daemon de teste valida
quadros/comandos/alvos e credenciais fictícias. Observações SA/SPD e confirmação
do produtor no Registry são injetadas: não são leituras de kernel ou de charon.

Config conserva um selo privado da autoridade/serial da reserva. O construtor
recusa configuração de outra admissão e devolve a reserva ao chamador. Versão
charon/6.1.0 precede qualquer segredo no canal; load-conn e os dois load-shared
precedem uma nova observação do namespace e initiate. A tentativa é consumida
mesmo após erro/cancelamento/prazo. Erros não repassam errmsg do peer. O registro
não fica bloqueado durante IO VICI. Initiated não é Connected nem prova de tráfego.

Cleanup usa um prazo novo, tenta terminate/unload apenas nos nomes fechados e
marca incerteza antes da primeira carga. Uma falha antes de initiate também
recebe terminate direcionado, pois a ausência de resposta não desfaz efeitos
remotos. Comandos de cleanup não são repetidos. O produtor original recebe
retirement mesmo se o registro falhar; só saída observada e ausência no
observador liberam a reserva. Erro/Drop não liberam automaticamente o namespace.

list-sas é consultado sem noblock; só uma resposta final vazia completa o lote.
O conjunto inteiro passa por nomes, IKEv2, endpoints, IDs únicos/canônicos,
reqid, modo TUNNEL/ESP, SPIs não zero/únicos, VIPs e seletores locais/remotos.
Há limite de 256 filhos; redes remotas devem caber nas solicitadas e seletores
locais devem ser hosts VIP. Lote malformado não publica prefixo válido. Rekey
com duas IKE_SAs é aceito; filhos transitórios sem SPIs não são instalados.
Os campos instalados e o modo em maiúsculas seguem vici_query.c/ipsec_types.c
fixados em strongSwan 6.1.0. Campo active é relato do daemon, sem autoridade
para alterar recursos nativos. Consulta vazia não prova conexão ou cleanup.

Red/Green executados para selo de admissão, candidatos de rekey e retirement
após falha do registro. Os casos incluem seis prefixos de erro, prazo e
cancelamento com produtor vivo, cleanup sem replay, presença/ausência injetada,
rekey/transição, IPv4/IPv6/vazio e 30 formas inválidas de snapshot.

[PASS, negative oracles] 46 mutações detectadas por assertions executadas nos
testes previstos, com baseline/restauração em cópia descartável. Recibo/logs em
output/fixtures/ipsec-control-oracles/; os 216 hashes de entrada conferem.
O CI inclui o gate, sem execução remota. Matrizes A1 e de transporte conservam
seus checkpoints; não foram reexecutadas nesta fase. O runner A1 agora explicita
que sua baseline também inclui os peers de controle, sem alterar as 42 mutações.

[PASS, local] 256 testes Rust com desktop e 252 sem desktop; dois ignored
(runtime opcional e harness de crash exercitado pelo pai). Fmt, clippy
all-targets/all-features -D warnings e sintaxe Python passaram. Logs em
output/fixtures/ipsec-control-{desktop,core,clippy,cases}.log e recibo do
commit em output/fixtures/ipsec-control-commit-evidence.json. A validação
do transporte e dos consumidores C/PPP é reaproveitada de f241d39 nos caminhos
inalterados; não é uma nova execução dessas matrizes ou de VPN real.

[NOT RUN] Não há Peer nativo, charon executado, claims duráveis após falha do
helper, observador SA/SPD, prova de origem/probe, Factory/dispatch IPsec ou VPN
real nesta etapa. Esses itens continuam necessários antes de habilitar IPsec.
Nenhuma instalação, elevação, configuração de VPN ou publicação foi feita.
.app/payload conservado pertence a 692489d. UI/catálogos/dependências/patches
não mudaram; validação visual e consumidores C/PPP mantêm seus checkpoints.

## VICI: prazo absoluto e cancelamento (checkpoint f241d39)

```bash
cargo test --locked --no-default-features --test vici --test vici_deadlines
python3 scripts/macos/check-vici-deadlines.py
```

O cliente conserva um único prazo absoluto desde connect/from_stream até a
resposta. Os construtores *_until também recebem prazo e cancelamento do
chamador. O transporte consulta o sinal em intervalos de poll de até 25 ms;
isso não desfaz um comando já enviado nem comprova cleanup no daemon/kernel.
Timeout e cancelamento são erros distintos, sem repassar texto do peer.

[PASS, socket/process fixture] Cinco testes novos exercitam o consumidor público.
Um teste falhou antes da correção: aguardar após from_stream reiniciava o prazo
em command e enviava uma solicitação expirada. Agora o peer não recebe bytes.
Um listener Unix real verifica UID, cancelamento antes/depois da admissão,
prazo e path absoluto. Um peer Python independente verifica respostas válidas
e mantém o próprio processo/canal vivo durante cancelamento de resposta,
cabeçalho parcial, confirmação de assinatura e escrita bloqueada. A escrita
cancelada deixa o corpo incompleto. O peer usa uma barreira separada, prazo
próprio finito e espera pelo Child; testes não o matam para produzir o resultado.
Também distinguem abort de IO nativo do marcador privado de cancelamento.

[PASS, negative oracles] Dez mutações detectadas por assertions executadas nos
testes previstos, com baseline/restauração em cópia descartável. Recibo, hashes
e logs em output/fixtures/vici-deadline-oracles/. O workflow inclui esse gate;
isso não é uma execução remota do CI. A evidência A1 abaixo conserva seu
checkpoint histórico; a matriz A1 não foi repetida nesta mudança de transporte.

[PASS, local] 246 testes Rust com desktop e 242 sem desktop; os dois ignored
continuam sendo o runtime opcional e o harness de crash exercitado pelo pai.
Fmt, clippy all-targets/all-features -D warnings e sintaxe Python passaram.
Os 207 hashes de entrada da matriz conferem com o estado final.

[PASS, pinned native consumers] Revalidados 12 cenários do leitor de senha C
do openfortivpn e 25 cenários PPP/forkpty/exec com programas e dados fictícios.
A primeira revalidação PPP falhou na resolução do novo submódulo ao incluir
local_socket.rs fora do crate; o path explícito corrigiu a compilação isolada.
Log anterior em output/fixtures/vici-deadline-ppp-red.log. UI, catálogos,
dependências e patches não mudaram; nenhuma nova validação visual foi feita.

[NOT RUN] Sem charon, admissão nativa por PID/socket/generation, comandos de
ciclo de vida IPsec, observação SA/SPD ou VPN real. O teste de listener não
força um connect pendente por backlog cheio. IPsec continua indisponível no
broker/helper até integrar processo, kernel, probe e cleanup. Esta mudança
não reempacota o .app/payload conservado do checkpoint 692489d.

## IPsec: identidade, namespace e mensagens preparadas (checkpoint A1)

```bash
cargo test --locked --no-default-features --lib connection::ipsec
python3 scripts/macos/check-ipsec.py
```

[PASS, contract + SDK] Nove testes exercitam o registro de reservas e as mensagens
construídas, usando o codec VICI produtivo. Não existe observador de kernel
nativo nesta fase: os conjuntos de reqids e o encerramento do produtor são
injetados. Reservas são opacas, vinculadas à instância/token e UID/perfil/geração;
recusam conflito externo/local, reuso antes de cleanup, token alheio/antigo,
falha de observação, excesso de 64 perfis e namespace maior que 16 bits.
Ausência de SA/SPD sem encerramento do produtor não libera o slot.
Observadores futuros também precisam incluir admissões duráveis incompletas;
o lock do controlador não cerca outro root arbitrário.

O campo sadb_x_ipsecrequest_reqid do SDK Darwin local foi inspecionado como
u_int16_t, e o fonte fixado do kernel-pfkey atribui o reqid nesse campo. Isso
é inspeção estática, sem leitura ou escrita PF_KEY executada. O allocator não
trunca hashes e não usa nome/reqid como permissão para apagar recursos.

Um consumidor C compilado contra o SDK confirma os 16 bits do campo e
IPSEC_MANUAL_REQID_MAX = 0x3fff. O teste falhou com a primeira faixa 1..65535:
o [parser do XNU](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/netkey/key.c)
substitui reqids manuais acima desse limite. A faixa emitida agora é 1..16383;
observações podem incluir também IDs automáticos até 65535. O consumidor só
imprime tamanho/constante, sem socket, SA, política ou privilégio.

[PASS, codec/schema assertions] Nomes reversíveis conservam UID, geração e
todos os bytes/caso do perfil, dentro do limite do protocolo. load-conn fixa
IKEv2, endpoints resolvidos, identidade EAP/PSK, reqid e seletores canônicos;
não carrega segredo nem configura trap/restart automático. Senha/PSK só entram
em load-shared, com donos exatos e Debug redigido. Prazos positivos limitados
e arredondamento para cima impedem timeout zero/infinito nos comandos de ciclo
de vida. Catálogo vazio de redes prepara seletores IPv4/IPv6; não comprova
proteção de tráfego em nenhuma família. Referência de esquema:
[VICI 6.1.0](https://github.com/strongswan/strongswan/blob/6.1.0/src/libcharon/plugins/vici/README.md).

O nome de usuário é codificado como KEY_ID binário explícito nos campos local/
EAP e no dono do segredo. O fonte fixado de identification.c reconhece aliases,
prefixos tipados, subnets e ranges; passar `%any` diretamente criava um curinga.
O teste falhou antes da correção e agora distingue `%any`, `*`, prefixo, subnet e
tipo numérico como bytes literais. Gateway não especificado também é recusado.
Essa prova de construção não substitui a negociação de identidade com um servidor.

[PASS, local] 241 testes Rust com desktop e 237 sem desktop, com dois ignored
(runtime opcional e harness de crash chamado pelo pai). O alvo IPsec foi repetido
após tornar a limpeza do fixture SDK dependente da criação bem-sucedida da pasta.
Fmt/clippy all-targets/all-features -D warnings e sintaxe Python passaram.
UI, catálogos, dependências e patches não mudaram; evidências desses consumidores
permanecem no checkpoint 692489d, sem nova execução ou inspeção visual.

A matriz final detectou 42 mutações e passou baseline/restauração: namespace,
tokens, conflito/limite manual, dono/configuração, identidade binária, endpoints,
seletores, segredos e prazo. Exige assertion executada no teste previsto, sem
contar erro de compilação. Os 201 hashes de fonte/testes/runner conferem com o
estado final; logs/recibo em output/fixtures/ipsec-oracles/. Cópia/build descartáveis
removidos. O workflow inclui o gate, sem execução remota. Matrizes anteriores
conservam seus commits e limites; não foram reexecutadas nesta fase.

[NOT RUN] As mensagens não foram enviadas a charon. Faltam consumidor de
respostas/eventos, admissão de processo/socket, observador SA/SPD, retenção de
admissão entre falhas, probe/origem, integração Factory/dispatch e cleanup
nativo. Broker/helper continuam recusando IPsec. Nada instalado ou conectado;
o .app/payload de desenvolvimento conservado pertence ao checkpoint 692489d.
Esta fase não reempacota ou atualiza um componente instalado.

## Helper com modos fechados e canal herdado

```bash
cargo test --locked --no-default-features --offline --lib helper::server
cargo test --locked --no-default-features --offline --lib inherited_helper_channel
cargo test --locked --no-default-features --offline --test helper_entrypoint
python3 scripts/macos/check-helper-channel.py
```

Executar como usuário comum no macOS. O binário `vpnt-helper` aceita somente
`runtime` e `admin`, sem flags de fixture, paths ou UID alvo. Rejeita antes do
storage UID real/efetivo diferente de root. Depois exige FD 0 válido, stream Unix
conectado, sem nome em ambas as extremidades, com peer não root obtido pelo
kernel. Pipes, datagramas, TCP e serviços Unix nomeados são recusados. O helper
usa esse único FD duplex, com CLOEXEC, sem protocolo em stdout/stderr. Não usa
SUDO_UID/SUDO_USER como autoridade. A herança do peer UID através da elevação
ainda não foi exercitada; os testes do canal rodam sob o usuário comum.

O UID autenticado seleciona exclusivamente `ProfileStore::for_user`; o diretório
root já precisa existir. Runtime adquire o lock global e o mantém por toda
a sessão. Chama `run_ssl`; admin exige documento único mais EOF em até
cinco segundos e chama save/remove sob a reserva do perfil alvo, sem tomar o
lock de rede. Runtime não edita
perfis. A futura regra sudoers deve liberar sem senha somente o comando exato
runtime; a administração precisa da autorização de elevação separada. Nenhuma
regra foi criada ou instalada por estes testes.

A entrada tem deadline por frame iniciado; uma sessão runtime ociosa pode
continuar aberta. Admin inclui documento e EOF no mesmo prazo. O buffer de
entrada apaga os bytes consumidos e zeroiza no drop. Há dois threads de IO,
filas de 32 mensagens/pedidos e prazo de cinco segundos por frame de saída.
Erro de escrita fecha a admissão; EOF, HUP/INT/TERM e erro de protocolo fecham o
canal de pedidos. O controlador conserva workers/leases/aposentadorias durante
o cleanup, sem timeout que declare recursos removidos. Encerrar o controlador
cancela também uma leitura parcial ou ociosa antes de juntar os threads.
Sinais reais do entrypoint root e backpressure até o prazo da escrita ainda
precisam de cenário próprio; o prazo da administração/leitura foi executado.

Oito testes do servidor exercitam sockets nativos, fragmentação, injeção de
campos/comandos, CLOEXEC, cancelamento de leitura parcial, silêncio por cinco
segundos e apagamento do buffer sem corromper o frame seguinte. A administração
passa pelo aplicador produtivo com storage/flock próprios de fixture: salva,
relê e remove perfil; segundo documento ou falta de EOF não pode mutar; reserva
alterada não autoriza escrita. A seleção de modo mantém runtime exclusivo e
permite admin com o lock de rede ocupado. O caso adicional por socket edita
outro perfil e recusa save/remove do alvo reservado, conservando ambos os locks.
Um teste do executável final confirma a recusa
do usuário comum mesmo com SUDO_UID/SUDO_USER forjados e argumentos adicionais.

Um oitavo cenário do controlador atravessa o transporte produtivo, codec real,
Coordinator e um sleep próprio. Confere UID, conectar/verificar e EOF enquanto
aposentadoria está pendente; o helper precisa esperar a remoção observada.
A tabela/PPP/probe/cleanup são simulados; isso não executa `run_ssl` como root,
retém uma PPP real, altera rotas ou comprova uma conexão VPN.

A matriz usa uma cópia descartável de fonte/build: três baselines e três
restaurações (servidor, controlador pelo socket e entrypoint), mais 12 mutações.
Remove restrição de argv, recusa de socket nomeado, CLOEXEC, UID encaminhado,
EOF administrativo, save/remove, validação da reserva, disputa incorreta do
lock de rede pelo admin, cancelamento da leitura,
prazo e apagamento do buffer. Exige assertion executada no teste previsto;
compilação ou falha incidental não contam. Omissão isolada de SO_TYPE sobreviveu
porque getpeereid também recusou o datagrama com EINVAL neste macOS; não foi
contada como mutação detectada. Recibos/hashes de src/tests e logs ficam em
`output/fixtures/helper-channel-oracles/`. O workflow macOS inclui essa matriz;
CI remoto ainda não executado.

**Limites:** helper não instalado e política sudoers não aplicada. O cliente e
o broker normal estão preparados abaixo. A elevação precisa conferir a passagem de FD 0,
PTY e política de registro de IO, preservando o sigilo das credenciais.
Snapshot inclui metadados IPsec/SSL; só SSL tem despacho de conexão. O driver IPsec
permanece por implementar. Installer, sinal/UID após elevação, recursos
privilegiados e testes com gateways reais continuam pendentes. Nada foi
instalado, elevado, conectado ou publicado.

Checkpoint histórico executado: `016d1cf`, com 143 testes Rust com desktop/142 sem desktop,
11 mutações do helper, 67 de rotas e 16 da supervisão PPP. Os hashes dos 118
arquivos src/tests conferem com os três recibos desse commit. Cliente/broker
foram depois validados em c687e96. Servidor/controlador e suas matrizes foram
reexecutados no avanço de reservas/refresh abaixo; PPP/runtime C conservam
os respectivos limites históricos. Recibos antigos não são hashes do head novo.

## Administração e reserva por perfil

```bash
cargo test --locked --no-default-features --test profile_reservations --test storage
cargo test --locked --no-default-features --lib connection::controller::profiles
cargo test --locked --no-default-features --lib connection::controller::engine::metadata
cargo test --locked --no-default-features --lib helper::server::tests::profiles
python3 scripts/macos/check-profile-administration.py
```

O store mantém `.profile-<id-em-hex>.lock`, owner/modo privados, flock exclusivo
não bloqueante e CLOEXEC. IDs são codificados byte a byte, sem hash ou colisão
por maiúsculas: no APFS local, Case/case colidiram antes da correção; o teste
reproduziu Busy indevido e passou depois da codificação. O inode é persistente,
inclusive após remover o perfil; instalação/atualização não podem substituí-lo.
Save/remove disputam a mesma reserva do controlador e revalidam antes da escrita.
O lock do documento continua serializando atualizações de perfis diferentes.

Cinco testes de filesystem/subprocesso usam somente diretórios próprios:
alvo reservado não muda, outro perfil continua editável, processo Python
independente observa flock, nenhum FD da reserva atravessa exec, inode sobrevive
ao release e permissões/ACL/symlink/hardlink/substituição são recusados.
Administradores root continuam confiáveis; validação de inode não é um fence
atômico contra outro root que substitui manualmente o arquivo de lock.

O registro do controlador conserva as reservas fora da pilha do worker.
Dois testes reais de store/lock verificam releitura antes de admitir o perfil,
recusa de cache alterado/removido, validação antes de release e reserva após
unwind. No adaptador nativo, a reserva precede egress/spawn; só a confirmação de
cleanup da rede permite removê-la. O corpo anterior de cleanup foi movido para
native/cleanup.rs sem mudança de comportamento. Essa ligação foi compilada e
revisada; ainda não foi executada como root com PPP/recursos reais.

O snapshot pode reler o store por Factory::profiles. A atualização dos slots
valida o conjunto inteiro antes de mudar qualquer um: worker ativo ou conexão
enfileirada impedem alteração/remoção do alvo; metadados inativos mudam com
geração crescente, sem overflow. Slots ativos e seus recursos são preservados.
Três cenários atravessam o controlador/codec/store/reservas produtivos com
worker e plano de dados simulados: novo/editar/remover, cleanup retido, rollback
de refresh rejeitado e metadados IPsec sem despacho ao worker SSL. Dois casos
puros cobrem conexão enfileirada e limites u64::MAX-1/u64::MAX.

Dezenove mutações exigem falha no consumidor previsto: save/remove sem reserva,
flock, caixa do ID, validação/inode/hardlink/ACL/CLOEXEC, cache antigo, release
no unwind/sem validar, omissão de refresh/geração/remoção, alteração de slot
enfileirado/ativo, commit parcial e IPsec despachado como SSL. Oito baselines/
restaurações cobrem filesystem, custódia, metadata e admin por socket. Fonte e
build descartáveis; recibos/logs em `output/fixtures/profile-admin-oracles/`.
O workflow macOS inclui essa matriz; sem execução remota nesta entrega.

No checkpoint fc067b4 passaram 167 testes Rust com desktop/165 sem desktop, fmt,
clippy all-targets/all-features -D warnings, build, pacote e cmp. Um teste de
admissão do runtime preparado continua ignorado por padrão. Foram reexecutadas
19 mutações de perfis/oito baselines, 12 do helper/seis e 67 de rotas/oito.
Os 137 hashes de src/tests conferem entre as três matrizes e a fonte final.
Recibos anteriores do helper e rotas foram preservados nos diretórios
`helper-channel-oracles-before-profile-admin/` e
`route-oracles-before-profile-admin/`. Os 24 oráculos do broker/UI de c687e96
e os 16 de PPP do checkpoint anterior são reutilizados, sem nova execução.
UI, dependências, patches e runtime C não mudaram; nenhuma inspeção visual
nativa ou prova de rede real foi acrescentada por esses checks.

As falhas de editar alvo reservado, admin disputando lock global, snapshot
desatualizado e colisão Case/case foram executadas antes das respectivas
correções. Falha incidental de compilação ao mover o harness foi corrigida e
não conta como Red nem como mutação detectada.

**Limites daquele checkpoint:** a UI/broker ainda não implementava
SaveProfile/RemoveProfile nem refresh correlacionado. O avanço atual está abaixo. Nada instalado, elevado, conectado ou
publicado. Não houve system pppd, interface/rota nova ou VPN. Instalação/remoção,
sudoers/IO/PTY e prova nativa de credenciais/cleanup continuam pendentes.

## Instalação e remoção assíncronas pelo app

```bash
cargo test --locked --no-default-features --lib install::client
cargo test --locked --no-default-features --lib broker::component
cargo test --locked --all-features --lib desktop::worker::tests::component
python3 scripts/macos/check-component-client.py
```

O cliente admite o pacote/instalador em thread própria, espera o gate do broker
e revalida antes de iniciar. O broker fecha o canal runtime anterior e exige
saída do seu Child antes de liberar o gate. Pausa retry e alterações concorrentes;
snapshot/hide continuam responsivos. Instalação prepara somente
`/usr/bin/open -W -n -b com.apple.installer <pacote admitido>`, sem shell ou -F.
Exit zero não confirma instalação: exige digest esperado do helper instalado e
snapshot compatível em uma sessão nova. O comportamento real do Installer e
essa admissão positiva como root continuam NOT RUN.

Remoção prepara somente sudo -A -k com instalador fixo + remove. Reusa os tipos
do servidor, anuncia Ready antes de enviar um id + EOF em socketpair anônimo;
exige versão, limite, id, ausência de resposta extra, EOF e exit zero. Preserva
perfis/segredos e desativa retomada para a conta removida. Prazo/erro é reportado
sem matar filho; enquanto ele vive, conserva exclusão e mostra componentOperation
settling. Sair do app mantém o launcher desativado mesmo após esse filho terminar.

[PASS, process/socket fixtures] Os consumidores produtivos são exercitados por
processos ordinários próprios. Gate não liberado deve expirar sem spawn;
remover não confirma sucesso antes de seu filho sair; prazo chega antes da
espera e não permite sucesso tardio. O ator atravessa parse_request/fila/correlação
do reply e confirma consultas/hide durante a operação. Isso não executa open,
sudo, prompt, PackageKit, componente instalado ou rede VPN.

[PASS, browser simulated] `tests/browser/component.js` é uma função para
Playwright CLI run-code sobre o servidor demo local. Intercepta todo transporte
de componente com respostas sintéticas; nunca constrói backend privilegiado.
Dezesseis cenários cobrem instalar/remover nos dois idiomas, temas e larguras
420/280. Conferem confirmação antes de envio, Escape/cancelar sem pedido, foco
contido/restaurado, espera sem fechar/repetir, erro de prazo, retenção observada
por polling e navegação somente após sucesso. Painel medido em 320/280 px,
diálogo em 280/256 px, sem overflow horizontal. Capturas dos dois temas foram
inspecionadas. Recibo/capturas em output/playwright/component-*.

O caso de catálogo recuperado também falhou antes da correção: a continuação
usava o snapshot anterior ao pedido e abria cadastro mesmo havendo perfis.
Agora consulta o último snapshot recebido; catálogo vazio abre cadastro e
perfis existentes voltam ao painel. O cenário final cobre ambos nos dois idiomas.

[PASS, local] Suítes completas: 232 testes Rust com desktop e 228 sem desktop,
dois ignored (runtime opcional e child harness de crash exercitado pelo pai).
Após fortalecer as assertions de concorrência, a biblioteca desktop foi repetida
e as baselines seletivas revalidaram cliente/broker sem desktop. Fmt, clippy
-D warnings, lint/typecheck/build, oito testes Bun/114 assertions, 81 tokens,
bins/askpass, pacote e inspeção headless passaram; classes segue sem regras.

A matriz detectou 24 mutações/seis baselines-restaurações e mais duas seletivas/
quatro. Também passaram 24 do executor/quatro e 17 administrativas/seis.
Gate e recibo prematuro sobreviveram às primeiras assertions instantâneas:
os testes agora retêm a operação até o prazo antes de liberar o filho; só a
falha discriminante posterior foi contada. Erros de compilação não contam.
Recibos em output/fixtures/component-client-oracles{,-selected},
installation-engine-oracles e admin-client-oracles. Depois dessas matrizes,
mudaram apenas UI/navegação e o script de browser, revalidados no navegador;
o runner ganhou seleção de labels. O recibo do executor precede ainda o
fortalecimento do teste do cliente, fora dos consumidores que ele exercita.
As demais matrizes conservam seus checkpoints históricos, sem nova execução.

[NOT RUN] Tray/WKWebView, autenticação nativa, sudoers efetivo/FD 0/PAM/IO/PTY,
instalação/remoção elevadas, VPN/tráfego/cleanup reais, driver IPsec, assinatura/
notarização, revisão final e CI remoto continuam abertos. Nenhuma prova de
fixture ou navegador encerra esses gates. O artefato local é de desenvolvimento.

## Componente incluído no app e admissão sem Installer

```bash
cargo test --locked --no-default-features --lib install::bundle::tests
cargo test --locked --no-default-features --test app_component
python3 scripts/macos/check-app-component.py
cargo build --locked --bins
python3 scripts/macos/build-askpass.py
python3 scripts/macos/prepare-installation.py
python3 scripts/macos/package-app.py --replace --component-payload "target/vpnt-installation/ID_DO_PAYLOAD"
target/vpnt.app/Contents/MacOS/vpnt --inspect-component
```

[executed, filesystem/byte binding] Sete testes do leitor Rust vinculam versão,
UID real, build, hashes e host ao caminho fixo Contents/Resources/Component
derivado do executável. Metadados têm schema fechado, hashes/versão numérica
válidos e limites de leitura; troca de host, pacote ou metadados invalida a
admissão original. O principal para ler arquivos vem do UID obtido pelo processo,
não do UID alegado no JSON. O entrypoint não aceita flags de path/UID nem usa
SUDO_UID como autoridade. Seus gates de root/UID efetivo diferente estão no
código, sem execução desses ramos privilegiados nesta fase.

[executed, native filesystem + own ACL fixtures] Recusa links em arquivo ou
ancestrais, hardlinks, FIFO, permissões/ACL de escrita alheia e pacote excessivo.
Diretórios/arquivos devem pertencer a root ou ao usuário atual. A exceção de
ancestral só admite o /Applications padrão root:admin 0775, ou seu caminho de
volume de dados, com essas propriedades exatas; o app, descendentes e arquivos
continuam sob as checagens estritas. O diretório real foi apenas lido; nenhum
app ou configuração foi criado em Applications. Isso não demonstra um bundle
executado naquele diretório nem admissão de arquivo pertencente a outro UID.

[executed, native headless host + package tools] Dois testes atravessam os
empacotadores reais com runtime/roles fictícios, incluem o .pkg auditado no .app
e executam o host nativo copiado com --inspect-component. O programa confere os
bytes reais do próprio executável e pacote e devolve metadados correspondentes.
Checksum alterado é recusado; argv extra, ambiente ou cwd não selecionam outro
componente. Pacote simples sem componente falha na inspeção sem abrir GUI.
Se a fonte do componente estiver corrompida, a tentativa de --replace falha
antes de apagar o app anterior; seus bytes e sua admissão permanecem válidos.
O plist do .app precisa corresponder ao mínimo declarado, considerando o maior
entre macOS 13.0 e o mínimo do componente.

[executed, regression/oracles] A assertion inicial de admissão falhou no método
produtivo antes da implementação. A matriz detectou 17 mutações, com quatro
baselines/restaurações: UID/versão/schema/digests, selo de metadados, hashes de
host/pacote, links/modos/ACL, nome do executável, preservação do app anterior,
mínimo incoerente e exceção do Applications. Esta última só roda quando a
máquina tem root:admin 0775, como no ambiente local verificado. O runner valida
todas as âncoras primeiro e exige falha executada da assertion esperada. Logs e
187 hashes conferidos ficam em output/fixtures/app-component-oracles/.

[executed, local] Passaram 219 testes Rust com desktop e 216 sem desktop,
com dois ignored: admissão opcional do runtime e harness de crash exercitado
pelo pai. Fmt, clippy all-targets/all-features com -D warnings, sintaxe Python e
build dos binários/askpass passaram. UI/catálogos/layout, dependências e patches
não mudaram, sem novo browser/aceite visual. As 15 mutações do .pkg permanecem
no checkpoint 64fe499; as 48 de payload/executor, em e8f4b7e; as demais 157,
em seus checkpoints anteriores. Esses oráculos não foram reexecutados nesta
fase. As suítes completas incluem os testes positivos dessas camadas. O CI
inclui a matriz nova, ainda sem execução no serviço remoto.

[executed, prepared native artifact] O .app final incluiu o runtime/adapters
locais já admitidos no payload 6f4596d2684eb8feb0966a41e1e44276b0df6b61abc568f8ceeaa10b6ee2d234.
O host real foi executado apenas com --inspect-component, cwd / e ambiente
mínimo; devolveu UID 502, mínimo macOS 26.0 e os hashes esperados. Bytes do host
coincidem com target/debug/vpnt; o pacote incluído tem SHA256
8a2b54192a8ccfd8edc3b386898fe17b32bce5f1ae824ac608db3aab39cda0a3.
Recebimento nativo de metadados e leitura de arquivos não são execução do
Installer, instalação, abertura do tray ou prova de VPN.

[partial] Esta fase prepara o artefato e sua admissão; não aciona os botões
InstallHelper/RemoveHelper nem abre o Installer. Ainda faltam o cliente/ator
assíncronos, quiescência do runtime e exclusão de operações incertas, confirmação
bilíngue, prova de recibo/sessão após instalação e os gates positivos root/
PackageKit/PAM. Hashes são integridade do build de desenvolvimento e não
substituem assinatura nem cercam alteração arbitrária pelo próprio usuário.
CLI sem GUI não prova tray/WKWebView; VPN/tráfego/cleanup e IPsec continuam
pendentes. Nenhuma elevação, instalação ou VPN foi executada.

## Pacote local do componente privilegiado — checkpoint 64fe499

```bash
cargo test --locked --no-default-features --test install_package --test install_preparation
python3 scripts/macos/check-installation-package.py
python3 scripts/macos/package-installation.py --payload "target/vpnt-installation/ID_DO_PAYLOAD"
```

[executed, native packaging + fictional roles] Quatro testes Rust atravessam
o preparador e pkgbuild/productbuild/pkgutil/lsbom reais, com runtime sintético
e executáveis fictícios que só oferecem inspect/policy nos testes. O pacote
gerado é extraído novamente e o mesmo inspetor nativo admite o payload extraído.
O BOM precisa registrar root:wheel, os modos exatos e todos os alvos conhecidos.
Entradas AppleDouble só são aceitas quando correspondem a um alvo conhecido,
com o mesmo modo e ownership. Os bytes do payload são copiados sem forks/ACLs
do arquivo de origem; metadados de proveniência gerados pelo macOS podem
continuar no arquivo. Ownership gravado no BOM não prova instalação como root.

[executed, native archive admission] Distribution confere domínio localSystem,
volume de boot, arquitetura nativa e mínimo de macOS do payload, sem relocação
ou scripts externos de JavaScript. PackageInfo confere autoridade root,
identidade/versão/destino fixos, actions e scripts exatos. Somente os acréscimos
calculados de tamanho, referência local e bundle-version vazio do productbuild
são normalizados. Payload de arquivo aponta apenas para
/Library/PrivilegedHelperTools/dev.vpnt.staging/<hash>; os alvos live são do
executor. Referência de esquema: [Apple Distribution XML](https://developer.apple.com/library/archive/documentation/DeveloperTools/Reference/DistributionDefinitionRef/Chapters/Distribution_XML_Ref.html).

[executed, ordinary-user script rejection; partial root execution] sh -n
analisa preinstall/postinstall extraídos. Ambos recusam volume alternativo com
exit 64 e o usuário comum com exit 77, inclusive com SUDO_UID forjado. A última
linha do postinstall confere executável fixo e o único argumento activate.
O preinstall preparado confere donos/modos/links dos ancestrais e, se o build
já existir, exige todos os arquivos com hashes/modos exatos e nenhum item extra.
Essas verificações positivas de árvore root, a convenção de argumentos sob
PackageKit e a ativação pelo postinstall ainda não foram executadas como root.
Não chamar installer nem abrir o pacote para instalar durante esses testes.

[executed, well-formed altered archives] O teste reconstrói arquivos válidos
com volume/domínio alterados, root XML desconhecido, destino/autoridade/relocação
alterados, bundle action ou script action diferente e BOM de usuário comum.
Todos são recusados pela fronteira específica esperada. Outros produtos válidos
com bytes de script ou payload alterados, modo alterado e arquivo extra são
recusados; isso distingue admissão de apenas detectar arquivo quebrado.
Repetição conserva inode/hash do pacote saudável; corrupção não é substituída.
Saída sobreposta à entrada e flag --install são recusadas antes de criar pacote.
Árvores temporárias próprias são removidas ao final.

[executed, regression] O teste sob umask 077 falhou primeiro porque os diretórios
novos do payload congelado conservavam 0700. O preparador do pacote agora aplica
0755 somente aos diretórios dessa cópia nova, conservando o root privado 0700 e
a entrada original. O teste passou; a auditoria exige os modos gravados exatos.
O comando --verify também resolve o alias do diretório temporário do macOS
antes da admissão, sem relaxar a recusa a links do inspetor.

[executed, unsigned artifact] O pacote do runtime C/adapters locais foi gerado
e extraído sem elevar: 18 arquivos de dados, 53 entradas no BOM, incluindo
26 entradas de metadados, mínimo macOS 26.0. pkgutil --check-signature confirmou
ausência de assinatura. A auditoria exige esse estado para este pacote de
desenvolvimento; signed=false é verificado, não inferido só pela falta de --sign.
O pacote fica em target/vpnt-packages/<id> e declara installationPerformed=false.
Ele não instala o .app e não foi instalado na máquina. Distribuição assinada/
notarizada, execução elevada e efeitos do Installer permanecem pendentes.

[executed, local] Passaram 210 testes Rust com desktop e 207 sem desktop,
com os mesmos dois ignored descritos no checkpoint do executor. Fmt, clippy
all-targets/all-features com -D warnings, build dos binários/askpass e pacote
.app/cmp passaram. A matriz do pacote detectou 15 mutações e passou quatro
baselines/restaurações: guards de volume/root, operação de postinstall, contrato
de Distribution/PackageInfo/root XML/actions, conteúdo de script/payload/modos,
ownership, declaração falsa de instalação, sobreposição e umask. Cada mutação
exige falha executada da assertion esperada. Os 182 hashes de fontes/testes/
catálogos/scripts conferem em output/fixtures/installation-package-oracles/.
As 48 mutações de payload/executor continuam vinculadas ao checkpoint e8f4b7e;
nesta fase não foram reexecutadas, nem as outras 157 anteriores. O código de
src/ é o mesmo, e o fixture compartilhado do preparador foi revalidado nas
baselines. O workflow inclui a matriz nova; CI remoto não foi executado.

[partial] Ainda faltam a ligação InstallHelper/RemoveHelper ao app, os gates
positivos root/PackageKit/sudo/PAM/FD 0/IO/PTY, aceite de tray/WKWebView, IPsec,
VPN/tráfego/cleanup reais, revisão final e CI remoto. Os fixtures não encerram
esses gates. Fontes de src/, UI, dependências e patches permanecem iguais a
e8f4b7e; o fixture do preparador foi compartilhado com os novos testes.

## Executor de instalação e recuperação — checkpoint e8f4b7e

```bash
cargo test --locked --no-default-features --lib install::engine::tests
cargo test --locked --no-default-features --test install_preparation
python3 scripts/macos/check-installation-engine.py
```

[executed, ordinary-user filesystem + native parser] O mesmo executor de
ativação/remoção trabalha sobre uma árvore privada cfg(test). Instala, repete,
atualiza os digests de todos os usuários registrados e remove um usuário ou os
últimos arquivos comuns. Recibo canônico exige inventário completo, hashes e
modos; links, permissões inseguras, alteração alheia, UID não registrado e
escapes de namespace são recusados antes de mutação. Um ProfileStore real salva
e relê um perfil fictício: bytes e inodes do perfil, reserva e lock global
persistem após instalação/repetição/remoção. Nenhum segredo pessoal é usado.

[executed, filesystem/process fixture] O journal privado contém hashes
antes/depois e backups conferidos. A transação retém o ControllerLock persistente,
suspende políticas, troca componentes e recibo e só então repõe políticas.
Falhas após 11 prefixos de instalação, quatro de atualização e 12 de remoção
restauram as imagens anteriores. Quatro filhos reais terminam com _exit após
cada escrita de uma atualização; o processo pai aguarda seu próprio Child,
confere a ordem de política/binário/recibo, readquire o mesmo inode de lock e
recupera as imagens anteriores. Isso prova interrupção nos pontos exercitados,
sem equivaler a falha em qualquer syscall ou perda de energia.

[executed, filesystem fixture] Recuperação recusa imagens desconhecidas,
backups ausentes necessários ou corrompidos antes de restauração parcial.
Preparação incompleta de backups só pode ser descartada com imagens live ainda
iguais ao estado anterior. Marker de commit durável exige imagens finais
correspondentes; recuperação finaliza esse commit. Coleta interrompida aceita
apenas manifesto/backups registrados ou diretório terminal vazio/com marker
válido. Conteúdo desconhecido é conservado com RecoveryRequired. Journal sem
manifesto válido e temporário órfão de escrita interrompida também são
conservadores: não há recuperação por palpite. O lock advisory não cerca
modificações de outro root arbitrário.

[executed, native parser; partial installed policy] O executor chama visudo
real para a política gerada e uma configuração de fixture com @includedir.
Exige que cada arquivo esperado apareça como parsed OK; sintaxe global sem
incluir a regra é recusada e revertida. O código limita tempo/saídas do parser;
seus casos de prazo e saturação ainda não têm consumidor de subprocesso
dedicado. Isso não prova privilégios efetivos, PAM, PTY, IO ou herança após sudo.

[executed, native Unix fixture + unprivileged entrypoint] Remoção usa o peer UID
do socketpair anônimo, um único documento limitado seguido de EOF e respostas
sem expor outros UIDs. UID forjado/campo extra/segundo documento são recusados.
Os modos activate/remove recusam o processo comum com exit 77, mesmo com
SUDO_UID ou path de fixture no ambiente. Nenhum modo produtivo aceita override
de instalação, UID ou paths. A entrada root preparada só admite activate pelo
próprio executável no staging fixo e remove pelo instalador live; esses gates
positivos de root, conta local e versão mínima ainda não foram executados.
O helper agora exige recibo íntegro, usuário registrado e ausência de journal
pendente; runtime conserva o lock durante essa admissão. A ligação dessa
admissão ao entrypoint root permanece sem prova elevada.

[executed] Quinze testes novos do executor passaram, além do child harness
marcado ignored e chamado explicitamente pelo teste pai. A matriz detectou
24 mutações com quatro baselines/restaurações: retenção do lock, repetição,
arquivos alheios, hashes/inventário/modos/canonicalização, links, namespace,
ordem de política, rollback, backups, commit/coleta, IPC e root/UID admission.
Cada caso exige assertion executada do consumidor; erro de build/âncora não
conta. Logs e inventário de hashes estão em
output/fixtures/installation-engine-oracles/. A primeira tentativa revelou que
o teste de crash ainda não observava retenção do lock durante as escritas;
o observador agora tenta adquirir o lock real em cada prefixo e exige Busy.
Essa mutação só foi contabilizada após falhar na assertion e a baseline passar.

[executed, local] A suíte completa passou com 206 testes Rust com desktop e
203 sem desktop. Os dois ignored são a admissão opcional do runtime e o child
harness de crash, este exercitado pelo pai. A tentativa dentro do sandbox teve
14 falhas de acesso a sockets/leituras nativas/chaveiro; a execução como usuário
comum fora do sandbox passou. Fmt, clippy all-targets/all-features com -D warnings,
build dos binários, build do askpass, pacote .app e cmp passaram. A matriz
anterior de payload/preparador também foi reexecutada: mais 24 mutações e quatro
baselines/restaurações. Os 176 hashes da matriz do executor conferem com as
fontes atuais. UI/catálogos/layout, dependências e patches não mudaram; provas
visuais e as 157 mutações anteriores às fases de instalação mantêm seus
checkpoints históricos, sem reexecução neste ciclo.

[partial, histórico e8f4b7e] A fase preparou apenas código e artefatos locais. Staging root/.pkg,
integração InstallHelper/RemoveHelper ao app, instalação e remoção elevadas,
política efetiva/askpass/PAM, IPsec, VPN/tráfego/cleanup real, aceite de
tray/WKWebView, revisão final e CI remoto continuam pendentes. O workflow inclui
a nova matriz. Nenhum sudo, installer do macOS, instalação ou VPN foi executado.

## Payload e política de instalação — checkpoint f2e6793

```bash
cargo test --locked --no-default-features --lib install::
cargo test --locked --no-default-features --test install_preparation
python3 scripts/macos/check-installation.py
cargo build --locked --bins
python3 scripts/macos/build-askpass.py
python3 scripts/macos/prepare-installation.py
```

[executed, filesystem/contract fixture] O payload tem manifesto fechado, versão
exata, destinatário entre 501 e 2147483647 e inventário completo com hashes.
Recusa campos/caminhos extras, chaves duplicadas, metadados excessivos, arquivo
faltante, diretório não listado, conteúdo alterado e identidade de build antiga.
Exige diretórios/arquivos próprios, sem links ou permissões/ACL que permitam
escrita alheia. Reusa a admissão de runtime/patches/Mach-O já existente; adapters
só podem depender das bibliotecas do sistema. Rehash externo não autoriza uma
política mais ampla ou runtime incompatível. Ownership root e execução elevada
não são provados pelas árvores pertencentes ao usuário de teste.

[executed, static contract + native parser] A política contém aliases únicos por
UID, digest SHA-256 do helper/instalador e argumentos exatos. Somente runtime
recebe NOPASSWD; admin/remoção usam PASSWD. Inclui NOSETENV/NOLOG_INPUT/
NOLOG_OUTPUT/NOINTERCEPT e Defaults por comando que desativam PTY e IO/subcomandos.
As assertions conferem esse contrato; `visudo -c -s -f` analisa somente a política
de fixture. Sintaxe válida não comprova seleção da regra, autenticação, IO,
herança de FD 0 nem o efeito de configurações globais/plugins. Essas provas
continuam pendentes no caminho instalado. Referência: [sudoers](https://github.com/sudo-project/sudo/blob/main/docs/sudoers.man.in).

[executed, native process + synthetic runtime] O teste do preparador usa o
inspetor Mach-O compilado, um runtime sintético e papéis de executáveis fictícios;
só o inspetor é executado. Atravessa o script Python e o parser visudo reais.
Repetição conserva o build e remove cópias temporárias. Corrupção do destino
é recusada sem repará-lo silenciosamente; saída sobreposta às entradas é recusada
antes de escrever. Flags e SUDO_UID forjado não ativam o componente. Naquele
checkpoint o CLI só oferecia inspect/policy; os modos preparados posteriores
estão descritos na seção do executor acima.

[executed, native file admission] O preparador também admitiu o runtime C local
já construído e os cinco adapters reais: 17 arquivos, mínimo macOS 26.0.
Nenhum cliente VPN foi executado para isso; é inspeção de arquivos/formato e
integridade, sem prova funcional de VPN, assinatura ou notarização. O payload
fica em target/vpnt-installation/<id>. A saída declara installationPerformed=false
e, naquele checkpoint, activationAvailable=false. O executor posterior mudou
esse segundo campo para true; isso indica código disponível, sem instalação.
Python >=3.11 é necessário. O preparador não roda
sudo, installer do macOS ou escrita fora da saída local escolhida.

[executed] Nesta fase passaram 191 testes Rust com desktop e 188 sem desktop,
com um teste de admissão do runtime ainda ignorado por padrão. Fmt, clippy
all-targets/all-features com -D warnings, build de todos os binários, pacote
local e cmp passaram. UI/catálogos/layout, dependências e patches não mudaram;
as provas visuais e os demais oráculos conservam seus checkpoints históricos,
sem nova execução das 157 mutações anteriores. Não são hashes do head atual.

A matriz desta fase detectou 24 mutações e passou quatro baselines/restaurações:
inventário/versão, campos/chaves extras, limite, hashes, links/permissões/ACL,
admissão de adapters/runtime, política canônica, identidade antiga, autenticação,
argumentos, PTY/digest, corrupção do destino, declaração falsa de instalação,
sobreposição de saída e sucesso para comando desconhecido. Logs e hashes de
158 entradas de fonte/teste/catálogo/preparador estão em
output/fixtures/installation-oracles/. Compilações/âncoras inválidas não foram
contadas; o runner agora valida todas as âncoras antes da matriz. Os casos de
arquivos 0555 precisaram de chmod somente no fixture para simular adulteração;
a falha inicial de preparação desses testes não conta como regressão detectada.

[partial, histórico f2e6793] A fase seguinte precisava implementar ativação/rollback sob lock global,
remoção conservadora, staging root e .pkg. Preservar perfis e inodes é requisito
para esse executor, ainda não provado por testes de aplicação. InstallHelper/
RemoveHelper do app continuam pendentes. Não foi instalado, elevado, conectado
ou publicado nenhum componente. O workflow inclui os oráculos desta fase;
CI remoto, autenticação e política efetiva permanecem sem execução.

## Administração assíncrona de perfis

```bash
cargo test --locked --no-default-features --lib helper::admin_client
cargo test --locked --no-default-features --lib broker::admin
cargo test --locked --all-features --lib desktop::worker
python3 scripts/macos/build-askpass.py
python3 scripts/macos/check-admin-client.py
```

[executed, native/process fixture] O ator produtivo recebe SaveProfile e
RemoveProfile com o locale tipado, inicia um worker administrativo e conserva
a correlação até a resposta final. Outros perfis continuam controláveis durante
a autorização. O alvo em uso não abre prompt; conectar ou trocar segredos do
alvo em edição retorna Busy. Não há atualização otimista do catálogo.

O comando preparado é somente `/usr/bin/sudo -A -k --
/Library/PrivilegedHelperTools/dev.vpnt.helper admin`, com helper/askpass
root verificados, ambiente reduzido, cwd fixo e socketpair duplex em FD 0.
O protocolo 2 anuncia AdminReady antes da leitura. O cliente espera versão de
protocolo/app compatível antes de enviar um documento e EOF. Recusa ID errado,
duplicata, resposta excessiva, versão incompatível, prazo e exit status não zero.
Erros chegam antes do reap; sucesso só após EOF e espera do próprio filho.
Fechar/expirar não mata o helper nem repete o documento após autorização tardia.

Depois do reap, o broker solicita um snapshot correlacionado no canal runtime.
Preserva gerações locais mais recentes e só confirma a mudança que aparece no
catálogo. Remover credenciais exige confirmação da ausência do perfil e recibo
bem-sucedido. Se o chaveiro falhar depois disso, retorna `secret_cleanup_failed`:
o perfil já foi removido; o resultado é parcial. Perda do runtime invalida sucesso.
Uma operação incerta mantém a edição bloqueada até conseguir reler o catálogo;
a falha reportada não comprova rollback ou conclusão do cleanup.

[executed, build/static rejection] O askpass AppKit separado é compilado com
warnings como erros, sem dependências Rust novas. Compartilha os quatro textos
pt-BR/en-US em `ui/src/locales/native.json`. Antes de mostrar UI exige usuário
comum, stdout pipe, pai `/usr/bin/sudo` com identidade de início preservada,
locale fechado e deadline monotônico. O diálogo preparado usa campo de senha,
Cancel/Escape e observa prazo/saída do pai. Escreve apenas no pipe do sudo e
apaga o buffer mutável; objetos temporários do AppKit não são uma prova de
apagamento de toda memória. Invocação direta por pai não autorizado foi
recusada com exit 1, sem UI/stdout/stderr. Nenhum prompt ou PAM real foi executado.

`-k` ignora o cache quando a política pede autenticação; não sobrepõe NOPASSWD.
A futura regra admin precisa exigir PASSWD, preservar FD 0 e desativar PTY e
registro de entrada/saída. Esses requisitos ainda não foram instalados nem
provados. Referências primárias: [sudo](https://github.com/sudo-project/sudo/blob/main/docs/sudo.man.in)
e [sudoers](https://github.com/sudo-project/sudo/blob/main/docs/sudoers.man.in).

[executed, native Keychain] O novo teste do ator atravessa parse_request, fila
real, broker, clientes e dois subprocessos fictícios. Um probe de outro perfil
responde antes da autorização administrativa; salvar aguarda o filho e o
snapshot novo. O segredo vem de uma base descartável do Security.framework e
não aparece no snapshot. Exclusão da base, chaveiro padrão e lista de busca
foram conferidos; não houve uso de credenciais ou VPN pessoais.

[executed] A suíte final passou com 182 testes Rust com desktop e 179 sem
desktop; um teste de admissão do runtime permanece ignorado por padrão. Fmt,
clippy all-targets/all-features com -D warnings, build, pacote e cmp passaram.
UI: lint, typecheck, oito testes Bun/114 assertions e 81 tokens passaram;
o gate de classes segue sem regras. Build do runtime C não foi repetido.

Foram executadas 17 mutações administrativas/seis baselines, 24 do broker/UI/
oito baselines, 13 do helper/seis, 20 de perfis/dez, 67 de rotas/oito e 16 de
supervisão PPP/duas. Cada mutação precisa da falha prevista no consumidor;
erro de compilação, âncora alterada ou timeout incidental não conta. Os 148
hashes src/tests/catálogos conferem com helper/perfis/rotas/PPP. Os inventários
de 170 arquivos do broker/admin diferem da fonte final apenas em common.tsx,
cujo ajuste posterior conserva o foco no diálogo ocupado; esses oráculos não
renderizam esse componente. A prova de navegador abaixo cobre o ajuste final.
Recibos em output/fixtures/*-oracles; arquivos anteriores preservados em
*-before-async-admin/ e *-before-icon-alignment/.

A execução paralela revelou Busy após liberar a reserva. A hipótese de uma
referência herdada durante fork motivou reprodução determinística com descritor
duplicado: o teste falhou antes e passou após LOCK_UN explícito no Drop. O inode
persiste, e unwind do worker continua sem liberar uma reserva conservada pelo
controlador. O erro inicial de importação do teste não conta como Red. A matriz
remove LOCK_UN e exige novamente essa assertion executada.

[executed, browser simulated] O build final foi operado no navegador isolado
em pt-BR/en-US, claro/escuro e viewports 420/280: oito combinações. O painel
mediu 320/280 px, botão de voltar 24 px, sem overflow horizontal. Durante Save,
campos e navegação ficam indisponíveis; recusa restaura os controles sem sair.
Durante Remove, Escape não fecha a confirmação, o foco permanece no diálogo e
retorna ao botão original ao cancelar após a falha. Os 16 pedidos capturados
levaram o locale correto. Save bem-sucedido na API demo voltou às Preferências.
Capturas representativas dos dois temas/idiomas/larguras foram inspecionadas.
A medição encontrou o descender do SVG alterando a altura do ícone; inline-flex
corrigiu o alinhamento. Desabilitar controles retirava o foco do diálogo; agora
o próprio diálogo recebe foco durante a espera. Os erros iniciais de seletor
traduzido e de chamada do CLI não foram falhas do produto. Script, recibo com
hashes da UI final e 16 capturas: output/playwright/admin-*. Respostas lentas/
recusadas foram injetadas no browser, sem prompt macOS ou VPN real.

[partial] Installer/remoção, política sudoers e admissão instalada continuam
pendentes. Não houve sudo, elevação, instalação, system pppd, interface/rota
nova, gateway, VPN real ou publicação. Askpass nativo, tray/WKWebView, driver
IPsec, teste de tráfego/cleanup real, revisão final e CI remoto continuam abertos.

## Cliente do helper e broker normal

```bash
cargo test --locked --no-default-features --offline --lib helper::client
cargo test --locked --no-default-features --offline --lib broker::tests
cargo test --locked --all-features --offline --lib desktop::worker
python3 scripts/macos/check-broker.py
```

Executar no macOS como usuário comum. O cliente produtivo admite o helper fixo
com as verificações existentes de proprietário, modo, ACL e Mach-O. Prepara
somente `sudo -n -- /Library/PrivilegedHelperTools/dev.vpnt.helper runtime`,
sem caminho/comando/UID recebido da UI. O teste substitui o Command apenas na
API compilada com cfg(test); não executa sudo. O filho recebe socketpair duplex
em FD 0, ambiente reduzido e cwd `/`; stdout/stderr são descartados. Filas e
frames são limitados, com prazo de cinco segundos por frame iniciado/escrita.
O frame de credenciais é zeroizado. Erro/EOF fecha admissões, publica falha e
descarta credenciais enfileiradas antes de esperar o Child próprio. Não há kill
ou prazo que transforme a saída do launcher em prova de cleanup da rede.

O broker exige protocolo e versão exata do app, snapshot inicial solicitado e
geração zero/Off antes de consultar metadados do chaveiro. Lê credenciais apenas
em conectar/reconectar e confere expiração novamente após essa leitura.
Accepted não produz Connected; somente Changed da geração atual pode fazê-lo.
Resultados antigos não afetam uma geração nova. Probe não reconecta; desligar
todas envia uma operação para cada perfil ativo. Perda/versão incompatível
retira a disponibilidade do helper, sem declarar Off. O canal morto não aceita
mensagens restantes como uma nova sessão. Logs têm somente estado/horário,
com limite de 60; snapshots contêm indicadores de presença, nunca credenciais.

Dois testes do cliente usam um processo Python independente e sockets nativos:
conferem FD/ambiente, fluxo/EOF, protocolo incompatível, saída e frame malformado.
O peer de erro segura o cleanup após receber EOF: a aplicação precisa observar
a falha antes de permitir seu término. Sete testes do broker exercitam esse
peer, Keychain de fixture, gerações/cancelamento, probe, dois perfis, versão,
expiração, perda e snapshot inicial indevidamente conectado. Um deles usa
Security.framework real numa base descartável, interação desabilitada, salva
credenciais fictícias via broker e as carrega para o filho fictício. Ao final
exige exclusão bem-sucedida e chaveiro padrão/lista de busca inalterados.

Dois casos adicionais atravessam o ciclo de retomada com processos reais
fictícios. Enquanto o primeiro peer segura o cleanup, nenhum substituto pode
ser lançado. Depois de reap do filho direto, um canal novo exige novo snapshot,
versão e estado inicial Off; só uma nova ação carrega credenciais/conecta.
O peer registra apenas tipos de comando para conferir ausência de replay.
Falhas sucessivas de lançamento e versão são recusadas e espaçadas; Quit
desabilita relançamento. O código produtivo começa em um segundo, dobra até
30 e reinicia após admissão válida. O fixture usa 20 ms para percorrer o mesmo
ciclo. Não prova que sudo/descendentes ou recursos de rede terminaram; o lock
global do helper continua obrigatório antes de admitir uma sessão real.

O worker do host usa fila limitada e mantém Keychain/helper fora do event loop.
Um teste exige que um pedido expirado não inicie nem repita uma operação.
Pedidos interativos têm 119 segundos no worker/120 na ponte; os demais, nove/dez.
O polling da UI pausa enquanto qualquer ação aguarda resposta. O controlador
compartilhado commandFlow descarta snapshots/erros de polling anterior a uma
ação e de ações anteriores à mais recente. Uma ação ultrapassada retorna false,
impedindo que seu callback autorize navegação tardia. Polling desmontado não
publica. Quatro testes Bun com Promises controladas exercitam sucesso/erro,
dois pedidos pendentes, retomada e descarte, sem depender de sleeps.
Não foi validado um prompt de autenticação real nem o deadline sob esse prompt.

A matriz descartável executa quatro baselines/restaurações (broker, cliente,
worker e UI) e 24 mutações. Exige a assertion do teste previsto, não falha de build:
versão, Accepted promovido a Connected, geração antiga, desligar só um perfil,
probe que desliga, expiração após Keychain, saída que vira Off, snapshot ativo,
kill do helper, falha atrasada até o cleanup, ambiente herdado e pedido expirado.
A primeira tentativa de Accepted->Connected sobreviveu por ser sobrescrita pelo
evento Connecting no mesmo lote; o teste passou a conferir também o log público.
Cinco novas retiram retomada, espera de reap, backoff, novo snapshot ou a
desativação por Quit. Sete da UI retiram os gates de resposta antiga,
ação ultrapassada, polling durante ação e publicação após desmontar.
Na execução final as 24 foram detectadas e as oito baselines passaram. Logs,
comandos e hashes dos 149 arquivos src/tests/ui/src estão em
`output/fixtures/broker-oracles/`; o workflow macOS inclui a matriz. O recibo e
logs anteriores de 9c4df14 foram preservados em `broker-oracles-9c4df14/`.

No checkpoint c687e96 passaram 153 testes Rust com desktop/151 sem desktop, fmt,
clippy -D warnings, lint/typecheck da UI, oito testes Bun com 114 assertions,
81 entradas de tokens, build, pacote local e cmp do binário. O gate de classes segue sem regras.
Os 24 oráculos do broker/UI e as provas de navegador abaixo são reutilizados
com esses consumidores, catálogos, layout e dependências inalterados. Helper/
controlador foram depois reexecutados acima. PPP/runtime C conservam seus
checkpoints históricos; o runtime C não foi reconstruído nesta rodada.

**Limites daquele checkpoint:** SaveProfile/RemoveProfile ainda faltavam; foram
ligados na etapa administrativa abaixo. InstallHelper/RemoveHelper,
installer/sudoers e admissão instalada permanecem pendentes. Só SSL tem despacho preparado; IPsec falta.
Nenhum teste executou sudo/elevação, pppd do sistema, interface/rota nova ou VPN.
Lançar o .app em demo não forneceu prova visual: CUA reiniciou duas vezes e o
fallback de clique retornou -25200. Isso é limite do driver, sem concluir falha
do painel. A instância própria foi encerrada e sua saída conferida. Tray,
WKWebView, temas/idiomas e prompts nativos ainda exigem inspeção real.
Nada instalado, conectado ou publicado; CI remoto e revisão final pendentes.

[executed, browser simulated] Na nova UI de demonstração em navegador isolado,
uma resposta de polling fictícia com Connected foi retida até após conectar e
cancelar. O MutationObserver observou Connecting/Disconnecting/Disconnected,
sem Connected transitório ou alerta. O caso usa API Rust de demonstração e
injeção controlada da resposta antiga, não helper/VPN. Script e captura locais:
`output/playwright/recovery-ui.js`, `recovery-race.log` e `recovery-en-light.png`.
Painel pt-BR/escuro medido em viewports 800/320/280: larguras 320/320/280,
sem overflow horizontal e com foco por teclado de 2 px. Captura inspecionada:
`recovery-pt-dark-narrow.png`; medidas em `recovery-layout.log`. A captura
en-US/clara também foi inspecionada. Layout/catálogos/tokens não mudaram.
Essas inspeções no navegador não substituem o aceite nativo do WKWebView.

## Exclusão entre controladores

```bash
cargo test --locked --no-default-features --lib helper::controller_lock
```

São cinco testes locais no macOS. Um processo Python independente tenta o
mesmo `flock` e deve receber ocupado até o handle Rust sair do escopo; depois
consegue adquirir. Conferir CLOEXEC, inode/conteúdo preservados após fechar,
troca do arquivo e mudança de modo detectadas, proprietário incorreto, arquivo
ausente, diretório exposto, link/hardlink/FIFO e ACL de leitura recusados.
Somente arquivos de `output/fixtures/` são criados/modificados. A fábrica
produtiva deve recusar o usuário comum antes de abrir o estado instalado.

Produção exige root e o arquivo persistente `.controller.lock` em
`/Library/Application Support/vpnt`, preparado pela futura instalação com
diretório `0700` e arquivo `0600`, ambos root. A fábrica não cria, substitui,
apaga ou corrige permissões. O instalador/atualizador deve preservar o inode
existente. O controlador deverá manter o handle durante todas as gerações e
o cleanup pendente, não só durante o despacho de um comando. Isso limita
controladores cooperantes; não impede outro processo root de alterar rotas,
nem é uma prova de ownership do kernel. O helper compilado já adquire esse
lock; sua execução privilegiada ainda está pendente. Nenhum lock instalado
foi criado nesta máquina.

## Runtime privado dos clientes

```bash
python3 scripts/macos/build-runtime.py
python3 scripts/macos/build-runtime.py --verify-only
```

O build fica em `target/`, incluindo pkgconf/autoconf/automake locais e fontes verificadas por
SHA-256. O strongSwan é compilado com os plugins necessários incorporados; seu
PID padrão fica em um prefixo próprio. O patch versionado permite ao futuro
driver indicar um PID diferente por perfil em configuração privada. A fonte
é extraída novamente do arquivo verificado antes de cada build. O openfortivpn
também é compilado da fonte restaurada, com os patches de `--no-routes`,
vínculo de transporte e suporte ao pppd legado do macOS. Nenhum comando instala
em `/Library` ou inicia túneis.

A verificação confere inventário/hashes, dependências Mach-O com prefixos
privados ou do sistema, assinaturas ad hoc e a versão mínima real do macOS.
Executa apenas `--version` sem privilégios, com bibliotecas da cópia de staging
e um arquivo de configuração fictício regular. O manifest não pode presumir
compatibilidade com um macOS anterior ao mínimo dos componentes.
O cliente real deve aceitar os argumentos fixos do driver e recusar 13 formas
inválidas dos novos metadados antes de chegar a `--version`; o check exige o
diagnóstico de parser esperado, não apenas um código de erro.

O bundle de CAs contém somente certificados públicos exportados do chaveiro de
raízes do sistema. Exportação vazia ou inválida interrompe o build; o sandbox
pode retornar uma lista vazia sem erro. O bundle e o patch de PID integram a
verificação do manifest. Os patches de rotas e transporte do openfortivpn
também são exigidos.
O build executa o callback C original de interface pronta, com chamadas de
rota/DNS interceptadas: nenhuma com `--no-routes`, chamadas preservadas ao
habilitar rotas. Esse fixture não faz escritas reais de rede.
Também executa o consumidor TCP original com o patch aplicado, usando somente
loopback para conferir vínculo ao índice, origem, descritor CLOEXEC e rejeições.

Esses checks não provam carregamento dos plugins privilegiados, criação de SAs,
PPP, tráfego pelo túnel ou cleanup de rotas. O controle de filhos tem testes de
processos reais para ambiente limpo, TERM, KILL após prazo e reap; isso prova
saída do processo direto, enquanto cada driver ainda deve verificar seus recursos.

A admissão em Rust repete inventário, SHA-256, proprietário, permissões e ACLs,
rejeita links e verifica os comandos de carregamento Mach-O. Os fixtures incluem
binários sintéticos inválidos e dependências em caminhos mutáveis. Para aplicar
esse mesmo código ao artefato nativo preparado, execute separadamente:

```bash
cargo test --locked --no-default-features --test runtime_policy -- --ignored
```

O cliente VICI usa sockets Unix com verificação do UID remoto, buffers de valores
apagados ao sair do escopo e `Debug` sem os valores. Testes exercitam o formato
binário, respostas/eventos intercalados, truncamento, fechamento do peer e prazo
total durante mensagens fragmentadas. O teste de listener precisa de permissão
de socket local. Esses fixtures não iniciam charon nem provam controle de uma SA.

O codec de pinentry implementa a troca usada por openfortivpn 1.24.1, com limite
de comandos/linha, consulta única da senha e resposta de erro fixa. Não usa
`SETKEYINFO` ou o texto do prompt para selecionar credenciais. `PinentryChild`
passa um socket anônimo pelo descritor 3 ao filho que iniciou. O adaptador
verifica o UID remoto; o helper exige o PID do filho esperado e uma única
mensagem completa antes de entregar a senha. O canal expira em cinco segundos
e é revogado em cancelamento, saída ou Drop. Cada tentativa tem um socket
diferente; não existe endpoint de senhas no filesystem.

`vpnt-pinentry` não aceita argumentos nem override de UID/caminho: exige UID real
e efetivo root e usa o canal herdado. O teste roda como usuário comum com
adaptador de fixture e UID explícito; isso não substitui a instalação e o teste
root do binário final. O caminho do driver/helper está compilado, sem execução
instalada ou privilegiada.

```bash
cargo test --locked --no-default-features --test pinentry --test pinentry_channel --test profiles --test secrets
python3 scripts/macos/check-pinentry-consumer.py
```

O segundo comando compila o leitor C original de senha do openfortivpn a partir
de fonte com SHA-256 fixado e o exercita contra o codec Rust. Verifica valores
fictícios com espaços, `%`, `+`, UTF-8 e os limites de 256 bytes. Os 12 cenários
incluem PID incorreto, protocolo/pedido duplicado, UID remoto errado, rejeição
do binário final sem root, revogação, expiração e filhos concorrentes com
senhas diferentes; não iniciam o cliente VPN. O código C fica no fixture,
separado do app. Os testes de entrada
rejeitam usuário SSL acima de 64 bytes, senha SSL acima de 256 bytes e fingerprint
fora dos 64 dígitos hexadecimais. O protocolo inicial só valida a forma dos
segredos; o tipo do perfil root determina o limite efetivo do cliente.

## Camada de processo SSL

```bash
cargo test --locked --no-default-features --lib
```

No macOS, os testes compilam um processo C descartável que consome os argv,
ambiente e canal herdado reais do driver. Ele verifica configuração vazia,
rotas/DNS/peerdns desativados, paths fixos, ambiente OpenSSL privado, ausência
de senha em argv e entrega pelo socket. Emite deliberadamente log com uma
senha fictícia, linha excessiva e mensagens de interface/falhas. O driver retém
somente observações tipadas; buffers de leitura são limitados e apagados.

Verificar cancelamento/reap e a preservação da causa após saída do processo.
Timeout inclui o texto real do Darwin (Operation timed out). O entrypoint
produtivo exige root, runtime instalado verificado e pinentry fixo com dono e
dependências confiáveis. O fixture usa explicitamente uma árvore do usuário e
não substitui essa prova privilegiada. Gateway SSL literal IPv6 é rejeitado;
o transporte do cliente usa IPv4/DNS. A seleção da saída resolve o gateway por
DNS-SD do sistema antes do túnel e consulta `RTM_GET`. O token é ligado ao
perfil, hostname, porta, interface, índice, endereços e próximo salto; a consulta
com escopo revalida a saída antes/depois do spawn. A entrada de DNS para probe
continua recusando índice zero.

```bash
python3 scripts/macos/check-transport-consumer.py
```

Este comando exige macOS, usuário comum e OpenSSL 4 já disponível no Homebrew.
Em cópia descartável da fonte com SHA-256 fixado, aplica os patches, compila
o consumidor TCP C e executa seis cenários em loopback. Resolve o IP fixo sem
consultar DNS e preserva o hostname. Confere `IP_BOUND_IF`, origem, CLOEXEC e
recusa de índice incorreto, opção de vínculo recusada, interface vazia/ausente.
Três mutações removem vínculo, comparação do índice e destino fixo; cada uma
deve compilar e falhar numa asserção executada. DNS é interceptado e proxies
são apagados; nem as mutações podem contactar um destino externo. A baseline
restaurada passa novamente. Logs/hashes ficam em
`output/fixtures/transport-oracles/`. O workflow prepara esse check no macOS;
preparo local não prova execução remota. Não cria PPP, rotas, DNS ou VPN.

Interface citada no log é somente candidata. Esses testes não provam propriedade
de PPP, leases/cleanup de rotas, probe pelo túnel ou estado conectado. Isso
continua pendente de controlador/helper e verificação nativa/real.

## Propriedade PPP e probe nativo

```bash
cargo test --locked --no-default-features --lib connection::macos
```

No macOS, `OwnedPpp` identifica o filho do cliente ainda sob handle por UID,
executável fixo, pai, instante de início e registro PPP do `configd`. A interface
deve estar ativa, ter índice/endereços e não estar ativa no snapshot anterior.
Registros ausentes, duplicados ou incompatíveis não autorizam o vínculo. O nome
do log não seleciona a interface: dois túneis podem ter endereços iguais.
`kqueue` acompanha a saída dos dois processos sem sinalizar PIDs descobertos.
Cada uso revalida processos, registro, índice e endereços. PPP encerrado não
equivale a rotas limpas; uma interface ainda ativa sem novo dono verificado não
é declarada removida apenas pela saída do cliente.

`/private/var/run` é gravável pelo grupo de sistema no macOS. A implementação
não trata seus pidfiles como prova confiável e não modifica suas permissões.
A associação vem da leitura do serviço de configuração e da identidade nativa
dos processos. O código publicado do [pppd da Apple](https://github.com/apple-oss-distributions/ppp/blob/main/Helpers/pppd/sys-MacOSX.c)
define os campos `pid` e `InterfaceName`; o [controle do configd](https://github.com/apple-oss-distributions/configd/blob/main/configd.tproj/session.c)
exige root ou entitlement de escrita. O módulo de propriedade só lê esses registros.

O probe público aceita somente um `OwnedPpp`, revalida o vínculo antes/depois
da resposta e não promove sozinho o estado Connected. Ping usa binários do
sistema, interface/origem explícitas e prazo; TCP exige `IP_BOUND_IF` ou
`IPV6_BOUND_IF`, bind da origem e conferência das opções após o handshake.
O socket permanece sob handle durante a checagem final. Não há fallback para
socket sem vínculo, payload de aplicação ou porta 22. Alvos locais, loopback,
multicast, não especificados e broadcast global são rejeitados em produção,
incluindo loopback representado como IPv4-mapped IPv6.

DNS-SD recebe o índice explícito, com consultas A/AAAA separadas, limite de
resultados e de espera. Os serviços são desalocados antes dos contextos; não
sobram threads de resolução após cancelar. O lookup não prova tráfego: uma
resposta local/cacheada ainda precisa passar pelo teste no socket vinculado.

Separar as evidências deste comando:

- **Nativa, local:** leitura somente de PPP no `configd`; identidade/UID/pai e
  saída de processos próprios; TCP e ping em `lo0`, IPv4/IPv6; DNS de localhost;
  prazo e cancelamento de espera no kernel.
- **Fixture:** registros CF tipados e snapshot PPP sintético para associação,
  recusas de dono/pai/executável, interface já ativa ou inativa, registros
  ausentes/duplicados; vínculo de teste invalidado após handshake TCP real.
- **Pendente:** descoberta de PPP real criado pelo cliente, tráfego remoto pelo
  túnel, integração com gerações/helper/UI, leases e remoção real de recursos.

Os testes não criam interfaces, rotas, SAs ou registros no `configd`. O comando
pode precisar sair do sandbox para sockets, ICMP e o serviço nativo. Isso é
execução como usuário comum; não instala componentes nem se torna root.

## Retenção PPP e protocolo de ADD

```bash
cargo test --locked --no-default-features --lib connection::macos::ppp_attachment
cargo test --locked --no-default-features --lib connection::macos::routing::write
```

`PppAttachment` exige root, um `ControllerLock` ainda vivo e `OwnedPpp` válido
antes/depois do vínculo. Abre seu próprio socket de controle `PF_PPP`, emite
somente `PPPIOCATTACH` para a unidade comprovada e confere `PPPIOCGUNIT`.
O descritor CLOEXEC mantém essa referência até sair do escopo. A API não expõe
o FD, não cria unidades e não emite `PPPIOCDETACH` ou destruição por nome.
Nome, unidade e índice são distintos: o fixture usa ppp42 com índice 234.
Validar a referência não significa que pppd ou a conexão estejam ativos.

A [camada de controle PPP da Apple](https://github.com/apple-oss-distributions/ppp/blob/main/Family/ppp_domain.c)
associa o socket à unidade e solta seu cliente no fechamento. O
[driver de interface](https://github.com/apple-oss-distributions/ppp/blob/main/Family/ppp_if.c)
conta os clientes e chama o detach quando sai o último. Essa leitura fundamenta
a estratégia de ciclo de vida; **não prova** comportamento ou cleanup na máquina
atual. A integração deverá observar a ausência das rotas após desligar o cliente
e fechar apenas sua própria referência, mantendo cleanup pendente na incerteza.

Os três testes de retenção usam um socket Unix real para observar fechamento,
mas interceptam abertura/ioctls PPP. Conferem ordem, unidade, CLOEXEC, mudança
de ownership durante o vínculo, erro de attach e descarte da referência em
falha. O EOF pode aguardar o exec de outro fixture que tenha acabado de fazer
fork; não depende de fechamento instantâneo. O gate de UID é exercitado sem root.
Isso é fixture de controle/lifecycle, não uma retenção PPP nativa executada.

`AddWriter` é separado de `Reader`. Sua fábrica exige root e lock; o método
PPP aceita somente uma interface comprovada e sua referência retida, derivando
índice e origem. O método de blackhole deriva esses dados de uma UTUN própria
e exige o mesmo lock. Ambos revalidam antes/depois do envio e emitem somente
`RTM_ADD`, sem substituir ou apagar rotas. Famílias sem origem no recurso são
recusadas. O codec suporta IPv4/IPv6, origem link-local com escopo, máscaras,
host e blackhole. Os testes de ADD continuam sendo prova de ABI, sem escrita
no kernel; não provam bloqueio de tráfego.

Os dois testes de ADD usam somente `AF_UNIX`. Um processo C independente,
compilado contra `net/route.h` e `net/if_dl.h` do SDK, decodifica o pacote real
e verifica endereços/máscara, flags, índice e origem. O C também confere a
codificação dos dois ioctls PPP com as macros do SDK, usando os números do
[header PPP publicado](https://github.com/apple-oss-distributions/ppp/blob/main/Family/if_ppp.h).
São 11 cenários de mensagens: IPv4, IPv6, origem link-local com zona, host,
blackhole, PID/seq estrangeiros, EEXIST, origem alterada, truncamento, peer
encerrado e peer silencioso. Casos separados verificam cancelamento antes e
depois do envio, sem depender de sleeps para sincronizar o cancelamento.

Depois de tentar enviar, timeout/cancelamento/erro retornam um recibo não
confirmado com a rota tentada; não se presume que nada foi criado. Antes do
envio, cancelar não produz pacote. A confirmação exige ACK com PID/seq/opcode,
rota e origem esperados, mas é somente prova de protocolo: o controlador deverá
reler a tabela e executar o probe antes de Connected. Nem ACK nem igualdade de
atributos fornece identidade para DELETE. Não há API de DELETE/CHANGE.

Nenhum teste chama a fábrica privilegiada de ADD, anexa um socket PPP real,
cria interface ou escreve no kernel de rotas. A aplicação/remoção nativa e a
integração ao helper/controlador seguem pendentes.

## Interface própria para a família IP ausente

```bash
cargo test --locked --no-default-features --lib connection::macos::sink
```

O adaptador preparado abre um controle UTUN com unidade automática, guarda o
descritor CLOEXEC e recusa nomes/índices já presentes no snapshot anterior,
inclusive interfaces inativas. Exige root e lock. Antes de atribuir endereço,
desativa e relê `UTUN_FLAGS_NO_INPUT | UTUN_FLAGS_NO_OUTPUT`. Usa um endereço
aleatório privado ULA IPv6 `/128` ou link-local IPv4 `/32`, exclusivo da família
ausente. Até 32 candidatos são conferidos contra endereços existentes e rotas
de host em qualquer escopo; uma colisão posterior invalida o recurso.

Os pedidos de alias só recebem o nome retornado pelo próprio controle. Não há
alteração de interface descoberta por log/IPC. A intenção de atribuir endereço
é registrada antes do ioctl: até uma falha parcial fecha só o FD próprio e
conserva metadados para observar o cleanup. O fechamento não equivale a remoção
observada; são conferidos nome/índice, qualquer rota referindo o índice e o
endereço/rota de host, incluindo uma rota local que reste em `lo0`.

Os seis testes interceptam a criação, conexão, opções e alias; o único FD real
é de um socket Unix descartável. Cobrem ordem, duas famílias, CLOEXEC,
falhas/races/cancelamento, nome/índice preexistente, seleção limitada e cleanup.
Um consumidor C independente lê os bytes por stdin, com estruturas/macros do
SDK, e confere unidade automática, sockaddr_ctl, flags, ifaliasreq/in6_aliasreq,
máscaras, peer, escopo, NODAD e lifetimes. O C não abre sockets nem usa ioctl.
O gate de UID é executado como usuário comum sem abrir controle nativo.

A estratégia segue o [controle UTUN do XNU](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/net/if_utun.c)
e a seleção de endereço da [camada de rotas](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/net/route.c).
O endereço da mesma família é necessário para o plano de ADD; usar somente um
gateway AF_LINK não elimina essa exigência. Leitura de fonte e ABI não provam
criação, descarte de pacotes ou detach na versão instalada. Nenhuma UTUN,
endereço ou rota foi criada pelos testes; esses gates continuam pendentes.

## Backend de leases e cleanup por interface

```bash
cargo test --locked --no-default-features --lib connection::macos::routing::backend
cargo test --locked --no-default-features --lib owned_ppp_exit_requires_both_original
```

`NativeBackend` liga `AddWriter`, `PppAttachment`, `OwnedPpp`, o lock global e
`Snapshot` ao contrato de `Coordinator`. O registro é ligado a UID/perfil/geração
e a um plano de redes. O coordenador consulta essa autorização antes de criar
ou emprestar uma rota. O escritor só recebe destinos desse plano e de interfaces
retidas; o cancelamento usa uma flag própria da geração. O entrypoint compilado
do helper já o consome pelo controlador SSL. O adaptador root ainda não foi
executado no caminho instalado.

A confirmação exige ACK e releitura da chave exata destino/máscara/escopo.
Prefixo que apenas contém o destino, outro escopo ou duplicidade de chave não
substituem essa prova. Falha posterior ao envio permanece num recibo, inclusive
se a tabela depois voltar a coincidir. O backend converte falhas de leitura em
indisponibilidade; não permite que `Error::Changed` do adaptador seja confundido
com recurso substituído e descartável pelo coordenador.

O ciclo de encerramento preparado é: parar o cliente, marcar a geração em
cleanup, aguardar ambos os watches de saída, fechar apenas as referências PPP
e UTUN próprias, repetir o cleanup das leases e conferir os destinos do plano
e recursos implícitos. A liberação final exige ausência dos índices, de qualquer
rota que ainda os referencie e de rotas locais dos endereços. Um endereço PPP
compartilhado por outro vínculo preserva sua rota; não se exige removê-la.
Fechar a referência não significa que as rotas sumiram. Rotas emprestadas
também entram na conferência final. Mesma interface ainda presente, mesmo com
atributos diferentes ou possível reutilização do índice, mantém pendência.
Uma rota observada em interface estrangeira é preservada; uma movida para
outro destino próprio continua pendente. Não há DELETE/CHANGE por chave.

Os onze testes do registro exercitam o consumidor `Coordinator` com tabela e
ciclo de vida de interface simulados. Cobrem autorização, redes não registradas,
ACK perdido, ACK sem rota, falha de leitura após ADD, bloqueio de nova geração
durante cleanup, fechamento único, empréstimos, substituição/reuso, tokens de
outro backend, dois destinos próprios, migração entre eles e cleanup implícito
pendente após as quatro leases de full tunnel desaparecerem. Dois testes
adicionais verificam a fila de aposentadoria de falhas, erros de leitura,
nova admissão bloqueada e rotas implícitas/endereços compartilhados. Isso não executa
o adaptador privilegiado e não prova retenção PPP, ADD ou purge de rotas reais.

O teste de saída usa quatro processos próprios ao todo, em duas ordens de
encerramento. Executa `OwnedPpp::processes_exited` com os dois watches reais e
exige que ambos tenham saído. A associação/interface desse teste é sintética;
não inicia pppd nem openfortivpn. A leitura real de loopback também confere a
chave exata no snapshot; um teste puro recusa prefixo mais amplo, escopo
diferente e duplicidade.

O plano aceita ausência de sink somente quando ele não é necessário. A fábrica
PPP prepara a UTUN apenas para full tunnel com uma família sem origem; redes
split explícitas sem suporte continuam inválidas. Cadastro que falha conserva
uma guarda de aposentadoria, inclusive após configurar um alias. A fila impede
nova admissão até a remoção observada. O futuro helper precisa parar seus filhos
e consumir `reap_retired`/`has_resources`, além das leases, antes de encerrar.
Fixtures não executam a fábrica privilegiada. Releitura e leases também não
substituem o probe pelo túnel para promover a sessão a Connected.

## Supervisor PPP e barreiras antes do exec

```bash
python3 scripts/macos/check-ppp-supervisor.py
python3 scripts/macos/check-ppp-supervisor-mutations.py
```

Os comandos exigem macOS, usuário comum e o tarball do openfortivpn 1.24.1
preparado pelo build de runtime/consumidor de pinentry. O SHA-256 é conferido
antes de aplicar o patch obrigatório e extrair `pppd_run` e seu construtor de
argv. A fixture troca somente o caminho fixo do supervisor para o executável
de teste. Forkpty, PTY e exec são reais; `/usr/sbin/pppd` é substituído por um
programa C fictício. Ele confere stdio no PTY, ambiente limpo, ausência de FD 3/4
e grava somente um marcador local para provar que chegou ao exec.

O supervisor preparado aceita a lista completa e exata de argumentos; não
aceita call, file, plugin, caminhos ou opções adicionais. O entrypoint produtivo
exige UID real/efetivo root; não oferece override de UID, caminho ou modo.
FD 4 precisa ser um stream do proprietário esperado e fica CLOEXEC. FD 3 é
fechado. Supervisor e filho fazem handshakes separados com tags/PID, antes do
fork/exec; só operações nativas sem alocação/locks rodam no pre_exec. O PID
também é comunicado ao próprio pai por pipe CLOEXEC, para registrar falha de
exec. I/O de cada handshake tem prazo monotônico de cinco segundos.

EOF, dados de controle inesperados e HUP/INT/TERM revogam a execução. O
supervisor sinaliza apenas seu Child não reaped, espera término e pode escalar
para KILL desse mesmo handle após um segundo. O recibo final vem após wait;
falha de protocolo/exec não é transformada em sucesso.

O receptor produtivo autentica UID real/efetivo, executável, pai e identidade
PID/início via APIs nativas antes de cada permissão. Mantém três ExitWatch
originais e registra a possível autorização antes de escrever o ACK. Cancelar
fecha a escrita, conservando a leitura de recibos/EOF. A saída do cliente e
EOF não encerram cleanup após uma possível autorização: todos os três watches
precisam indicar saída, mesmo que o recibo final tenha sido perdido.
O driver passa senha em FD 3 e controle em FD 4 no mesmo pre_exec; pinentry
fecha FD 4, e o filho PPP não recebe nenhum dos dois canais após exec.

Os 16 cenários de wire usam um receptor independente. Cobrem término normal,
EOF, TERM ignorado/escalation, saída do cliente, fechamento real do PTY/HUP,
dado extra, PID incorreto nas duas permissões, revogação durante pre_exec,
peer errado, exec ausente, call/opções adicionais e rejeição do binário
produtivo como usuário comum. Um marcador não pode existir antes das permissões.
Nove cenários adicionais usam o receptor produtivo e a passagem real de FD 3/4,
com proprietário/caminhos próprios de fixture: normal, revogação, TERM ignorado,
saída do pai, programa errado, pai estrangeiro, falha de exec, cancelamento
prévio e órfão. No último, o cliente de teste mata somente seu supervisor filho;
o payload ignora HUP/TERM e termina sozinho. O receptor precisa manter cleanup
pendente depois do EOF/saída dos pais até o watch do PPP original indicar saída.
Dois casos deixam o canal aberto em silêncio: antes da permissão do supervisor
e antes da permissão do filho. Ambos precisam terminar entre 4,5 e sete segundos
sem executar o payload; o segundo também exige saída do filho original antes
do recibo final. Esses casos exercitam o prazo monotônico de cinco segundos.

A matriz usa cópia descartável com source/build próprios: baseline de 16 casos
wire e nove do receptor, 16 mutações e restauração dos mesmos 25 casos.
Compilação/formatação não contam como falha discriminante: exige assertion
executada do consumidor. As mutações removem as duas permissões, comparação de
PID, CLOEXEC, fechamento da senha, tratamento de HUP/wait, ordem do recibo,
preservação do PTY, limite de argv, verificação de pai no receptor e espera do
PPP órfão. Cinco adicionais omitem opções internas de segurança, estendem o
prazo para 30 segundos ou aceitam postoptions, opções por TTY e política do
home root. As três últimas executam assertions dos testes de filesystem;
as demais exigem falha do consumidor de processos. A matriz exige o consumidor
previsto para cada mutação; falha incidental de outro teste não conta. Os nomes
temporários dos testes de configuração usam contador atômico, e a lista de
entradas é independente da lista produtiva. Comandos, exits e hashes de src/tests ficam em
`output/fixtures/ppp-supervisor/` e `output/fixtures/ppp-supervisor-oracles/`;
fonte/build descartáveis são removidos.

O runtime nativo foi recompilado com os três patches do openfortivpn; a admissão
Rust do artefato preparado passou. O manifest exige o hash do patch de supervisão,
e o teste de política recusa sua ausência ou hash divergente. A fixture TCP
executada com esses mesmos patches passou os seis casos e três mutações;
o consumidor nativo de senha passou 12 casos. Isso não instala o runtime.

**Limites:** o receptor, o driver e o backend estão integrados em código, sem
helper/UI instalado. A admissão de configuração abaixo ainda precisa ser
exercitada no caminho root instalado, com o pppd do sistema. A checagem
de cleanup precoce descrita abaixo tem evidência de fixture, não de recursos PPP
reais. Nenhum teste chamou system pppd, criou interface, alterou rotas ou usou
credenciais de VPN.

## Admissão da configuração global PPP

```bash
cargo test --locked --no-default-features --offline --lib helper::ppp_config
```

A inspeção foi somente de leitura: manual local, strings/metadados de assinatura do executável
e fonte pública da Apple. O binário local contém `ppp-884`; isso orienta a versão
da fonte, sem provar equivalência entre fonte e binário. A fonte consultada é
[Apple ppp-884](https://github.com/apple-oss-distributions/ppp/tree/ppp-884/Helpers/pppd):
`main.c` lê options, o home obtido por getpwuid, argv e depois postoptions;
`tty.c`/`options.c` leem opções da TTY. `pathnames.h` e os consumidores de IP/auth
mostram os hooks e arquivos de segredos. A verificação `codesign --verify --strict -R '=anchor apple' /usr/sbin/pppd`
passou como usuário comum fora do sandbox. Dentro dele retornou
CSSMERR_TP_NOT_TRUSTED; o resultado fora dele é a evidência de confiança.
A inspeção não executou pppd/dryrun:
a carga de plugins já pode acontecer enquanto o parser lê configuração.

O entrypoint root e o início do driver recusam arquivos de opções/hooks/segredos
ambientes, inclusive arquivos vazios, diretórios ou symlinks pendentes. Recusam
todo `options.*`, sem adivinhar o nome do PTY futuro. O home vem de getpwuid(0),
sem confiar em HOME; `.ppprc` e `.ppp_pseudonym` precisam estar ausentes. Caminhos
e ancestrais exigem proprietário confiável, sem symlink ou escrita concedida a
outros por modo/ACL. Erro de leitura e diretório excessivo recusam admissão.
O pppd fixo também tem arquivo/ancestrais/proprietário/permissões conferidos.
Não há leitura do conteúdo de segredos, parser de configuração, exclusão ou
correção da configuração existente. `peers` é preservado; call/file/plugin são
recusados no argv. Mudanças concorrentes feitas por outro processo root não
são impedidas atomicamente por esse gate; administradores root são confiáveis.

A fonte de `acscp.c` habilita ACSP por padrão. O comando interno acrescenta
`noacsp`, `no-use-dhcp`, `no-intercept-dhcp`, `noproxyarp` e `nopersist`, sem
aceitar essas opções do caller/IPC. Os nomes também estão presentes no binário
local. O payload C fictício recebe o argv do mesmo builder produtivo e confere
a lista completa, além dos canais/PTY; isso não executa o parser do sistema.

Dois testes de filesystem próprio cobrem opções/scripts/segredos inacessíveis,
postoptions, PTY com pontos, symlinks pendentes, diretórios no lugar dos arquivos,
permissões inseguras e diretório inacessível. O conteúdo e um perfil estrangeiro
em peers permanecem intactos. Três mutações exigem falha desses testes; a omissão
das opções internas exige falha do consumidor de processos. Evidência e hashes
das fontes Apple ficam localmente em `output/fixtures/pppd-audit-source/`.
Nenhuma configuração global foi alterada. A admissão root instalada e seu
comportamento com o pppd real ainda não foram executados.

## Controlador SSL por geração

```bash
cargo test --locked --no-default-features --lib connection::controller
```

O consumidor preparado `run_ssl` exige root e o lock persistente, carrega do
storage root os perfis do UID autenticado pelo helper e mantém
workers SSL separados por perfil; IPsec aparece somente nos metadados.
O executável preparado chama a fábrica e o
adaptador nativo, ligado em código ao broker normal, sem execução root ou prova
de VPN pela UI nesta entrega.
IPsec ainda precisa do seu driver e do despacho correspondente.

Conectar e desligar exigem geração maior que a anterior daquele perfil;
probe exige a geração atual. Credenciais são validadas antes de invalidar uma
operação anterior. Reconectar cancela o worker antigo e guarda somente uma
tentativa nova, em memória, até o cleanup terminar. Desligar ou EOF descartam
essa tentativa e seus segredos. Estados antigos são rejeitados tanto ao ler o
worker quanto ao entregar mensagens que aguardavam uma saída lenta.

O worker seleciona egress/snapshot antes do cliente, descobre OwnedPpp, registra
o plano no backend e adquire as leases. Só então entra em Verifying. Um probe
responsivo exige revalidar cliente, vínculo e leases antes de Connected; falta
de tráfego produz Unresponsive. Probes periódicos ou pedidos pela geração atual
podem recuperar a resposta. A fila de saída tem limite; a leitura trabalha em
lotes, e o estado mais recente de cada worker é coalescido em seu próprio slot.
Uma saída cheia não bloqueia cancelamento/cleanup. EOF ou consumidor de saída
perdido cancela todos os workers e aguarda leases e aposentadorias antes de
retornar e permitir a liberação do lock.

Os sete testes originais usam os codecs reais de request/message, Coordinator e processos
`sleep` próprios, parados e reaped pelo mesmo ManagedChild. A tabela, vínculo,
probe e condição de purge são simulados. Cobrem conectar/verificar/sem tráfego/
recuperar/desligar, probe tardio, nova geração aguardando cleanup, cancelamento
antes de descoberta, cancelamento de reconexão enfileirada, falha após probe,
dois perfis concorrentes, EOF com aposentadoria pendente, requisições antigas,
segredos inválidos e consumidor que deixa de ler. Nenhum teste inicia pppd,
openfortivpn ou strongSwan, atribui endereços ou altera rotas reais. O caso de
EOF espera uma observação real da barreira de aposentadoria ou um término
indevido do controlador; uma consulta instantânea a `is_finished` sozinha
não prova que o loop já chegou a essa barreira.

Se o setup falha depois do spawn, o driver conserva processo e recibos até
cleanup. Antes de qualquer permissão PPP, EOF após saída do cliente prova que
nenhum holder pode obter uma permissão futura. Se houve possível permissão,
o controlador espera os três processos originais. Quando ainda não descobriu
OwnedPpp, usa a observação anterior de interfaces/rotas e uma releitura de configd:
uma PPP nova/alterada sem dono estrangeiro comprovado ou uma rota nova sem
explicação segura conserva a pendência. Preserva observações anteriores e PPPs
estrangeiras comprovadas; não apaga interface/rota por nome, PID ou chave.
Dois testes puros e duas mutações discriminantes exercitam esse fallback,
incluindo PPP anterior inativa que aparece ativa, rota local residual,
neighbor cache físico e rota cujo índice já desapareceu. Não houve execução
privilegiada desse caminho ou prova de purge real. Não há timeout que transforme
incerteza em Off. A ligação instalada ao helper/broker/UI, validação da admissão,
instalação e conexão real continuam pendentes.

## Política de rotas e leitura nativa

```bash
cargo test --locked --no-default-features --test route_leases --test route_flow
cargo test --locked --no-default-features --lib connection::macos::routing
python3 scripts/macos/check-route-policy.py
```

O primeiro comando é portável. Usa um kernel de fixture com identidades de
recursos e falhas observáveis. Verificar empréstimo sem remoção, compartilhamento
até o último usuário, sobreposição de prefixos distintos, conflito exato,
UID/perfil/geração, handles de coordenadores diferentes e rollback em ordem
inversa. O pin do gateway pode ser adquirido antes do cliente e estendido com
as redes após a descoberta PPP. Uma extensão incompleta com rollback pendente
não pode validar como pronta. Falha ao remover uma rede retém o pin anterior,
os recibos e o perfil ocupado até o retry; não basta apagar a sessão da lista.

Rede vazia significa túnel completo: pares `/1` preservam os defaults `/0`.
O plano prevê blackhole para a família IP não suportada, em vez de deixá-la
usar silenciosamente a conexão física. Redes explícitas sem suporte são
recusadas. Isso valida o plano; não comprova que o kernel aplicou o bloqueio.

O segundo comando, no macOS, lê `NET_RT_DUMP2` e consulta somente `RTM_GET`
no kernel real; os testes de ADD usam apenas os datagramas privados acima.
As respostas de loopback são conferidas contra o índice de `lo0` obtido por
uma API independente. O codec trata alinhamento de quatro bytes, máscaras
compactas, escopo IPv6/KAME, limites e truncamento. O consumidor GET também é
exercitado por datagramas privados: PID/seq incorretos não podem satisfazer
outra consulta. Nenhum dado pessoal da tabela é impresso. São evidências de
leitura nativa e protocolo; não são provas de ADD/DELETE ou de tráfego VPN.

O terceiro comando exige macOS e usuário comum. Em cópia descartável de fonte
e build, executa baseline, mutações nomeadas e baseline restaurada; falhas de
compilação não contam como mutações detectadas. A mutação de opcode GET executa
**somente o teste puro do codec**; a de opcode ADD executa somente o consumidor
C/AF_UNIX. Nenhuma envia o opcode alterado a um socket de rotas.
As outras consultas nativas permanecem GET. Cópia/build são removidos;
logs, comandos e hashes de fonte ficam em `output/fixtures/route-oracles/`.
São 67 mutações, incluindo remoção do vínculo de perfil da saída SSL,
aceitação indevida de DNS sem escopo para probe e retirada do flock, vínculo
de inode, ACL ou checagem de hardlink do controlador. As dez novas de ADD/PPP
retiram opcode correto, índice, zona da origem, PID/seq, comparação de origem,
recusa de ACK perdido, recibo após cancelamento, leitura da unidade ou validação
final do dono. As 15 novas do backend retiram autorização, plano de redes,
releitura exata, confirmação, retenção de recibos, tratamento de erro, varredura
de destinos, espera de saída, vínculo ao backend/geração ou checagem de destinos
próprios. Também alteram a busca exata e a conjunção dos watches.
As 12 novas retiram bloqueio dos dois sentidos, recusa de interface anterior,
intenção de alias parcial, validação posterior, recusa de colisão de host,
máscara IPv6 host, NODAD, unidade automática, gate de cleanup implícito,
retenção de aposentadoria, observação da rota local PPP e bloqueio de admissão
pendente. Executam somente fixtures de chamadas/AF_UNIX e o consumidor stdin;
nenhuma dessas mutações cria uma UTUN ou endereço real.
Oito novas do controlador aceitam estado/operador antigo, iniciam substituto
antes de cleanup, omitem a espera de cleanup/aposentadoria, promovem conexão
sem teste, aceitam probe sem resposta ou preservam uma reconexão após desligar.
Duas adicionais retiram a espera por PPP nova/alterada sem atribuição e por
rotas residuais no cleanup precoce. Baseline e restauração também executam os
oito cenários do controlador e os dois testes desse fallback.
As baselines nativas incluem
seleção de saída por `RTM_GET` de TEST-NET, sem abrir conexão para esse endereço.
Baseline e restauração também executam os cinco testes do lock. O processo
Python independente detecta a mutação que omite o flock; bookkeeping interno
não basta para satisfazer o teste.
O workflow macOS prepara essa mesma execução; CI remoto ainda precisa rodar.

Confirmação/cleanup de recursos reais, bloqueio de tráfego na UTUN e integração helper/UI
continuam pendentes. O [delete de rotas no XNU](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/net/route.c)
seleciona a chave destino/máscara/escopo, sem comparação atômica dos atributos
observados antes. O backend deverá lidar com alterações concorrentes e identidade
perdida; a identidade monotônica do fixture não fornece essa prova no macOS.
Não usar igualdade de atributos ou um pidfile para declarar ownership nativo.

## Fluxos de demonstração

Use `cargo run -- --demo-server 4178` e abra o endereço local do README.
Exercite pelos controles visíveis, nos dois idiomas e temas:

- Conectar e cancelar antes da conclusão; o resultado tardio não pode religar.
- Conectar, forçar "sem resposta", reconectar e desligar todas as VPNs.
- Editar, continuar editando após Voltar e descartar sem persistir alterações.
- Cadastrar/remover um perfil e enviar senhas fictícias; dados reais ficam fora
  do modo de demonstração. Porta de teste 22 deve ser rejeitada.
- Alterar idioma e tema, recarregar e conferir persistência e traduções.
- Navegar com teclado, usar setas/Home/End nas abas do log, cancelar diálogos
  com Escape e verificar foco visível/contido.
- Medir painel de 320 px, campos alinhados e ausência de corte ou overflow
  horizontal; testar também uma viewport menor e conteúdo com rolagem.

No host nativo, verifique separadamente ícone, abertura/fechamento pelo clique,
posicionamento, Escape, diálogo antes do painel, perda de foco e saída. Uma
janela criada, um processo ativo ou a UI em Chrome não provam esses comportamentos
em WKWebView. Se a captura ou automação nativa estiver bloqueada pelo macOS,
registre o limite em vez de declarar a revisão visual nativa aprovada.

## VPN real

Ainda pendente. Antes de declarar essa camada pronta, testar o consumidor real
de perfis/chaveiro/helper e os clientes strongSwan/openfortivpn. Exercitar conectar,
cancelar durante a conexão, reconectar, desligar e túnel sem tráfego. Confirmar
que só o teste pelo túnel permite exibir "conectada", sem depender apenas de PID,
porta pública ou rota. Preservar configurações existentes e impedir acesso a
segredos por arquivos, argumentos, logs ou snapshots de UI.

Instalação privilegiada e conexão com configurações reais exigem a autorização
específica aplicável. Fixtures e simulações devem ser identificadas como tais.

## Arquivo e estrutura

Na raiz do repositório, com Node.js, Bun e OpenPencil CLI disponíveis:

```bash
node --check design/build-proto.mjs
bunx @open-pencil/cli info vpnt.fig --json
bunx @open-pencil/cli lint vpnt.fig --json
```

Critérios:

- Sintaxe do gerador válida.
- Dez páginas com os nomes descritos no README, sem página padrão vazia.
- 84 componentes principais, 42 por tema, e instâncias vinculadas nas telas.
- Os 14 estados do cartão presentes nos temas claro e escuro.
- Lint recomendado com zero erros, avisos e informações.

## Revisão visual

Abra `vpnt.fig` no OpenPencil e confira as dez páginas. Para revisar uma página
renderizada a partir do arquivo salvo:

```bash
bunx @open-pencil/cli export vpnt.fig --page '1 · Painel' -f png -o /tmp/vpnt-panel.png
```

Confira legibilidade, cortes, sobreposição e ações visíveis em painel, cartões,
preferências, perfis, primeiro uso, log, diálogos, ícone e menu. O painel deve
mostrar o aviso de túnel sem resposta com Reconectar e Desligar.

## Componentes e reprodução

Use uma cópia descartável para estes testes:

1. Abra as dez páginas da cópia para carregá-las no editor.
2. Altere uma propriedade visual dos componentes principais e confira a
   atualização das instâncias, inclusive nas outras páginas. Os textos
   personalizados, como nome da VPN e rótulo dos botões, devem ser preservados.
3. Feche a cópia sem salvar.
4. Crie um documento vazio separado e execute o gerador conforme o README.
5. Salve o resultado em outro caminho e rode `info`, `lint` e a revisão visual
   nesse arquivo. Ele deve atender aos mesmos critérios do arquivo versionado.

Mudanças deliberadas de telas ou estados devem atualizar o protótipo, o gerador
e os critérios afetados em conjunto.

## Limites do protótipo

Renderização, lint e propagação de componentes não provam conexões de VPN ou
transições funcionais; os controles de `vpnt.fig` são estáticos.

## Backend de usuário: kernel-libipsec, observação e admissão VICI

Estado desta integração, sem instalação de runtime e sem VPN real. Comandos na
raiz do repositório, como usuário comum:

```bash
cargo test --locked --no-default-features --lib connection::macos::utun_socket::tests
cargo test --locked --no-default-features --lib connection::macos::utun_observer::tests
cargo test --locked --no-default-features --lib connection::ipsec::producer::tests::utun
RUST_TEST_THREADS=4 cargo test --locked --no-default-features --lib helper::process::tests
RUST_TEST_THREADS=4 cargo test --locked --no-default-features --lib connection::ipsec::tests::control
cargo test --locked --no-default-features --test runtime_policy -- --ignored
python3 scripts/macos/build-runtime.py --verify-only
python3 scripts/macos/tests/test_rust_build_inputs.py
python3 scripts/macos/tests/test_runtime_configure_recovery.py
```

- [PASS, local] `helper::process::tests`: 1 teste. O filho de fixture confere
  stdin como FIFO anônimo somente leitura, stdout/stderr em `/dev/null`; o pai
  mantém a única escrita com `FD_CLOEXEC` e o filho sai normalmente após o EOF.
  O fixture é um filho comum, não o watcher do charon; a composição com o
  watcher original está provada em fixture separado, sem daemon real.
- [PASS, local] `connection::ipsec::tests::control`: 12 testes, com peer VICI
  independente. Inclui a admissão de `stats`/plugins antes de qualquer load ou
  envio de credencial, a recusa de backend ausente/PF_KEY/duplicado/malformado e
  a ordem `version`, `stats`, `load-conn`, `load-shared`, `initiate`. O audit do
  peer prova os comandos enviados e sua ordem; a posição de `Config::shared` é
  verificada por inspeção do código, não pelo audit.
- [PASS, SDK/fixture] `connection::macos::utun_socket::tests`: quatro testes;
  `connection::macos::utun_observer::tests`: nove. O positivo de utun é
  sintético; os negativos usam descritores de um filho comum próprio. Nove
  mutações do observador foram detectadas, com baseline e restauração.
- [PASS, consumidor nativo de fixture]
  `connection::ipsec::producer::tests::utun`: cinco testes pelo método público
  `NativeContext::observe_interface`, incluindo tentativa não iniciada, owner
  alheio, scanner sem utun, aposentadoria e mutex ocupado com prazo/cancelamento.
  Cinco mutações foram detectadas por assertions. Nenhuma observação concede
  autoridade de lease, rota ou cleanup.
- [PASS, runtime privado preparado] O teste ignorado
  `prepared_native_runtime_passes_the_same_admission_code` foi executado:
  um teste passou. Ele admite os arquivos preparados para o usuário comum;
  não exerce a instalação root-owned.
- [PASS, sem privilégio] `python3 scripts/macos/build-runtime.py --verify-only`
  terminou com exit 0; `output/fixtures/libipsec-final-runtime.log` registra
  `Verified 10 runtime files; minimum macOS 26.0; versions OK`. O mínimo 26.0 é
  metadado derivado desta máquina, não um novo mínimo suportado; host e
  fixtures miram 13.
- [PASS, local] `test_rust_build_inputs.py` e
  `test_runtime_configure_recovery.py`: 7 testes cada, sem Cargo, rede,
  privilégio ou build. Eles também rodam no job macOS do CI, antes dos gates
  caros.
- O shim C do SDK (`native/utun_socket.c`) só é compilado quando o alvo é
  macOS: `build.rs` retorna antes em outros alvos, e `cc` está fixado em
  `=1.11.1`. A nova borda de build reutiliza a versão já existente no lockfile,
  sem mudar versões de dependências; nenhum serviço ou action foi acrescentado.

[PASS, integração local] Fmt, clippy com `-D warnings`, build, 330 testes
desktop e 314 core passaram com `RUST_TEST_THREADS=4`, dois ignored em cada
suíte. As 32 mutações do produtor passaram com controles verdes do pipe antes
e depois da matriz; as 59 mutações iniciais de controle também passaram.
`output/fixtures/libipsec-integration-receipt.json` registra fontes estáveis,
sem VPN ou instalação real. A primeira falha de lint e seu recibo permanecem
em `libipsec-initial-*`; a correção equivalente de `is_multiple_of` entrou antes
da execução verde.

[PASS, escopo final afetado] Depois dessa integração, mudaram somente os casos
de limite do peer/checker VICI e a exatidão JSON da recuperação de configure.
Fmt e clippy foram repetidos; os 12 testes de controle, a matriz completa de
61 mutações, os dois testes Python de sete casos cada e a verificação do
runtime passaram. Os limites aceitos 128/64 e recusados 129/65 estão cobertos;
os mutantes `>` para `>=` falham por assertion. O recibo
`output/fixtures/libipsec-final-scope-receipt.json` registra as cinco entradas
alteradas e sua estabilidade. A evidência das suítes não afetadas e da matriz
do produtor foi reutilizada; os caminhos de produção Rust/C e os patches não
mudaram entre essas duas execuções.

[PASS, empacotamento local] `target/vpnt-libipsec-checkpoint.app` foi produzido
com o binário do build integrado, conferido byte a byte. É um host local sem
instalação do componente. A UI não mudou desde o checkpoint anterior: seus
26 hashes registrados coincidem, assim como o diff de `ui`, `scripts/design`
e `DESIGN.md`; foram reutilizados os oito testes/114 assertions e os 81 tokens.
O gate de classes continua sem regras. Isso não prova um túnel real.

Recibos históricos: o runtime preparado atual foi gerado com o script no hash
`1163454a…`; a recuperação de configure mudou `scripts/macos/build-runtime.py`
para `23edb1fc…`, e o guard JSON estrito para `37e14397…`. O recibo do build não
foi refeito nesta etapa; o novo
`--verify-only` não prova paridade de fonte entre revisões do script. Nenhuma
instalação privilegiada, VPN real, tráfego, utun real, efeito de login ou CI
verde é afirmado aqui.

## Retenção do utun e canal herdado do produtor (checkpoint local)

Comandos locais, como usuário comum, sem daemon, VPN ou instalação:

```bash
RUST_TEST_THREADS=4 cargo test --locked --offline --no-default-features --lib helper::charon_channel
RUST_TEST_THREADS=4 cargo test --locked --offline --no-default-features --lib connection::ipsec::producer
cargo test --locked --offline --no-default-features --lib connection::macos::utun_observer
python3 scripts/macos/build-runtime.py --jobs 2
python3 scripts/macos/build-runtime.py --verify-only
python3 scripts/macos/check-utun-handoff.py
python3 scripts/macos/check-charon-config.py
```

- [PASS, fixture nativo local] O canal genérico tem sete testes com processos
  comuns e descritores de streams. O recebimento é de uso único, vinculado à
  alocação do `ManagedChild` original; PID sozinho não concede autoridade. A
  criação do par, a marcação de descritores recebidos e os spawns compartilham
  um guard, sem mantê-lo durante o poll ou a espera pelo filho.
- [PASS, fixture nativo local] A matriz recusa 254 direitos em um datagrama e
  prova, por EOF no peer, que todas as referências importadas foram fechadas.
  Os subprocessos de teste aguardam prontidão antes do `recvmsg` não bloqueante;
  os casos de truncamento e de falta de slots não dependem da ordem do scheduler.
  `EMSGSIZE` permanece erro recuperável sem descritores instalados; layout
  truncado ou inconsistente encerra o importador com `_exit(78)`, sem core.
- [PASS, fixture nativo local] O plugin fecha o canal imediatamente após o
  envio. Depois de um primeiro datagrama válido, `ECONNRESET` na segunda leitura
  significa fim do canal; o mesmo erro na primeira leitura continua sendo
  recusa. Dois datagramas seguidos de fechamento continuam recusados. O probe
  independente deste host confirmou mensagens enfileiradas antes do erro 54.
- [PASS, runtime privado preparado] O build local com os cinco patches terminou
  com exit 0 e insumos estáveis. Foram verificados dez arquivos; o TU compilado
  coincide com o candidato corrigido. O manifest deste build tem hash
  `0e2cb1cf004c7e34174886d81222052d55ab7e1d389f7dfbe8a4f2e521e5c2e7`.
  O mínimo macOS 26.0 continua metadado deste host, não um novo mínimo suportado.
  O recibo está em `output/fixtures/retained-runtime-receipt.json`.
- [PASS, consumidor C original em fixture] `check-utun-handoff.py` extrai o
  arquivo original do tarball verificado, aplica o patch canônico sem fuzz e
  compila o TU completo. Oito cenários e treze mutações passaram, com baseline
  e restauração. O fixture substitui o TUN por um objeto comum; não carrega
  plugins do charon. A falha de preparo anterior à inicialização libera apenas
  a estrutura já alocada, sem chamar `libipsec_deinit` antes de init; uma mutação
  reproduz essa regressão por assertion controlada. O checker usa os mesmos
  pré-requisitos de arquivo local no CI e no desenvolvimento, sem recibo privado.
- [PASS, fonte e fixture] O observador de recursos em espaço de usuário mantém
  separadas a ocupação anterior ao initiate e a ausência completa exigida no
  release. O contrato legado de `KernelClaims` continua completo. A fonte real
  do ledger ainda precisa registrar a admissão antes do prepare e mantê-la até
  a parada e a ausência verificada dos recursos; vetores injetados não provam
  esse ledger. Sete testes do adaptador e sete mutações foram executados em
  cópia privada, antes da integração final.
- [PASS, integração local] Fmt, clippy com `-D warnings`, build e as suítes
  completas passaram: 352 testes desktop e 336 core no host macOS, dois ignored
  em cada suíte. O teste ignorado do runtime preparado foi executado à parte
  e passou. São 26 testes do produtor, 11 do observador (incluindo dois casos
  sintéticos da correlação) e sete do canal. O take recusa objeto comum, é de
  uso único e respeita prazo/cancelamento inclusive com o mapa ativo ocupado.
  Cancelar o handoff fica latched; cancelar apenas a espera posterior por VICI
  preserva a tentativa já admitida. A parada é confirmada antes de soltar o pin.
- [PASS, limpeza em fixture] O teste de retire usa um stream cujo peer fica no
  pai: o filho mantém a referência original até sair e o helper deve fechar a
  sua após o reap. EOF comprova o encerramento das duas referências; a antiga
  asserção racy por `F_GETFD` foi removida. A mutação que mantém o pin é recusada
  por essa assertion observável, sem reduzir o número de threads.
- [PASS, parser original] Dois renderers com caminhos distintos passaram no
  parser original com `charon.plugins.kernel-libipsec.vpnt_retain_utun`.
  Renomear apenas a seção para `libipsec` nos mesmos dois documentos produz
  exit 1 e uma assertion do parser. O fixture textual sozinho não é a prova.
- [PASS, mutações e pacote] As matrizes completas do produtor (32 mutações)
  e do controle (61) passaram com baseline/restauração. Os dois gates Python
  de recuperação/build-inputs passaram com sete testes cada. O pacote local
  `target/vpnt-retained-checkpoint.app` contém o binário byte a byte do build;
  é um host sem instalar o componente. O recibo
  `output/fixtures/retained-integration-receipt.json` registra 14 passos verdes
  e 371 insumos estáveis. A UI/design permaneceu inalterada em 33 insumos;
  foram reutilizados os checks de UI válidos do checkpoint anterior.
- [NOT RUN, utun real] A admissão de um utun real permanece sem prova. Uma
  interface observada é uma amostra; a referência retida fixa o socket, sem
  conceder autoridade de rota/VIP. Fixtures e comparações sintéticas não
  substituem o consumidor privilegiado real.
- [NOT RUN, CI remoto] Foi preparado um job `runtime-handoff` macOS separado
  para construir o runtime e executar o consumidor C. A configuração local não
  equivale a execução ou aprovação remota.
- [NOT RUN, VPN real] Não foram executados charon/utun reais, instalação
  privilegiada, políticas IPsec de socket, rotas/VIP, tráfego de túnel ou teste
  de coexistência. O Driver IPsec, o ledger real e a proteção do transporte UDP
  permanecem pendentes. Nenhuma VPN real pode ser declarada conectada com esta
  evidência.

### Fixture VICI ociosa (correção posterior ao checkpoint)

- [PASS, fixture nativa] Removido o timeout de leitura de 200 ms da fixture
  do produtor. Um cliente válido pode ficar ocioso por 350 ms e ainda receber
  a resposta `version`; o listener e a observação de EOF são multiplexados.
  O comportamento antigo falhou nessa regressão na cópia diagnóstica.
- [PASS, escopo afetado] Formatação, clippy de todos os targets/features com
  `-D warnings`, 27 testes do produtor e as 32 mutações passaram no estado
  final. Recibo: `output/fixtures/fixture-idle-scope-receipt.json`, quatro
  passos verdes com fonte estável. Revisão independente da delta concluída.
- [PASS, evidência reutilizada] Somente a fixture C e o teste de regressão
  mudaram desde `6acbad9`. Código de produção, runtime, UI, controle, parser e
  pacote conservaram seus insumos; os 14 passos do checkpoint são reutilizados.
  As suítes completas anteriores continuam sendo 352 desktop e 336 core,
  com dois ignorados em cada; não foram reexecutadas nesta correção.
- [Limite da fixture] Há um cliente por vez; uma mensagem parcial pode bloquear
  a leitura. Os testes cobertos enviam a mensagem completa. Isso não altera o
  protocolo ou os prazos do produtor real.
- [NOT RUN, VPN real] Esta correção não executa túnel, instalação privilegiada,
  política IPsec, configuração de VIP/rotas ou tráfego real.
