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
```

O gate de tokens compara as 81 entradas mapeadas em `DESIGN.md` com o CSS.
O gate de classes ainda não tem classes proibidas configuradas; sua execução
não representa cobertura de estilos. O teste de CSS rejeita ciclos diretos em
variáveis, que podem anular medidas mesmo quando os nomes coincidem.

O teste de HTTP executa um processo filho do servidor de demonstração e usa
somente loopback. Precisa de permissão de socket. Ele verifica origem/Host,
rejeição de JSON ambíguo, sobrevivência a UTF-8 inválido e uma resposta posterior
válida. Os testes de sessão exercitam tokens de geração, cancelamento, reconexão
e classificação de resultados sem subprocessos de VPN.

O CI em `.github/workflows/check.yml` repete os checks de macOS e do núcleo
portável em Linux. Preparar o workflow e executar checks locais não equivale
a uma execução verde no GitHub; esta exige envio e execução no serviço.

## Persistência, chaveiro e protocolo

Os módulos dessa camada ainda não estão ligados ao modo normal da UI nem a um
helper instalado. Para executar seus testes isolados no macOS:

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
nem é uma prova de ownership do kernel. Integração e execução privilegiada
ainda pendentes; nenhum lock real foi criado nesta máquina.

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
root do binário final. A ligação ao helper/driver completo continua pendente.

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

O segundo comando, no macOS, lê `NET_RT_DUMP2` e consulta somente `RTM_GET`.
As respostas de loopback são conferidas contra o índice de `lo0` obtido por
uma API independente. O codec trata alinhamento de quatro bytes, máscaras
compactas, escopo IPv6/KAME, limites e truncamento. O consumidor GET também é
exercitado por datagramas privados: PID/seq incorretos não podem satisfazer
outra consulta. Nenhum dado pessoal da tabela é impresso. São evidências de
leitura nativa e protocolo; não são provas de ADD/DELETE ou de tráfego VPN.

O terceiro comando exige macOS e usuário comum. Em cópia descartável de fonte
e build, executa baseline, mutações nomeadas e baseline restaurada; falhas de
compilação não contam como mutações detectadas. A mutação de opcode executa
**somente o teste puro do codec**, sem enviar o opcode alterado a um socket de
rotas. As outras consultas nativas permanecem GET. Cópia/build são removidos;
logs, comandos e hashes de fonte ficam em `output/fixtures/route-oracles/`.
São 20 mutações, incluindo remoção do vínculo de perfil da saída SSL,
aceitação indevida de DNS sem escopo para probe e retirada do flock, vínculo
de inode, ACL ou checagem de hardlink do controlador. As baselines nativas incluem
seleção de saída por `RTM_GET` de TEST-NET, sem abrir conexão para esse endereço.
Baseline e restauração também executam os cinco testes do lock. O processo
Python independente detecta a mutação que omite o flock; bookkeeping interno
não basta para satisfazer o teste.
O workflow macOS prepara essa mesma execução; CI remoto ainda precisa rodar.

Backend privilegiado de escrita, consumo do lock global, recibos de criação
reais e integração helper/UI continuam pendentes. O [delete de rotas no XNU](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/net/route.c)
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
