# vpnt

Ícone de bandeja (tray) para ligar, desligar e acompanhar VPNs no macOS, no
Windows e no Linux, com a mesma interface nos três.

> Protótipo visual aprovado. O host macOS e a interface bilíngue estão em
> implementação, com um modo de demonstração explícito. A camada de VPN real
> ainda não está disponível. Windows e Linux ficam para depois.

## Proposta

- **Host em Rust**, um binário único, com `tao` (laço de eventos), `tray-icon`
  (ícone na barra ou bandeja) e `wry` (webview nativa do sistema: WKWebView,
  WebView2 ou WebKitGTK).
- **Interface web única** no popover, igual nos três sistemas.
- **Idiomas da interface:** português do Brasil (`pt-BR`) e inglês dos Estados
  Unidos (`en-US`). O protótipo visual permanece em português.
- **Perfis de VPN** configuráveis. Os primeiros tipos previstos são IPsec IKEv2
  (strongSwan) e SSL VPN da Fortinet (openfortivpn).
- **Estado real do túnel**: além de saber se o cliente está rodando, o vpnt
  testa se o tráfego passa. Um túnel que parece ligado mas não responde
  aparece como "sem resposta", com a opção de reconectar.
- **Segredos só no chaveiro do sistema**, nunca em arquivo nem em argumento de
  linha de comando.

## Desenvolvimento no macOS

Requer Rust 1.99, Bun 1.4.4, Xcode Command Line Tools e Python 3.11 ou superior
para empacotar. Compile a interface antes do Rust: seus arquivos entram no binário.

```bash
cd ui
bun install --frozen-lockfile
bun run build
cd ..
cargo build --locked
cargo run -- --demo --show
```

O modo `--demo` oferece perfis fictícios, transições e seleção dos 14 estados.
Os cadastros e as senhas de demonstração ficam apenas na memória; não use dados
reais nele. Idioma e tema persistem como preferências locais da interface.
Sem `--demo`, um worker separado atende a UI, consulta o helper e usa o chaveiro
do usuário. O cliente preparado verifica o executável fixo e invoca somente
`sudo -n -- /Library/PrivilegedHelperTools/dev.vpnt.helper runtime`, com canal
duplex anônimo herdado em FD 0. Nenhum helper ou sudoers é instalado pelo app
atual: sem esses pré-requisitos ele apresenta o primeiro uso. Cadastro/remoção
de perfis usa o canal administrativo separado descrito abaixo. Instalação e
remoção do helper ainda estão em desenvolvimento.
Essa ligação está compilada e testada com um subprocesso fictício, sem execução
de sudo, elevação ou conexão VPN real.

Para exercitar a mesma UI e a ponte de comandos no navegador:

```bash
cargo run -- --demo-server 4178
```

Abra `http://127.0.0.1:4178`. Esse servidor só atende o modo de demonstração
no loopback e não constrói um backend de VPN real.

Para criar um pacote de desenvolvimento local, sem instalar:

```bash
python3 scripts/macos/package-app.py
python3 scripts/macos/build-askpass.py
open target/vpnt.app --args --demo --show
```

O pacote é gerado em `target/vpnt.app`, sem assinatura nem notarização. Use
`--replace` para substituir um pacote anterior do vpnt nesse destino. Isso não
instala programas de VPN, componentes privilegiados ou regras do sudoers.
O askpass é produzido separadamente em `target/debug/vpnt-askpass`, sem instalar
ou executar sudo. O build só verifica sua recusa a um pai não autorizado.
Os checks e os limites de evidência estão em [`VALIDATION.md`](VALIDATION.md).

Os clientes VPN também podem ser preparados em um runtime separado, ainda sem
instalação. Esse build usa Python 3.12 ou superior, o compilador do Xcode e as
instalações locais de `openssl@4` e GNU `m4`:

```bash
python3 scripts/macos/build-runtime.py
```

O script compila strongSwan 6.1.0 com plugins incorporados e openfortivpn 1.24.1
a partir de fontes verificadas, com bibliotecas em `target/vpnt-runtime`.
pkgconf, autoconf e automake são compilados só em `target/build-tools`. As fontes
baixadas têm SHA-256 fixado; os programas do Homebrew permanecem intactos.
O manifest registra hashes, licenças, destino futuro e a versão mínima de macOS
exigida pelos binários produzidos. Esse runtime ainda não faz parte do `.app`
de demonstração nem é instalado pelo script.

O payload de instalação também pode ser preparado e inspecionado localmente:

```bash
cargo build --locked --bins
python3 scripts/macos/build-askpass.py
python3 scripts/macos/prepare-installation.py
```

O preparador gera `target/vpnt-installation/<sha256>`, com helper, pinentry,
supervisor PPP, askpass, inspetor, runtime e política sudoers. O manifesto vincula
versão, destinatário numérico e hashes. O inspetor Rust confere o conjunto inteiro,
os binários Mach-O, as dependências e a política antes de admitir o payload.
O destinatário padrão é o usuário atual; `--uid` prepara outro UID local no
intervalo aceito de 501 a 2147483647, sem conceder acesso. Repetir a preparação
reutiliza somente um build idêntico e íntegro; uma cópia corrompida é recusada.

A política preparada usa digest dos executáveis e argumentos exatos: runtime
sem senha, administração/remoção com senha, sem PTY nem registro de IO. Sua
sintaxe é validada com `visudo` somente no arquivo de fixture. Isso não comprova
os privilégios efetivos da máquina. Os modos disponíveis de `vpnt-install` são
`inspect` e `policy`, ambos apenas de leitura e recusados sob root. A ativação
transacional, a remoção e o pacote `.pkg` permanecem em desenvolvimento.

O build aplica [`charon-private-pid.patch`](scripts/macos/patches/charon-private-pid.patch)
à fonte verificada do strongSwan. Ele acrescenta `charon.vpnt_pid_file` para que
o helper possa usar um PID privado por perfil. O manifest registra o hash do
patch, e a admissão Rust exige essa mesma versão. Configuração, socket, credenciais
e recursos de rede por perfil ainda dependem da integração do driver.

O patch [`openfortivpn-no-routes.patch`](scripts/macos/patches/openfortivpn-no-routes.patch)
impede a remoção corretiva de uma rota quando `--no-routes` está ativo. O driver
SSL usa rotas e DNS desativados no cliente para que o controlador cuide dos
recursos que autorizou. A camada de processo está implementada; propriedade da
interface e probe nativo são consumidos pelo controlador preparado em Rust,
ligados em código ao helper e ao broker normal. O vínculo PPP combina registros do `configd`, processos de pai/filho
verificados e observação de saída pelo kernel. O probe exige interface e origem
explícitas, com ping e fallback TCP. Os fixtures usam loopback e interfaces
sintéticas; não provam PPP ou tráfego VPN. Aplicação/cleanup de recursos reais,
helper instalado e prova da integração completa continuam pendentes.

O transporte SSL recebe um vínculo de saída selecionado por leitura nativa da
rota, ligado ao ID, hostname e porta do perfil. O patch
[`openfortivpn-bound-transport.patch`](scripts/macos/patches/openfortivpn-bound-transport.patch)
fixa o IP escolhido, preserva o hostname de TLS e exige `IP_BOUND_IF` junto ao
bind da origem no macOS. Não há fallback sem vínculo. A prova atual usa o
consumidor C real em loopback e consultas somente de leitura; não demonstra
tráfego Fortinet nem coexistência com rotas de um túnel real.

O controle de rotas tem um coordenador de leases por UID, perfil e geração,
com compartilhamento, conflitos exatos, extensão após PPP e rollback. O plano
de túnel completo usa pares `/1` e bloqueia a família IP sem suporte. A leitura
nativa consulta a tabela e faz somente `RTM_GET`; os testes de aplicação e
remoção usam um kernel simulado. O lock global do controlador tem testes de
exclusão real entre processos e validação de inode/permissões/ACL; a fábrica
produtiva exige root e um arquivo persistente preparado pela instalação.
O controlador e o entrypoint preparado do helper já o consomem. Há um vínculo PPP por descritor
e um escritor separado de `ADD`, ambos preparados para exigir root, o lock e
a interface comprovada. Seus testes usam ioctls simulados e um consumidor C
da ABI Darwin em sockets Unix privados: nenhuma retenção PPP ou escrita real
de rota foi executada. O backend SSL já liga esses componentes ao coordenador,
autoriza UID/perfil/geração, relê a chave exata da rota e retém recibos incertos.
Só fecha sua referência após os dois processos saírem e só termina o cleanup
após conferir redes planejadas, empréstimos e rotas implícitas dos endereços.
O backend prepara uma UTUN própria para a família IP ausente no túnel completo,
desativa entrada/saída antes de atribuir um endereço privado e usa rotas blackhole.
Falhas parciais conservam metadados de cleanup e impedem nova admissão até a
remoção observada. A liberação fecha só os descritores próprios.
Os fluxos do backend usam tabela e ciclo de vida simulados; os pedidos UTUN e
de endereço têm fixtures e consumidor C independente do SDK. Watches de
processos e leitura nativa têm evidência separada. Execução privilegiada,
bloqueio de tráfego real e ligação instalada ao helper/UI continuam pendentes;
detalhes em `VALIDATION.md`.

O controlador SSL usa um worker por perfil, gerações crescentes, cancelamento
compartilhado, leases e revalidação após o probe. Reconectar aguarda o cleanup
anterior; fechar o canal cancela os workers e aguarda também a fila de recursos
de cadastros que falharam. Estados de worker são mantidos em memória de forma
limitada; saída lenta não bloqueia o cancelamento. Os testes passam pelo codec
real, coordenador e processos de teste próprios, com rede e PPP simuladas.
O adaptador root está compilado e ligado ao broker normal, mas não foi executado
como root nem validado por uma conexão da UI.
O canal herdado já observa o cliente, o supervisor e o filho PPP desde as
barreiras anteriores ao exec, conservando os três watches originais. Falhas
após spawn mantêm o driver e seus recibos. Se houve permissão antes de descobrir
a interface, o cleanup compara interfaces/rotas com a observação anterior:
recursos novos sem atribuição segura mantêm pendência, sem remoção por palpite.

O executável `vpnt-helper` aceita somente `runtime` ou `admin`, exige UID real e
efetivo root e um socketpair anônimo herdado em FD 0. O UID do peer vem do kernel;
SUDO_UID e campos de UID do IPC não selecionam o storage. Somente usuários com
storage root já preparado podem entrar. O modo runtime chama o controlador SSL
sob o lock global; admin lê um documento e EOF antes de salvar/remover perfil.
A administração disputa uma reserva persistente por perfil, sem tomar o lock
de rede: um perfil em uso é recusado e os demais podem ser editados. O controlador
conserva a reserva até comprovar cleanup, inclusive se o worker falhar.
Antes de iniciar, relê o perfil sob essa reserva. Snapshot atualiza os metadados
inativos sem interromper os ativos; IPsec aparece no catálogo, com seu driver
ainda pendente. Leitura e escrita rodam fora do controlador, com filas e
prazos limitados; EOF/sinais encerram admissões e aguardam cleanup. Há testes de
socket, arquivos/flock reais de fixture e controlador com rede simulada.
O binário ainda não está instalado ou no .app. Installer/sudoers e
comportamento após elevação continuam pendentes; o modo runtime deve ser a
única autorização sem senha da futura regra restrita.

O broker exige snapshot inicial compatível antes de consultar os indicadores
de segredos; lê credenciais somente ao conectar/reconectar por ação explícita.
Só eventos da geração atual do helper podem informar conexão. Accepted não
significa túnel conectado, e perda do canal não significa cleanup concluído.
O cliente fecha o socket e aguarda seu filho próprio sem matá-lo; a falha chega
à UI antes dessa espera. A retomada preparada espera esse filho e tenta um canal
novo com intervalo crescente de um a 30 segundos. Exige novo snapshot e uma
nova ação para conectar, sem repetir operações ou recarregar credenciais.
O lock do helper continua exigido: saída do launcher não prova cleanup de rede.
Salvar/remover perfis usa outro worker e um único comando fixo:
`sudo -A -k -- /Library/PrivilegedHelperTools/dev.vpnt.helper admin`.
O cliente valida helper e askpass em paths root fixos. O adaptador gráfico
AppKit usa os mesmos catálogos pt-BR/en-US da UI; a senha da conta só vai para
o pipe privado do sudo. O protocolo 2 exige AdminReady compatível antes de enviar
um documento com EOF; pedidos expirados não são repetidos após autorização tardia.
A UI continua atendendo comandos de outros perfis. Sucesso exige saída do filho
próprio e snapshot correlacionado no runtime. Só depois da remoção confirmada
são apagados os segredos; falha no chaveiro é reportada como resultado parcial.
Nenhuma dessas provas usa autenticação real. `-k` ignora o cache quando a política
exige senha; a futura regra administrativa deve exigir PASSWD. PTY e registro
de IO ainda precisam ser configurados e validados na instalação.
A prova nativa atual do chaveiro usa uma base descartável
com credenciais fictícias enviadas ao peer de teste, sem usar VPN pessoal.

O runtime inclui uma cópia dos certificados públicos de
`SystemRootCertificates.keychain`, conferida e incluída no inventário. A exportação
pode precisar de acesso ao Security.framework fora do sandbox; uma lista vazia
interrompe o build. Chaveiros pessoais não são usados para esse bundle.

O binário auxiliar `vpnt-pinentry` também é compilado, mas ainda não é
instalado ou incluído no `.app`. Ele recebe a senha por um socket anônimo
herdado do filho SSL que o helper iniciou, sem servidor de senhas no filesystem.
A camada de processo SSL e o caminho compilado do helper já consomem esse
transporte. A instalação e a prova privilegiada completa pela UI seguem pendentes.

O binário separado `vpnt-pppd` prepara a supervisão do filho PPP. Ele aceita
somente a lista fixa de argumentos, exige root e um canal herdado em FD 4,
autoriza supervisor e filho antes do exec, conserva o PTY e espera o filho
próprio antes de emitir seu recibo final. Não encaminha os canais de senha e
controle ao programa PPP. Os testes executam forks, sinais e watches reais,
com um payload fictício no lugar de `/usr/sbin/pppd`. Esse componente
já está ligado ao runtime e ao controlador preparados, mas não está instalado.
O receptor autentica UID, programa, pai e identidade nativa antes de conceder
cada permissão; EOF ou recibo final não substituem os watches de saída.
O runtime recompilado exige o patch e o hash desse caminho fixo. A admissão
recusa opções, hooks ou segredos globais que poderiam interferir na sessão,
incluindo postoptions, opções por TTY e arquivos do home root. Não os lê ou
altera. O comando interno desativa ACSP/DHCP, proxy ARP e persistência.
A execução privilegiada e a prova de remoção dos recursos reais continuam
pendentes. Não foi executado o pppd do sistema.

## Proposta visual

O arquivo [`vpnt.fig`](vpnt.fig), na raiz do projeto, abre no OpenPencil.
O protótipo está organizado em dez páginas nomeadas:

| Página | Conteúdo |
|---|---|
| 0 · Componentes claros | 42 componentes principais do tema claro |
| 0 · Componentes escuros | 42 componentes principais do tema escuro |
| 1 · Painel | 11 situações do popover, incluindo falha, ausência de rede e primeiro cadastro |
| 2 · Estados do cartão | 14 estados de uma VPN e a ação esperada em cada um |
| 3 · Preferências e perfis | Preferências, cadastro, perfis IPsec e SSL VPN, erros e sobre |
| 4 · Primeiro uso | Instalação do componente de administrador, falha e atualização |
| 5 · Log e diálogos | Log cheio, vazio e carregando; senhas e confirmações |
| 6 · Ícone e menu | Cinco estados do ícone em barras clara e escura e menu de contexto |
| 7 · Tema escuro | Painel e seleção das demais telas no tema escuro |
| 8 · Cartão no tema escuro | Os mesmos 14 estados do cartão no tema escuro |

As telas usam instâncias dos componentes das páginas 0. Os nomes, endereços e
usuários apresentados são fictícios. O arquivo é uma proposta estática: não
estabelece conexões de VPN.

A fonte do protótipo é [`design/build-proto.mjs`](design/build-proto.mjs).
Para gerar um novo documento, com o OpenPencil aberto em um documento vazio e
ativo:

```bash
bun design/build-proto.mjs
bunx @open-pencil/cli documents save --path vpnt.fig
```

O gerador substitui o conteúdo das páginas que ele cria no documento ativo.
Para validar o arquivo salvo:

```bash
bunx @open-pencil/cli info vpnt.fig --json
bunx @open-pencil/cli lint vpnt.fig --json
```

Os critérios de revisão visual, componentes e reprodução estão em
[`VALIDATION.md`](VALIDATION.md).

`proto.fig`, `design/proto.html` e `design/proto.png` são a proposta inicial,
anterior ao protótipo paginado; não são a fonte de `vpnt.fig`.

## Licença

[MIT](LICENSE).
