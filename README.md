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
Sem `--demo`, o app começa vazio e apresenta o primeiro uso; as operações de
VPN, chaveiro e instalação do helper ainda informam que estão em desenvolvimento.

Para exercitar a mesma UI e a ponte de comandos no navegador:

```bash
cargo run -- --demo-server 4178
```

Abra `http://127.0.0.1:4178`. Esse servidor só atende o modo de demonstração
no loopback e não constrói um backend de VPN real.

Para criar um pacote de desenvolvimento local, sem instalar:

```bash
python3 scripts/macos/package-app.py
open target/vpnt.app --args --demo --show
```

O pacote é gerado em `target/vpnt.app`, sem assinatura nem notarização. Use
`--replace` para substituir um pacote anterior do vpnt nesse destino. Isso não
instala programas de VPN, componentes privilegiados ou regras do sudoers.
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

O build aplica [`charon-private-pid.patch`](scripts/macos/patches/charon-private-pid.patch)
à fonte verificada do strongSwan. Ele acrescenta `charon.vpnt_pid_file` para que
o helper possa usar um PID privado por perfil. O manifest registra o hash do
patch, e a admissão Rust exige essa mesma versão. Configuração, socket, credenciais
e recursos de rede por perfil ainda dependem da integração do driver.

O patch [`openfortivpn-no-routes.patch`](scripts/macos/patches/openfortivpn-no-routes.patch)
impede a remoção corretiva de uma rota quando `--no-routes` está ativo. O driver
SSL usa rotas e DNS desativados no cliente para que o controlador cuide dos
recursos que autorizou. A camada de processo está implementada; propriedade da
interface e probe nativo têm módulos e testes locais, ainda sem ligação ao
controlador. O vínculo PPP combina registros do `configd`, processos de pai/filho
verificados e observação de saída pelo kernel. O probe exige interface e origem
explícitas, com ping e fallback TCP. Os fixtures usam loopback e interfaces
sintéticas; não provam PPP ou tráfego VPN. Leases/cleanup de rotas, helper e
integração real da UI continuam pendentes.

O runtime inclui uma cópia dos certificados públicos de
`SystemRootCertificates.keychain`, conferida e incluída no inventário. A exportação
pode precisar de acesso ao Security.framework fora do sandbox; uma lista vazia
interrompe o build. Chaveiros pessoais não são usados para esse bundle.

O binário auxiliar `vpnt-pinentry` também é compilado, mas ainda não é
instalado ou incluído no `.app`. Ele recebe a senha por um socket anônimo
herdado do filho SSL que o helper iniciou, sem servidor de senhas no filesystem.
A camada de processo SSL já consome esse transporte. A integração com o helper,
a instalação e a prova privilegiada seguem pendentes.

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
