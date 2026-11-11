# vpnt

Ícone de bandeja (tray) para ligar, desligar e acompanhar VPNs no macOS, no
Windows e no Linux, com a mesma interface nos três.

> Estado: protótipo visual para validação. Ainda não há versão utilizável.
> A primeira implementação será para macOS; Windows e Linux ficam para depois.

## Proposta

- **Host em Rust**, um binário único, com `tao` (laço de eventos), `tray-icon`
  (ícone na barra ou bandeja) e `wry` (webview nativa do sistema: WKWebView,
  WebView2 ou WebKitGTK).
- **Interface web única** no popover, igual nos três sistemas.
- **Perfis de VPN** configuráveis. Os primeiros tipos previstos são IPsec IKEv2
  (strongSwan) e SSL VPN da Fortinet (openfortivpn).
- **Estado real do túnel**: além de saber se o cliente está rodando, o vpnt
  testa se o tráfego passa. Um túnel que parece ligado mas não responde
  aparece como "sem resposta", com a opção de reconectar.
- **Segredos só no chaveiro do sistema**, nunca em arquivo nem em argumento de
  linha de comando.

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
