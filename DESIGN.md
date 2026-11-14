---
name: VPN Tray
description: Visual contract derived from the approved vpnt.fig flow and the classic ai-usagebar theme.
colors:
  surface: "#ffffff"
  card: "#f2f2f2"
  menu: "#ffffff"
  separator: "rgba(0, 0, 0, 0.1)"
  text: "rgba(0, 0, 0, 0.85)"
  secondary: "rgba(0, 0, 0, 0.5)"
  control: "rgba(0, 0, 0, 0.06)"
  control-hover: "rgba(0, 0, 0, 0.1)"
  menu-hover: "rgba(0, 0, 0, 0.06)"
  field: "#ffffff"
  switch-off: "#d9d9d9"
  blue: "#007aff"
  action: "#0066d6"
  link: "#0062cc"
  green: "#34c759"
  orange: "#ff9500"
  orange-text: "#8f4c00"
  red: "#ff3b30"
  red-text: "#b8221a"
  red-fill: "#c92a20"
  gray: "#a3a3a3"
  warn-bg: "#fff1d6"
  warn-fg: "#7a4a00"
  error-bg: "#ffe5e3"
  error-fg: "#a8201a"
  info-bg: "#e3f0ff"
  info-fg: "#00529e"
  white: "#ffffff"
  scrim: "rgb(0 0 0 / 24%)"
typography:
  font-family: '-apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif'
  font-body: "13px"
  font-label: "13px"
  font-control: "12px"
  line-height: "16px"
spacing:
  xs: "4px"
  sm: "8px"
  md: "12px"
  lg: "16px"
rounded:
  sm: "4px"
  control: "6px"
  card: "10px"
  panel: "12px"
  popover: "13px"
shadows:
  menu: "0 10px 15px -3px rgba(0, 0, 0, 0.1), 0 4px 6px -4px rgba(0, 0, 0, 0.1)"
x-layout:
  panel-width: "320px"
  control-height: "24px"
  control-x: "10px"
  switch-width: "24px"
  switch-height: "14px"
  switch-knob: "10px"
  switch-inset: "1px"
  panel-max-height: "720px"
  field-label-width: "92px"
  dialog-width: "280px"
  dialog-inset: "24px"
  log-max-height: "480px"
  menu-min-width: "184px"
  menu-pad: "5px"
  menu-item-x: "8px"
  menu-item-y: "5px"
  icon-menu: "15px"
  icon-inline: "13px"
  border-width: "1px"
  focus-width: "2px"
x-opacity:
  dim-opacity: "0.45"
  hover-brightness: "1.08"
x-motion:
  spinner-duration: "1s"
darkColors:
  surface: "#1e1e1e"
  card: "#292929"
  menu: "#2b2b2b"
  separator: "rgba(255, 255, 255, 0.1)"
  text: "rgba(255, 255, 255, 0.85)"
  secondary: "rgba(255, 255, 255, 0.55)"
  control: "rgba(255, 255, 255, 0.08)"
  control-hover: "rgba(255, 255, 255, 0.14)"
  menu-hover: "rgba(255, 255, 255, 0.1)"
  field: "#1e1e1e"
  switch-off: "#454545"
  blue: "#0a84ff"
  action: "#0a69d1"
  link: "#5cadff"
  green: "#30d158"
  orange: "#ff9f0a"
  orange-text: "#ffb340"
  red: "#ff453a"
  red-text: "#ff8f87"
  gray: "#7a7a7a"
  warn-bg: "#3b2c12"
  warn-fg: "#ffc266"
  error-bg: "#3e1f1c"
  error-fg: "#ff9a91"
  info-bg: "#14283d"
  info-fg: "#7cbcff"
darkShadows:
  menu: "0 10px 15px -3px rgba(0, 0, 0, 0.4), 0 4px 6px -4px rgba(0, 0, 0, 0.3)"
x-parity:
  include: ["ui/src"]
  exclude: []
  forbidden: []
  allowed: []
  cssFile: "ui/src/styles.css"
  cssVars:
    colors.surface: { selector: ":root", var: "--surface" }
    colors.card: { selector: ":root", var: "--card" }
    colors.menu: { selector: ":root", var: "--menu" }
    colors.separator: { selector: ":root", var: "--separator" }
    colors.text: { selector: ":root", var: "--text" }
    colors.secondary: { selector: ":root", var: "--secondary" }
    colors.control: { selector: ":root", var: "--control" }
    colors.control-hover: { selector: ":root", var: "--control-hover" }
    colors.menu-hover: { selector: ":root", var: "--menu-hover" }
    colors.field: { selector: ":root", var: "--field" }
    colors.switch-off: { selector: ":root", var: "--switch-off" }
    colors.blue: { selector: ":root", var: "--blue" }
    colors.action: { selector: ":root", var: "--action" }
    colors.link: { selector: ":root", var: "--link" }
    colors.green: { selector: ":root", var: "--green" }
    colors.orange: { selector: ":root", var: "--orange" }
    colors.orange-text: { selector: ":root", var: "--orange-text" }
    colors.red: { selector: ":root", var: "--red" }
    colors.red-text: { selector: ":root", var: "--red-text" }
    colors.red-fill: { selector: ":root", var: "--red-fill" }
    colors.gray: { selector: ":root", var: "--gray" }
    colors.warn-bg: { selector: ":root", var: "--warn-bg" }
    colors.warn-fg: { selector: ":root", var: "--warn-fg" }
    colors.error-bg: { selector: ":root", var: "--error-bg" }
    colors.error-fg: { selector: ":root", var: "--error-fg" }
    colors.info-bg: { selector: ":root", var: "--info-bg" }
    colors.info-fg: { selector: ":root", var: "--info-fg" }
    colors.white: { selector: ":root", var: "--white" }
    colors.scrim: { selector: ":root", var: "--scrim" }
    typography.font-family: { selector: ":root", var: "--font-family" }
    typography.font-body: { selector: ":root", var: "--font-body" }
    typography.font-label: { selector: ":root", var: "--font-label" }
    typography.font-control: { selector: ":root", var: "--font-control" }
    typography.line-height: { selector: ":root", var: "--line-height" }
    spacing.xs: { selector: ":root", var: "--space-xs" }
    spacing.sm: { selector: ":root", var: "--space-sm" }
    spacing.md: { selector: ":root", var: "--space-md" }
    spacing.lg: { selector: ":root", var: "--space-lg" }
    rounded.sm: { selector: ":root", var: "--radius-sm" }
    rounded.control: { selector: ":root", var: "--radius-control" }
    rounded.card: { selector: ":root", var: "--radius-card" }
    rounded.panel: { selector: ":root", var: "--radius-panel" }
    rounded.popover: { selector: ":root", var: "--radius-popover" }
    shadows.menu: { selector: ":root", var: "--shadow-menu" }
    x-layout.panel-width: { selector: ":root", var: "--panel-width" }
    x-layout.control-height: { selector: ":root", var: "--control-height" }
    x-layout.control-x: { selector: ":root", var: "--control-x" }
    x-layout.switch-width: { selector: ":root", var: "--switch-width" }
    x-layout.switch-height: { selector: ":root", var: "--switch-height" }
    x-layout.switch-knob: { selector: ":root", var: "--switch-knob" }
    x-layout.switch-inset: { selector: ":root", var: "--switch-inset" }
    x-layout.panel-max-height: { selector: ":root", var: "--panel-max-height" }
    x-layout.field-label-width: { selector: ":root", var: "--field-label-width" }
    x-layout.dialog-width: { selector: ":root", var: "--dialog-width" }
    x-layout.dialog-inset: { selector: ":root", var: "--dialog-inset" }
    x-layout.log-max-height: { selector: ":root", var: "--log-max-height" }
    x-layout.menu-min-width: { selector: ":root", var: "--menu-min-width" }
    x-layout.menu-pad: { selector: ":root", var: "--menu-pad" }
    x-layout.menu-item-x: { selector: ":root", var: "--menu-item-x" }
    x-layout.menu-item-y: { selector: ":root", var: "--menu-item-y" }
    x-layout.icon-menu: { selector: ":root", var: "--icon-menu" }
    x-layout.icon-inline: { selector: ":root", var: "--icon-inline" }
    x-layout.border-width: { selector: ":root", var: "--border-width" }
    x-layout.focus-width: { selector: ":root", var: "--focus-width" }
    x-opacity.dim-opacity: { selector: ":root", var: "--dim-opacity" }
    x-opacity.hover-brightness: { selector: ":root", var: "--hover-brightness" }
    x-motion.spinner-duration: { selector: ":root", var: "--spinner-duration" }
    darkColors.surface: { selector: ".dark", var: "--surface" }
    darkColors.card: { selector: ".dark", var: "--card" }
    darkColors.menu: { selector: ".dark", var: "--menu" }
    darkColors.separator: { selector: ".dark", var: "--separator" }
    darkColors.text: { selector: ".dark", var: "--text" }
    darkColors.secondary: { selector: ".dark", var: "--secondary" }
    darkColors.control: { selector: ".dark", var: "--control" }
    darkColors.control-hover: { selector: ".dark", var: "--control-hover" }
    darkColors.menu-hover: { selector: ".dark", var: "--menu-hover" }
    darkColors.field: { selector: ".dark", var: "--field" }
    darkColors.switch-off: { selector: ".dark", var: "--switch-off" }
    darkColors.blue: { selector: ".dark", var: "--blue" }
    darkColors.action: { selector: ".dark", var: "--action" }
    darkColors.link: { selector: ".dark", var: "--link" }
    darkColors.green: { selector: ".dark", var: "--green" }
    darkColors.orange: { selector: ".dark", var: "--orange" }
    darkColors.orange-text: { selector: ".dark", var: "--orange-text" }
    darkColors.red: { selector: ".dark", var: "--red" }
    darkColors.red-text: { selector: ".dark", var: "--red-text" }
    darkColors.gray: { selector: ".dark", var: "--gray" }
    darkColors.warn-bg: { selector: ".dark", var: "--warn-bg" }
    darkColors.warn-fg: { selector: ".dark", var: "--warn-fg" }
    darkColors.error-bg: { selector: ".dark", var: "--error-bg" }
    darkColors.error-fg: { selector: ".dark", var: "--error-fg" }
    darkColors.info-bg: { selector: ".dark", var: "--info-bg" }
    darkColors.info-fg: { selector: ".dark", var: "--info-fg" }
    darkShadows.menu: { selector: ".dark", var: "--shadow-menu" }
---

## Overview

O VPN Tray usa o tema clássico do ai-usagebar, aplicado por indicação explícita do
Djalma em 2026-11-13: superfícies opacas, cartões preenchidos, menu branco com
linha destacada em cinza e controles compactos. O fluxo continua sendo o de
`vpnt.fig` (referência aprovada); os valores de tema e espaçamento abaixo são os
do ai-usagebar (commit `4f9d73f2`, MIT/copyright 2026 AkitaOnRails) e
prevalecem sobre os valores antigos da figura onde houver conflito. O painel tem
320 px e segue o tema do sistema por padrão; claro e escuro são igualmente
suportados.

## Colors

Superfície, cartão, menu, controle e estado vêm do tema clássico. Rótulos usam
`text` (85% de opacidade) e `secondary` (50% no claro, 55% no escuro);
separadores usam 10% da cor oposta. `control` é o fundo padrão de botões e
seletores; `control-hover` é o realce de qualquer controle clicável; `menu-hover`
é o realce de linha de menu e de linha clicável dentro de cartão. Não há filtro
global de brilho no hover: cada controle declara o próprio preenchimento, e
linhas desabilitadas não realçam.

Azul indica ação; verde só indica túnel verificado; laranja indica atenção ou
tráfego sem resposta; vermelho indica falha. Ícones e texto acompanham o estado,
sem depender apenas da cor. Botões com texto branco usam `action` ou `red-fill`.
As cores semânticas de VPN sem papel equivalente no tema clássico (`switch-off`,
`field`, `link`, `orange-text`, `red-text`, avisos) permanecem para manter
contraste de erro e ação.

## Typography

Texto de corpo, nomes e rótulos de cartão usam 13 px, com altura de linha de
16 px. Controles — botões, gatilho do menu, campos e seletores — usam o texto de
controle de 12 px; linhas de menu continuam em 13 px, como as linhas de cartão.
A família é a pilha do sistema macOS (`-apple-system`, `BlinkMacSystemFont`,
`Segoe UI`); Inter saiu por indicação de 2026-11-13, junto com o tema clássico.
Os pesos permitidos são 400, 500 e 600. Nomes de perfis e rótulos podem quebrar
linha; traduções não devem ser cortadas para conservar uma altura fixa.

## Layout

Espaçamento de 4, 8, 12 e 16 px. Painel e cartões usam 8 px de margem interna e
8 px entre peças; controles têm 24 px de altura e 10 px de recuo horizontal
(`control-x`). O menu usa 184 px de largura mínima, 5 px de recuo, 8 px
horizontais e 5 px verticais por linha, ícone de 15 px e 8 px entre ícone e
texto. O painel cresce com o conteúdo e rola até o limite da tela. Campos e
seletores encolhem dentro da largura disponível. Nenhum fluxo depende de hover.

Por indicação do Djalma em 2026-11-13, todo controle padrão de linha única —
botão, campo de texto e seletor — mede a mesma altura de 24 px
(`control-height`), usa o texto de controle de 12 px e 10 px de recuo horizontal
(`control-x`); no seletor, o recuo direito cresce para caber o ícone e o
intervalo até ele. O seletor continua sendo o `select` nativo: `appearance: none`
remove só a seta do sistema, e o ícone `down` compartilhado, de 13 px
(`icon-inline`) e ancorado a 10 px do canto direito, ocupa o lugar dela — não há
dropdown próprio. A altura é declarada em `height`, não `min-height`, porque o
WebKit desenhava o seletor com 18 px apesar do mínimo; a largura continua vindo
do conteúdo e do espaço disponível. Cartões de VPN, linhas de perfil e linhas de
menu mantêm a altura do próprio conteúdo, para não cortar rótulo nem tradução.

O menu é ancorado ao próprio gatilho pelo primitivo Radix: abre acima dele
(`side="top"`), alinhado à borda final (`align="end"`), com 6 px entre gatilho e
menu e 8 px de margem de colisão em cada lado (`collisionPadding`). O primitivo
reposiciona em resize e rolagem, inverte o lado quando falta espaço acima e
nunca usa coordenadas fixas de tela. A altura máxima vem de
`--radix-dropdown-menu-content-available-height` e a largura é limitada ao
viewport menos 16 px (2 × `space-sm`); quando o conteúdo não cabe, o menu rola
dentro de si mesmo em vez de esconder as primeiras ações. O `sideOffset` de 6 px
da referência é uma exceção documentada: o deslocamento é calculado em JS, então
o valor fica no componente e não vira token CSS. Por indicação do Djalma, o
interruptor é mais compacto que o clássico: 24 por 14 px, com botão de 10 px e
1 px de recuo. Ícones grandes e linhas de preferências conservam 28 px,
independentes da largura do interruptor.

Por correção do Djalma em 2026-11-13, o popover abre na tela do clique, como no ai-usagebar: âncora em pontos Cocoa, origens negativas preservadas e limites da área visível ao abrir ou redimensionar; a escala da janela anterior não participa. A colocação nativa usa 0 pt abaixo da barra, 8 pt nas laterais e 24 pt acima da borda inferior, sem novos valores CSS; reabrir recaptura a âncora e remoção da tela recorre à primária.

### Conflicting visual priorities

Legibilidade e acesso às ações prevalecem sobre altura fixa. O painel mantém
320 px quando há espaço; em viewport menor, ocupa a largura disponível. Em
viewport baixo, o menu rola e continua alcançável; nenhuma ação é cortada.

## Elevation & Depth

Superfícies cheias e separadores discretos: o app não usa vidro nem gradientes
de fundo. A camada flutuante (menu de opções e diálogo) usa a sombra compartilhada
`shadows.menu`, conforme a correção de 2026-11-13; o scrim continua reservado ao
diálogo modal.

## Shapes

Raios de 4, 6, 10, 12 e 13 px, conforme os tokens. O popover externo usa 13 px
(`rounded.popover` → `--radius-popover`), o mesmo `window-radius` de 13 px da
referência ai-usagebar; cartões e menus usam 10 px; o diálogo continua em 12 px
(`rounded.panel`); controles e linhas de menu, 6 px. O recorte externo é do host
nativo: a janela é transparente e a camada AppKit é recortada em 13 pt contínuos,
então no CSS basta o raio do próprio painel sobre a raiz transparente — não há
`height: 100%`/`overflow: hidden` em `html`/`body`, que cortaria o portal do menu
no `body`. Por indicação do Djalma em 2026-11-13, os interruptores são mais
retangulares: usam borda de 1 px com `separator`, como os inputs, mas raio
externo de 3 px, calculado como `rounded.sm` menos a espessura da borda.
O botão interno acompanha o contorno com raio de 1 px, calculado descontando
borda e recuo do raio externo compartilhado (`--switch-radius`).
Usam 24 por 14 px, botão de 10 px e 1 px de recuo, tanto nos cartões quanto
nas preferências, em ambos os temas.

## Components

O cartão inteiro oferece a ação principal. Durante conexão, clicar cancela.
Sem resposta oferece Reconectar como ação principal e Desligar separadamente.
Preferências, perfis, log e confirmações ocupam o mesmo popover. Controles têm
nome acessível, foco visível e caminho por teclado. Diálogos usam o elemento
nativo `dialog`, com foco contido e Escape para cancelar.

O menu de opções é um componente compartilhado (`Menu`, `MenuItem`,
`MenuSeparator`) sobre o mesmo primitivo Radix da referência
(`@radix-ui/react-dropdown-menu` 2.1.24, MIT): `Root` não modal, `Trigger` como
botão real com o rótulo traduzido e o ícone `down`, `Content` dentro de
`Portal`. O primitivo cuida de ancoragem viva, Escape e clique fora, navegação
por teclado, itens desabilitados, retorno de foco ao gatilho (exceto quando a
saída foi um clique fora) e limpeza; não há ARIA menu feito à mão, medição de
DOM nem listeners globais. As linhas são `div` emitidas pelo primitivo e
estilizadas por `data-highlighted` (realce cinza no ponteiro e no teclado) e
`data-disabled` (não interativo, sem realce); o separador é a `div`
`role="separator"` do primitivo. Cada ação atual tem ícone do vocabulário
existente; nenhuma ação nova é criada.

Controles compartilhados seguem os papéis do ai-usagebar: texto de controle de
12 px, recuo horizontal de 10 px e preenchimento explícito no hover; o botão
primário e o de perigo preenchido recebem brilho 1.08 no hover
(`hover-brightness`), um token e não um valor solto.

O controle de seleção é o componente compartilhado `Select`, que embrulha um
`<select>` nativo real — mesmas props, valor controlado, `onChange`, `disabled`,
`aria-label` e opções — num `span.select-control` não interativo, sem tabstop
próprio. O ícone `down` compartilhado é `aria-hidden` e não captura ponteiro,
então clique, foco, teclado e o rótulo implícito de `field` continuam no
elemento nativo.

Por correção do Djalma em 2026-11-13, uma espera do Host não pode parecer
indisponibilidade permanente: `Toggle` e `Select` aceitam `busy`, que mantém o
bloqueio nativo (o elemento continua desabilitado de verdade e expõe
`aria-busy` enquanto durar) sem aplicar `dim-opacity` nem trocar a cor para
`secondary`. Só o `disabled` explícito e permanente usa a atenuação;
`disabled` junto com `busy` mantém a aparência permanente. Durante o `busy`, o
seletor conserva `control-height`, `control-x`, `font-control`, o raio de
controle e o ícone `down`; o interruptor conserva `switch-width`,
`switch-height`, `switch-knob`, `switch-inset` e o raio derivado. O único sinal
adicional é o cursor de progresso — sem texto novo no catálogo, spinner ou
mudança de layout. Nenhum valor otimista aparece: o estado marcado continua
vindo do snapshot autoritativo.

### Edição por teclado (menu Editar nativo)

Os atalhos padrão de edição (⌘Z, ⇧⌘Z, ⌘X, ⌘C, ⌘V, ⌘A) vêm do menu Editar nativo
do aplicativo (Desfazer, Refazer, Recortar, Copiar, Colar, Selecionar Tudo), que
envia os seletores padrão ao responder em foco, sem alvo explícito. A WebView e
seus campos de texto continuam sendo o responder; a UI não lê nem escreve a
área de transferência por JavaScript, não intercepta teclas e não ganha IPC ou
permissão nova. Os rótulos vêm do catálogo compartilhado pt-BR/en-US e seguem
o idioma já validado do host. Sem novos tokens nem alteração visual da UI.

### Ícone da barra de menus

Usar SF Symbols nativos como imagens de template, acompanhando a aparência da
barra: `lock.shield.fill` para IPsec conectado, `lock.fill` para SSL conectado,
`lock.square.stack.fill` para ambos e `lock.open` quando nenhum está conectado.
`exclamationmark.triangle.fill` indica estado incerto, transitório ou com erro.
Somente o snapshot autoritativo do helper instalado pode fechar o cadeado;
demonstração mantém o cadeado aberto. Preservar a proporção em 18 pt de altura.

## Do's and Don'ts

- Preservar a estrutura e os estados do fluxo aprovado em `vpnt.fig`.
- Usar os catálogos pt-BR/en-US para todo texto funcional da interface.
- Manter o modo de demonstração explicitamente identificado.
- Usar tokens do contrato; registrar novas indicações visuais neste arquivo.
- Menu e controles seguem o tema clássico do ai-usagebar: superfície opaca, realce
  de linha por preenchimento e sombra compartilhada na camada flutuante.
- Não trocar realce por filtro de brilho global, nem deixar linha de menu com
  fundo transparente no hover ou no foco por teclado.
- Não deixar o menu crescer além do viewport: largura e altura vêm do espaço
  disponível, com rolagem interna e 8 px de borda.
- Não recortar a página inteira (`height: 100%` + `overflow: hidden` em
  `html`/`body`): o portal do menu vive no `body`, e o recorte final do popover é
  do host nativo, não do CSS.
- Não trocar o `select` nativo por dropdown próprio, nem fixar a altura de
  cartões e linhas para igualar controles: só os controles de linha única usam os
  24 px de `control-height`.
- Não simular conexão real por haver processo ou rota: exigir teste de tráfego.
- Percentuais e medidas de `sr-only` são estrutura de acessibilidade, não novos tokens visuais.
