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
  hint-bg: "#4a4a4a"
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
  panel-min-height: "480px"
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
  icon-spinner: "14px"
  icon-help: "12px"
  hint-max-width: "200px"
  border-width: "1px"
  focus-width: "2px"
x-opacity:
  dim-opacity: "0.45"
  hover-brightness: "1.08"
x-motion:
  spinner-duration: "1s"
darkColors:
  hint-bg: "#383838"
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
    colors.hint-bg: { selector: ":root", var: "--hint-bg" }
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
    x-layout.panel-min-height: { selector: ":root", var: "--panel-min-height" }
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
    x-layout.icon-spinner: { selector: ":root", var: "--icon-spinner" }
    x-layout.icon-help: { selector: ":root", var: "--icon-help" }
    x-layout.hint-max-width: { selector: ":root", var: "--hint-max-width" }
    x-layout.border-width: { selector: ":root", var: "--border-width" }
    x-layout.focus-width: { selector: ":root", var: "--focus-width" }
    x-opacity.dim-opacity: { selector: ":root", var: "--dim-opacity" }
    x-opacity.hover-brightness: { selector: ":root", var: "--hover-brightness" }
    x-motion.spinner-duration: { selector: ":root", var: "--spinner-duration" }
    darkColors.hint-bg: { selector: ".dark", var: "--hint-bg" }
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

Espaçamento, dimensões e posicionamento seguem os tokens; o conteúdo deve permanecer
legível e as ações acessíveis mesmo em telas menores.

[Detalhes de layout](design/layout.md)

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

Controles compartilhados mantêm nomes acessíveis, foco visível e acesso por teclado.
O estado do interruptor vem do snapshot autoritativo, sem atualização otimista.

[Detalhes dos componentes](design/components.md)

### Avisos fecháveis

Os avisos de `dropped`, `credentials_rejected`, `gateway_timeout` e
`missing_program`, e o erro de comando no topo, têm botão X. O estado e o log
continuam acessíveis. Avisos de `cleanup_unconfirmed`, `unresponsive`, helper,
componente e diálogos permanecem visíveis.

## Do's and Don'ts

Preservar o fluxo aprovado, os tokens e os catálogos de texto da interface.
Manter a demonstração identificada e exigir teste de tráfego para conexão real.

[Regras completas](design/dos-and-donts.md)
