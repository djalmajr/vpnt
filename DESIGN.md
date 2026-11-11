---
name: vpnt
description: Visual contract derived from the approved vpnt.fig prototype.
colors:
  surface: "#ffffff"
  card: "#f2f2f2"
  menu: "#ffffff"
  separator: "#e3e3e3"
  text: "#262626"
  secondary: "#636363"
  control: "#e3e3e3"
  control-surface: "#f0f0f0"
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
  font-family: "Inter, -apple-system, BlinkMacSystemFont, \"Segoe UI\", sans-serif"
  font-body: "12px"
  font-label: "13px"
  line-height: "16px"
spacing:
  xs: "4px"
  sm: "8px"
  md: "12px"
  lg: "16px"
rounded:
  sm: "4px"
  control: "6px"
  card: "8px"
  panel: "12px"
x-layout:
  panel-width: "320px"
  control-height: "24px"
  switch-width: "32px"
  switch-height: "20px"
  panel-max-height: "720px"
  field-label-width: "92px"
  dialog-width: "280px"
  dialog-inset: "24px"
  log-max-height: "480px"
  menu-width: "196px"
  menu-row-height: "28px"
  border-width: "1px"
  focus-width: "2px"
x-opacity:
  dim-opacity: "0.45"
  hover-brightness: "0.96"
x-motion:
  spinner-duration: "1s"
darkColors:
  surface: "#1e1e1e"
  card: "#292929"
  menu: "#2b2b2b"
  separator: "#3a3a3a"
  text: "#dedede"
  secondary: "#ababab"
  control: "#3b3b3b"
  control-surface: "#303030"
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
    colors.control-surface: { selector: ":root", var: "--control-surface" }
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
    typography.font-family: { selector: ":root", var: "--font-family" }
    typography.font-body: { selector: ":root", var: "--font-body" }
    typography.font-label: { selector: ":root", var: "--font-label" }
    typography.line-height: { selector: ":root", var: "--line-height" }
    spacing.xs: { selector: ":root", var: "--space-xs" }
    spacing.sm: { selector: ":root", var: "--space-sm" }
    spacing.md: { selector: ":root", var: "--space-md" }
    spacing.lg: { selector: ":root", var: "--space-lg" }
    rounded.sm: { selector: ":root", var: "--radius-sm" }
    rounded.control: { selector: ":root", var: "--radius-control" }
    rounded.card: { selector: ":root", var: "--radius-card" }
    rounded.panel: { selector: ":root", var: "--radius-panel" }
    x-layout.panel-width: { selector: ":root", var: "--panel-width" }
    x-layout.control-height: { selector: ":root", var: "--control-height" }
    x-layout.switch-width: { selector: ":root", var: "--switch-width" }
    x-layout.switch-height: { selector: ":root", var: "--switch-height" }
    x-opacity.dim-opacity: { selector: ":root", var: "--dim-opacity" }
    x-layout.panel-max-height: { selector: ":root", var: "--panel-max-height" }
    x-layout.field-label-width: { selector: ":root", var: "--field-label-width" }
    x-layout.dialog-width: { selector: ":root", var: "--dialog-width" }
    x-layout.dialog-inset: { selector: ":root", var: "--dialog-inset" }
    x-layout.log-max-height: { selector: ":root", var: "--log-max-height" }
    x-layout.menu-width: { selector: ":root", var: "--menu-width" }
    x-layout.menu-row-height: { selector: ":root", var: "--menu-row-height" }
    x-layout.border-width: { selector: ":root", var: "--border-width" }
    x-layout.focus-width: { selector: ":root", var: "--focus-width" }
    x-opacity.hover-brightness: { selector: ":root", var: "--hover-brightness" }
    colors.scrim: { selector: ":root", var: "--scrim" }
    x-motion.spinner-duration: { selector: ":root", var: "--spinner-duration" }
    darkColors.surface: { selector: ".dark", var: "--surface" }
    darkColors.card: { selector: ".dark", var: "--card" }
    darkColors.menu: { selector: ".dark", var: "--menu" }
    darkColors.separator: { selector: ".dark", var: "--separator" }
    darkColors.text: { selector: ".dark", var: "--text" }
    darkColors.secondary: { selector: ".dark", var: "--secondary" }
    darkColors.control: { selector: ".dark", var: "--control" }
    darkColors.control-surface: { selector: ".dark", var: "--control-surface" }
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
---

## Overview

O vpnt usa o tema clássico aprovado em `vpnt.fig`: superfície opaca, cartões
preenchidos e controles compactos. O painel tem 320 px e segue o tema do sistema
por padrão; claro e escuro são igualmente suportados.

## Colors

As cores de superfície, cartão, controle, estado e aviso vêm do protótipo.
Azul indica ação; verde só indica túnel verificado; laranja indica atenção ou
tráfego sem resposta; vermelho indica falha. Ícones e texto acompanham o estado,
sem depender apenas da cor. Botões com texto branco usam `action` ou `red-fill`.

## Typography

Texto de corpo tem 12 px; nomes e títulos usam 13 px; altura de linha de 16 px.
Os pesos permitidos são 400, 500 e 600. Inter é a referência do protótipo; as
fontes do sistema são fallback local. Nomes de perfis e rótulos podem quebrar
linha; traduções não devem ser cortadas para conservar uma altura fixa.

## Layout

Espaçamento de 4, 8, 12 e 16 px. Painel com 8 px de margem interna e 8 px entre
peças; cartões com 12 px de margem interna; controles com 24 px de altura.
O painel cresce com o conteúdo e rola até o limite da tela. Campos e seletores
encolhem dentro da largura disponível. Nenhum fluxo depende de hover.

### Conflicting visual priorities

Legibilidade e acesso às ações prevalecem sobre altura fixa. O painel mantém
320 px quando há espaço; em viewport menor, ocupa a largura disponível.

## Elevation & Depth

Superfícies preenchidas e separadores discretos. O app não usa vidro, gradientes
ou sombras de destaque. O scrim serve somente para o diálogo modal.

## Shapes

Raios de 4, 6, 8 e 12 px, conforme os tokens. Cartão usa 8 px; painel e diálogo,
12 px; controles, 6 px. O interruptor mantém 32 por 20 px.

## Components

O cartão inteiro oferece a ação principal. Durante conexão, clicar cancela.
Sem resposta oferece Reconectar como ação principal e Desligar separadamente.
Preferências, perfis, log e confirmações ocupam o mesmo popover. Controles têm
nome acessível, foco visível e caminho por teclado. Diálogos usam o elemento
nativo `dialog`, com foco contido e Escape para cancelar.

## Do's and Don'ts

- Preservar a estrutura e os estados do protótipo aprovado.
- Usar os catálogos pt-BR/en-US para todo texto funcional da interface.
- Manter o modo de demonstração explicitamente identificado.
- Usar tokens do contrato; registrar novas indicações visuais neste arquivo.
- Não simular conexão real por haver processo ou rota: exigir teste de tráfego.
- Percentuais e medidas de `sr-only` são estrutura de acessibilidade, não novos tokens visuais.
