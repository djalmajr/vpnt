# Variante Linux Omarchy

O tema aplica-se somente quando o shell define `data-desktop="omarchy"` em `<html>`; `data-omarchy-mode` escolhe os fallbacks claro ou escuro e o esquema nativo. As propriedades do shell são consumidas por `var()`, portanto alterações ao vivo propagam sem recarga. Outros desktops conservam o contrato existente. A exceção de layout abaixo é independente do tema.

## Exceção de layout no Linux

Vale para **todo** shell com `data-platform="linux"`, com ou sem `data-desktop="omarchy"`; este último continua regendo só as cores e a geometria do tema. Em 2026-11-19, o app real no Omarchy mostrou uma segunda barra de rolagem na janela, além da rolagem de navegação em `.panel-content`. O recorte adotado é só:

```css
:root[data-platform="linux"] { overflow: hidden; }
```

Sem `height: 100%` e sem regra no `body`: `html` e `body` permanecem em fluxo natural. A navegação rola em `.panel-content`, acima do rodapé, que não faz parte da superfície rolável. Os portais do menu Options e da dica acessível moram no `body` e usam `position: fixed` (Radix Popper com `strategy: "fixed"` e `help-tooltip`), então não dependem de um contexto de rolagem na raiz; o limite final é o recorte físico da janela do host. Ao abrir o menu, a janela recebe uma reserva temporária de altura, liberada ao fechar; se faltar altura física, o conteúdo rola em `.panel-content` e o rodapé continua visível. Nenhum token novo entra nesta exceção. A prova nativa com o app instalado continua pendente; veja os passos manuais no relatório da rodada.

Por decisão do Djalma em 2026-11-19, o teto de 720 px não se aplica ao Linux: o
mesmo token existente é reescrito sob `:root[data-platform="linux"]` para
`--panel-max-height: 100vh`, e `ui/src/panelSizing.ts` não limita o pedido ao
teto quando o marcador está presente. A UI pede a altura natural do conteúdo,
com piso em `panel-min-height` (480 px) e sem teto de 720; o host limita só pelo
piso de 180 px e pela altura disponível calculada em `frame_with_gap` (altura do
monitor menos áreas reservadas, margem e gap). A reserva temporária do menu
continua valendo. Quando o conteúdo passa da altura disponível, só o miolo rola:
o cabeçalho é sticky e o rodapé fica fora da superfície rolável em todos os
hosts. No macOS nada muda: o teto de 720 px continua.

## Mapa de cores

`<original>` representa o último fallback da coluna à direita (claro / escuro). Valores iguais em ambos são repetidos. Os nomes são os tokens de cor de `styles.css`.

| Token | Propriedade e cadeia | Fallback final claro / escuro |
| --- | --- | --- |
| `--surface` | `var(--omarchy-popup-background, var(--omarchy-background, <original>))` | `#ffffff` / `#1e1e1e` |
| `--card` | `var(--omarchy-lighter-background, var(--omarchy-background, <original>))` | `#f2f2f2` / `#292929` |
| `--menu` | `var(--omarchy-popup-background, var(--omarchy-background, <original>))` | `#ffffff` / `#2b2b2b` |
| `--separator` | `color-mix(in srgb, var(--omarchy-foreground, var(--omarchy-popup-text, <original>)) 25%, var(--omarchy-popup-background, var(--omarchy-background, <original>)))` | `rgba(0, 0, 0, 0.1)` / `rgba(255, 255, 255, 0.1)` |
| `--text` | `var(--omarchy-popup-text, var(--omarchy-foreground, <original>))` | `rgba(0, 0, 0, 0.85)` / `rgba(255, 255, 255, 0.85)` |
| `--secondary` | `var(--omarchy-foreground, var(--omarchy-popup-text, <original>))` | `rgba(0, 0, 0, 0.5)` / `rgba(255, 255, 255, 0.55)` |
| `--control` | `color-mix(in srgb, var(--omarchy-foreground, var(--omarchy-popup-text, <original>)) 4%, var(--omarchy-popup-background, var(--omarchy-background, <original>)))` | `rgba(0, 0, 0, 0.06)` / `rgba(255, 255, 255, 0.08)` |
| `--control-hover` | `color-mix(in srgb, var(--omarchy-foreground, var(--omarchy-popup-text, <original>)) 8%, var(--omarchy-popup-background, var(--omarchy-background, <original>)))` | `rgba(0, 0, 0, 0.1)` / `rgba(255, 255, 255, 0.14)` |
| `--menu-hover` | `color-mix(in srgb, var(--omarchy-foreground, var(--omarchy-popup-text, <original>)) 8%, var(--omarchy-popup-background, var(--omarchy-background, <original>)))` | `rgba(0, 0, 0, 0.06)` / `rgba(255, 255, 255, 0.1)` |
| `--field` | `var(--omarchy-dark-background, var(--omarchy-background, <original>))` | `#ffffff` / `#1e1e1e` |
| `--switch-off` | `var(--omarchy-muted, var(--omarchy-selection, <original>))` | `#d9d9d9` / `#454545` |
| `--blue` | `var(--omarchy-blue, var(--omarchy-accent, <original>))` | `#007aff` / `#0a84ff` |
| `--action` | `var(--omarchy-accent, var(--omarchy-blue, <original>))` | `#0066d6` / `#0a69d1` |
| `--link` | `var(--omarchy-blue, var(--omarchy-accent, <original>))` | `#0062cc` / `#5cadff` |
| `--green` | `var(--omarchy-green, var(--omarchy-accent, <original>))` | `#34c759` / `#30d158` |
| `--orange` | `var(--omarchy-orange, var(--omarchy-yellow, <original>))` | `#ff9500` / `#ff9f0a` |
| `--orange-text` | `var(--omarchy-orange, var(--omarchy-yellow, <original>))` | `#8f4c00` / `#ffb340` |
| `--red` | `var(--omarchy-red, var(--omarchy-accent, <original>))` | `#ff3b30` / `#ff453a` |
| `--red-text` | `var(--omarchy-red, var(--omarchy-accent, <original>))` | `#b8221a` / `#ff8f87` |
| `--red-fill` | `var(--omarchy-red, var(--omarchy-accent, <original>))` | `#c92a20` / `#c92a20` |
| `--gray` | `var(--omarchy-muted, var(--omarchy-foreground, <original>))` | `#a3a3a3` / `#7a7a7a` |
| `--warn-bg` | `color-mix(in srgb, var(--omarchy-yellow, var(--omarchy-foreground, <original>)) 15%, var(--omarchy-popup-background, var(--omarchy-background, <original>)))` | `#fff1d6` / `#3b2c12` |
| `--warn-fg` | `var(--omarchy-yellow, var(--omarchy-foreground, <original>))` | `#7a4a00` / `#ffc266` |
| `--error-bg` | `color-mix(in srgb, var(--omarchy-red, var(--omarchy-foreground, <original>)) 15%, var(--omarchy-popup-background, var(--omarchy-background, <original>)))` | `#ffe5e3` / `#3e1f1c` |
| `--error-fg` | `var(--omarchy-red, var(--omarchy-foreground, <original>))` | `#a8201a` / `#ff9a91` |
| `--info-bg` | `color-mix(in srgb, var(--omarchy-blue, var(--omarchy-foreground, <original>)) 15%, var(--omarchy-popup-background, var(--omarchy-background, <original>)))` | `#e3f0ff` / `#14283d` |
| `--info-fg` | `var(--omarchy-blue, var(--omarchy-foreground, <original>))` | `#00529e` / `#7cbcff` |
| `--white` | `var(--omarchy-dark-background, var(--omarchy-background, <original>))` | `#ffffff` / `#ffffff` |
| `--scrim` | `color-mix(in srgb, var(--omarchy-dark-background, var(--omarchy-background, <original>)) 50%, transparent)` | `rgb(0 0 0 / 24%)` / `rgb(0 0 0 / 24%)` |
| `--hint-bg` | `var(--omarchy-lighter-background, var(--omarchy-background, <original>))` | `#4a4a4a` / `#383838` |

## Misturas

Separador usa 25% do foreground sobre o fundo do popup; controles normais usam 4%, e hover de controles e menu 8%, para distinguir camadas mantendo a paleta. Aviso, erro e informação usam respectivamente 15% de amarelo, vermelho e azul sobre o fundo do popup, preservando a cor sem competir com o texto. O scrim usa 50% do fundo escuro com transparência. Essas misturas acompanham o tema; se uma propriedade faltar, suas cadeias usam o fallback da tabela. O `::placeholder` de `input` e `textarea` usa 70% de `--text` sobre `--field`: o exemplo tem contraste menor com o fundo do campo que o valor digitado (mais apagado, não necessariamente mais claro), e fica em 4,5:1 ou mais nas paletas padrão e na do Omarchy de referência, sem trocar `--text` nem `--secondary`. Essa mistura vive em `styles.css` e vale para todos os hosts, inclusive o macOS.

## Geometria e animação

O painel não tem borda no CSS: ele é uma janela do Hyprland, que já desenha a borda com a cor do tema e `general:border_size` (hoje 2 px). Decisão do Djalma, 16/11/2026: a borda própria era redundante. `--omarchy-border-width` e `--omarchy-popup-border` continuam injetadas, sem uso no contorno externo. O raio externo usa `--omarchy-radius` (fallback 0 px). Os raios internos `sm`, `control`, `card`, `panel` e `popover`, além do switch, seu botão e abas, seguem o mesmo raio; isso evita cantos residuais quando o tema é reto. O posicionador nativo calcula o respiro como metade de `general:gaps_out` do Hyprland, hoje 5 px abaixo da barra e nas laterais, e soma `general:border_size`, porque o Hyprland desenha a borda da janela por fora da geometria, enquanto o cartão do Omarchy a desenha por dentro. Assim o espaço visível entre a barra e a borda fica igual ao dos popovers do Omarchy (hoje a janela fica a 7 px). Não é margem CSS. A entrada usa fade pela regra de janela `popin 100%`. Num workspace flutuante, o Omarchy carrega o plugin hyprbars e desenha uma barra de título de 30 px acima de cada janela. Acima do painel, essa barra ficava atrás da barra do topo e aparecia como uma faixa no respiro. Por isso, a regra de abertura pede `hyprbars:no_bar` enquanto o plugin está carregado. Quando a altura muda com o painel visível, quem redimensiona e reposiciona a janela é o Hyprland. Antes disso, o GTK solta os limites de tamanho. O Hyprland mantém o centro de uma janela flutuante que muda o próprio tamanho; se o GTK seguisse preso à altura antiga, recusaria o pedido e o painel cresceria em torno do centro, subindo para trás da barra.

## Contraste no tema atual

Calculado pela luminância relativa sRGB e razão `(L_clara + 0,05) / (L_escura + 0,05)`, incluindo misturas sRGB de 15%. Fundo do popup `#1a1b26`, texto `#a9b1d6`, cartão `#24283b` e texto em botões preenchidos `#13141c`.

| Par texto / fundo | Razão |
| --- | ---: |
| Texto / painel | 8,10:1 |
| Texto / cartão ou dica | 6,90:1 |
| Secundário / painel | 8,10:1 |
| Link / painel | 6,79:1 |
| Aviso / aviso | 6,36:1 |
| Erro / erro | 5,11:1 |
| Informação / informação | 5,25:1 |
| Texto / botão primário | 7,29:1 |
| Texto / botão destrutivo preenchido | 6,93:1 |

Esses pares atingem 4,5:1 no tema atual. Outros temas e combinações não foram medidos; o shell fornece cores arbitrárias e não garante contraste.

## Contrato preservado

Tipografia, espaçamento interno, dimensões, estados, acessibilidade, conteúdo e comportamento seguem `DESIGN.md`. A exceção específica Omarchy é o mapa de cores e a geometria descritos acima. O recorte da raiz vale só com `data-platform="linux"`. A cor do `::placeholder` é a única regra compartilhada com o macOS e os outros Linux; fora isso, o visual deles não é alterado.
