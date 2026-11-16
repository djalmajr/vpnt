# Variante Linux Omarchy

Aplica-se somente quando o shell define `data-desktop="omarchy"` em `<html>`; `data-omarchy-mode` escolhe os fallbacks claro ou escuro e o esquema nativo. As propriedades do shell são consumidas por `var()`, portanto alterações ao vivo propagam sem recarga. Outros desktops conservam o contrato existente.

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

Separador usa 25% do foreground sobre o fundo do popup; controles normais usam 4%, e hover de controles e menu 8%, para distinguir camadas mantendo a paleta. Aviso, erro e informação usam respectivamente 15% de amarelo, vermelho e azul sobre o fundo do popup, preservando a cor sem competir com o texto. O scrim usa 50% do fundo escuro com transparência. Essas misturas acompanham o tema; se uma propriedade faltar, suas cadeias usam o fallback da tabela.

## Geometria e animação

O painel não tem borda no CSS: ele é uma janela do Hyprland, que já desenha a borda com a cor do tema e `general:border_size` (hoje 2 px). Decisão do Djalma, 16/11/2026: a borda própria era redundante. `--omarchy-border-width` e `--omarchy-popup-border` continuam injetadas, sem uso no contorno externo. O raio externo usa `--omarchy-radius` (fallback 0 px). Os raios internos `sm`, `control`, `card`, `panel` e `popover`, além do switch, seu botão e abas, seguem o mesmo raio; isso evita cantos residuais quando o tema é reto. O posicionador nativo calcula o respiro como metade de `general:gaps_out` do Hyprland: hoje 5 px abaixo da barra e nas laterais; não é margem CSS. A entrada usa fade pela regra de janela `popin 100%`.

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

Tipografia, espaçamento interno, dimensões, estados, acessibilidade, conteúdo e comportamento seguem `DESIGN.md`. A exceção específica Omarchy é o mapa de cores e a geometria descritos acima; o visual de macOS e outros Linux não é alterado.
