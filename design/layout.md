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
dentro de si mesmo em vez de esconder as primeiras ações. Por indicação do Djalma
em 2026-11-14, o menu aberto num painel de um único cartão não pode ficar cortado
nem rolar havendo espaço físico na tela: enquanto o menu está aberto, o painel
pede ao host a altura que comporta o conteúdo intrínseco do menu (`scrollHeight`
mais bordas, mesmo quando o menu está limitado), mais `sideOffset`,
`collisionPadding` e a distância do gatilho à borda inferior do painel, e o
rodapé desce para essa borda; o Radix então coloca todas as ações acima do
gatilho. Ao fechar, navegar ou desmontar, a reserva é liberada e a altura
anterior volta, nunca abaixo de `panel-min-height`. A reserva é temporária, nunca vai além de `panel-max-height`
(720 px) e o host ainda limita à tela; só quando a tela não comporta o menu ele
rola. Não é aberta exceção de CSS para o menu: o dimensionamento fica em
`ui/src/panelSizing.ts`. O `sideOffset` de 6 px
da referência é uma exceção documentada: o deslocamento é calculado em JS, então
o valor fica no componente e não vira token CSS. Por indicação do Djalma, o
interruptor é mais compacto que o clássico: 24 por 14 px, com botão de 10 px e
1 px de recuo. Ícones grandes e linhas de preferências conservam 28 px,
independentes da largura do interruptor.

Os separadores conservam `border-width` mesmo quando o menu está limitado:
não encolhem no flex. A medida intrínseca usada para aumentar o popover deve
incluir suas linhas; comprimi-las a zero subestima a altura necessária.

Por correção do Djalma em 2026-11-13, o popover abre na tela do clique, como no ai-usagebar: âncora em pontos Cocoa, origens negativas preservadas e limites da área visível ao abrir ou redimensionar; a escala da janela anterior não participa. A colocação nativa usa 0 pt abaixo da barra, 8 pt nas laterais e 24 pt acima da borda inferior, sem novos valores CSS; reabrir recaptura a âncora e remoção da tela recorre à primária.

### Conflicting visual priorities

Por correção do Djalma em 2026-11-14, o popover abre já na altura predefinida
(`panel-min-height`, 480 px) e a conserva entre telas, para não haver
deslocamento de layout; o rodapé fica na borda inferior. A janela nativa nasce
com a mesma medida. Conteúdo mais alto cresce até `panel-max-height`; tela mais
baixa limita a janela e o painel rola.
O pedido ao host soma a estrutura fixa ao `scrollHeight` de panel-content,
independentemente do viewport atual; mudanças internas também são observadas.

Legibilidade e acesso às ações prevalecem sobre altura fixa. O painel mantém
320 px quando há espaço; em viewport menor, ocupa a largura disponível. Em
viewport fisicamente baixo, o menu rola e continua alcançável; nenhuma ação é
cortada. Havendo espaço na tela, a altura do painel cresce para o menu (ver
Layout), em vez de rolar.

