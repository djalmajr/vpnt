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
  disponível, com rolagem interna e 8 px de borda; a rolagem só vale quando a
  tela não comporta o menu, pois a janela cresce temporariamente para ele.
- Não manter permanentemente a altura extra reservada para o menu, nem calcular
  a posição do menu: só o tamanho da janela é dimensionado, e a reserva é
  liberada ao fechar, navegar ou desmontar. A altura predefinida
  `panel-min-height` é o piso aprovado do painel e não é essa reserva.
- Não recortar a página inteira no macOS (`height: 100%` + `overflow: hidden`
  em `html`/`body`): o portal do menu vive no `body`, e o recorte final do
  popover é do host nativo, não do CSS. No Linux, a única exceção é
  `:root[data-platform="linux"] { overflow: hidden; }`, registrada em
  [design/linux-omarchy.md](linux-omarchy.md#exceção-de-layout-no-linux).
- Não trocar o `select` nativo por dropdown próprio, nem fixar a altura de
  cartões e linhas para igualar controles: só os controles de linha única usam os
  24 px de `control-height`.
- Não simular conexão real por haver processo ou rota: exigir teste de tráfego.
- Percentuais e medidas de `sr-only` são estrutura de acessibilidade, não novos tokens visuais.
