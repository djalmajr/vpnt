## Components

Por indicação do Djalma em 2026-11-17, o cartão de limpeza não confirmada apresenta o aviso e a ação “Conferir de novo”, com loader durante a solicitação.

Por indicação do Djalma em 2026-11-16, com uma sessão anterior terminando, o painel avisa com loader e não oferece instalar.

Por indicação do Djalma em 2026-11-15, só o interruptor do cartão liga ou
desliga, emitindo connect/disconnect explícitos conforme o snapshot. É um
botão com aria-pressed e nome acessível formado por nome do perfil e estado
traduzido. Sem resposta, o interruptor desliga; Reconectar continua no aviso.
Com senha pendente, o interruptor abre o diálogo de segredos, sem aviso extra.
Durante conexão e reconexão, o interruptor fica indisponível e só Cancelar
cancela; limpeza e estados desabilitados também bloqueiam o interruptor.
O estado continua vindo do snapshot autoritativo, sem atualização otimista.

O corpo não é clicável: só o icon-button com chevron à direita do
interruptor abre o perfil, com nome traduzido “Detalhes de {name}”.
Não há botões aninhados nem segundo foco no corpo. Quando há Notice de aviso
ou erro, a linha de status não aparece; o nome acessível do interruptor ainda
contém o estado. Sem Notice, a linha mostra o ponto na cor do estado, na mesma
caixa e centro; durante conexão e reconexão, o spinner fica dentro do botão
Cancelar, antes do rótulo, e há um único spinner por cartão.
Cancelar é um botão real com foco próprio, menu-hover, raio de controle e
recuo horizontal space-xs.

A seção Segredos do perfil conserva uma linha de status por segredo e usa
um único botão no cabeçalho: Trocar quando algum segredo aplicável existe,
Informar quando nenhum existe. O mesmo diálogo atende IPsec (PSK e senha) e
SSL (senha).

Preferências, perfis, log e confirmações ocupam o mesmo popover. Controles têm
nome acessível, foco visível e caminho por teclado. Diálogos usam dialog nativo,
com foco contido e Escape para cancelar. As confirmações de remover o
componente e o perfil mostram o Icon loader girando dentro do botão primário,
antes do rótulo, com o botão indisponível e `aria-busy`;
o texto de espera anunciado como status continua, sem spinner. O Cancelar
segue bloqueado porque a operação do helper não pode ser cancelada por ali.
O loader compartilhado tem trilha circular completa em `dim-opacity` e arco de
90° em `currentColor`, centrados em 12,12 no viewBox de 24. Sua caixa CSS mede
14 px (`icon-spinner`), não encolhe e gira pelo centro da borda; o botão usa
flex para manter ícone e texto alinhados. Respeita movimento reduzido.

O rodapé fica sempre visível na base do painel, inclusive em perfil e log,
fora de panel-content, a área rolável do conteúdo do painel. O flex reserva a
altura real do rodapé, sem sobrepor o conteúdo; a janela curta limita o painel ao viewport.
A versão usa font-control (12 px), o token pequeno existente. O menu conserva
seu portal e a reserva temporária de altura.
Voltar e as rotas do rodapé usam a mesma guarda de alterações pendentes do
perfil, inclusive na criação: confirmar descarte segue ao destino escolhido;
continuar editando preserva o formulário. Durante salvar, essas saídas ficam
indisponíveis. O perfil lembra a origem Home ou Preferências: Voltar, descarte
confirmado, salvar e remoção retornam à origem. A criação carrega a origem pela
escolha de tipo; sem origem, retorna à Home.

As quatro linhas não triviais das Preferências usam o componente compartilhado
`Help`: ícone de interrogação ao lado do rótulo, com tamanho `icon-help` de
12 px e cor `secondary`, como na referência ai-usagebar. A dica abre por
ponteiro e foco, fecha com Escape e usa o texto traduzido como nome acessível,
sem `title`. O portal no `body` acompanha rolagem e resize; o posicionamento
colide com o viewport com margem `space-md`, invertendo o lado quando preciso.
A largura máxima `hint-max-width` de 200 px e o fundo `hint-bg` vêm da
referência, pois não havia papéis equivalentes. O texto reutiliza `white` no
claro e `text` no escuro. Reutiliza texto de controle, raio pequeno, sombra
de menu e recuo `space-sm`/`space-md`.
A altura e a largura também respeitam o viewport menos duas margens; a dica
rola se não couber. Não há seta nem token de deslocamento adicional.

O menu de opções é um componente compartilhado (`Menu`, `MenuItem`,
`MenuSeparator`) sobre o mesmo primitivo Radix da referência
(`@radix-ui/react-dropdown-menu` 2.1.24, MIT): `Root` não modal, `Trigger` como
botão real com o rótulo traduzido e o ícone `down`, `Content` dentro de
`Portal`. O primitivo cuida de ancoragem viva, Escape e clique fora, navegação
por teclado, itens desabilitados, retorno de foco ao gatilho (exceto quando a
saída foi um clique fora) e limpeza; não há ARIA menu feito à mão, coordenada de
menu nem listeners globais. A medição de DOM é só de tamanho: o tamanho da janela
pedida ao host (conteúdo intrínseco do menu e distância do gatilho à borda do
painel); a posição do menu continua sendo do Radix. As linhas são `div` emitidas pelo primitivo e
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

Por indicação do Djalma em 2026-11-15, toda linha clicável com hover dentro
de grupos (perfis em Preferências, tipos na criação) preenche a linha inteira
até as bordas do grupo, com o raio do cartão acompanhando o contêiner nos
cantos da primeira e da última linha. O foco visível continua visível.

Por correção do Djalma em 2026-11-16, o acesso de administrador instalado
usa três colunas: título e versão na primeira linha, explicação na segunda,
e lixeira à direita centralizada verticalmente nas duas linhas; as demais
`Row` continuam como estão. O botão reutiliza `icon-button` com cor neutra do
tema e nome acessível e `title` traduzidos de Remover. O clique abre a
mesma confirmação de remoção; não há rótulo separado de remoção.
Por indicação do Djalma em 2026-11-16, Instalar e Atualizar agem em um clique
no aviso, no onboarding ou nas Preferências; a autorização é a do Instalador do
macOS. O botão mostra o loader no lugar até a confirmação do componente. Com
VPN ativa, desligando ou em limpeza, fica indisponível e pede para desligá-la.
Remover mantém a confirmação.

Por indicação do Djalma em 2026-11-16, o seletor de perfis do Log é um
controle segmentado, inclusive com um só perfil: trilho `control`, segmentos
por conteúdo, seleção elevada em `surface` e texto dos demais em `secondary`.
Mantém tablist e foco por teclado. Nomes que não cabem encolhem com reticências,
sem rolagem do trilho, e o nome inteiro fica no `title`.

Por indicação do Djalma em 2026-11-15, a ação de copiar o Log usa `icon-button`
à direita na mesma linha do nome do perfil ou das abas. O botão fica fora do
`tablist`, com nome acessível e `title` traduzidos; após copiar, o ícone muda
para check e o nome traduzido informa que foi copiado. Sem linhas de log, não
há ação de cópia. O rodapé conserva apenas o texto das últimas 60 linhas.
Reutiliza o alvo de clique dos ícones de cabeçalho (`control-height`), sem novos
tokens, e mantém o fluxo atual de cópia e de seleção das abas.

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
`exclamationmark.triangle.fill` indica erro, túnel sem resposta ou componente
não verificado. Por correção do Djalma em 2026-11-14, estados em andamento
(conectando, verificando, reconectando, desconectando) não são alerta: leem como
desligado e não fecham o cadeado.
Somente o snapshot autoritativo do helper instalado pode fechar o cadeado;
demonstração mantém o cadeado aberto. Preservar a proporção em 18 pt de altura.
