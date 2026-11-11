# Validação do protótipo

Este contrato cobre a proposta estática em `vpnt.fig` e seu gerador. A validação
de conexões, privilégios e chaveiro será definida junto da implementação do app.

## Arquivo e estrutura

Na raiz do repositório, com Node.js, Bun e OpenPencil CLI disponíveis:

```bash
node --check design/build-proto.mjs
bunx @open-pencil/cli info vpnt.fig --json
bunx @open-pencil/cli lint vpnt.fig --json
```

Critérios:

- Sintaxe do gerador válida.
- Dez páginas com os nomes descritos no README, sem página padrão vazia.
- 84 componentes principais, 42 por tema, e instâncias vinculadas nas telas.
- Os 14 estados do cartão presentes nos temas claro e escuro.
- Lint recomendado com zero erros, avisos e informações.

## Revisão visual

Abra `vpnt.fig` no OpenPencil e confira as dez páginas. Para revisar uma página
renderizada a partir do arquivo salvo:

```bash
bunx @open-pencil/cli export vpnt.fig --page '1 · Painel' -f png -o /tmp/vpnt-panel.png
```

Confira legibilidade, cortes, sobreposição e ações visíveis em painel, cartões,
preferências, perfis, primeiro uso, log, diálogos, ícone e menu. O painel deve
mostrar o aviso de túnel sem resposta com Reconectar e Desligar.

## Componentes e reprodução

Use uma cópia descartável para estes testes:

1. Abra as dez páginas da cópia para carregá-las no editor.
2. Altere uma propriedade visual dos componentes principais e confira a
   atualização das instâncias, inclusive nas outras páginas. Os textos
   personalizados, como nome da VPN e rótulo dos botões, devem ser preservados.
3. Feche a cópia sem salvar.
4. Crie um documento vazio separado e execute o gerador conforme o README.
5. Salve o resultado em outro caminho e rode `info`, `lint` e a revisão visual
   nesse arquivo. Ele deve atender aos mesmos critérios do arquivo versionado.

Mudanças deliberadas de telas ou estados devem atualizar o protótipo, o gerador
e os critérios afetados em conjunto.

## Limites

Não há typechecker nem suíte de testes do app nesta fase. Renderização, lint e
propagação de componentes não provam conexões de VPN ou transições funcionais;
os controles do protótipo são estáticos.
