# Validação

Este contrato separa o protótipo estático, o host, os fluxos de demonstração
e a futura camada de VPN real. Nenhuma evidência de demonstração prova uma VPN.

## Código do app

Na raiz do repositório, após instalar as dependências da UI:

```bash
cd ui
bun run lint
bun run typecheck
bun test
bun run build
cd ..
bun scripts/design/check-tokens.ts
bun scripts/design/check-classes.ts
cargo fmt --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-targets --all-features
cargo test --locked --no-default-features
cargo build --locked
python3 scripts/macos/package-app.py --replace
```

O gate de tokens compara as 81 entradas mapeadas em `DESIGN.md` com o CSS.
O gate de classes ainda não tem classes proibidas configuradas; sua execução
não representa cobertura de estilos. O teste de CSS rejeita ciclos diretos em
variáveis, que podem anular medidas mesmo quando os nomes coincidem.

O teste de HTTP executa um processo filho do servidor de demonstração e usa
somente loopback. Precisa de permissão de socket. Ele verifica origem/Host,
rejeição de JSON ambíguo, sobrevivência a UTF-8 inválido e uma resposta posterior
válida. Os testes de sessão exercitam tokens de geração, cancelamento, reconexão
e classificação de resultados sem subprocessos de VPN.

O CI em `.github/workflows/check.yml` repete os checks de macOS e do núcleo
portável em Linux. Preparar o workflow e executar checks locais não equivale
a uma execução verde no GitHub; esta exige envio e execução no serviço.

## Persistência, chaveiro e protocolo

Os módulos dessa camada ainda não estão ligados ao modo normal da UI nem a um
helper instalado. Para executar seus testes isolados no macOS:

```bash
cargo test --locked --no-default-features --test storage --test profiles --test secrets --test keychain --test helper_protocol --test runtime_policy --test vici
```

Storage usa somente `output/fixtures/`, com proprietário do processo para o
fixture. Produção usa proprietário root e uma árvore fixa por UID. Verificar
persistência/remoção, atualizações concorrentes, diretórios e arquivos privados,
links, arquivo especial que não possa bloquear a leitura, limites e dados
inválidos. O teste sem privilégio não substitui a validação do helper instalado
contra arquivos de proprietários diferentes.

No macOS, os testes criam ACLs descartáveis: uma permissão de escrita deve ser
rejeitada no executável mesmo com modo `0555`, e uma permissão de leitura deve
ser rejeitada no perfil mesmo com modo `0600`. ACLs que apenas negam acesso nos
ancestrais permanecem válidas. Nenhuma ACL pessoal é modificada.

O teste nativo de chaveiro cria uma base descartável com dados fictícios. Usa
esse handle para salvar, ler, atualizar, bloquear/desbloquear e remover; verifica
ao final que o chaveiro padrão e a lista de busca permanecem iguais. Não imprime
a lista pessoal. Pode precisar de execução fora do sandbox para acessar
Security.framework; uma falha de criação no sandbox não deve ser reportada como
teste nativo aprovado. O teste de segredos cobre redigir Debug e validar os
valores na fronteira de entrada dos clientes.

O protocolo normal oferece snapshot, conectar, desligar e testar por ID de
perfil/geração. O canal administrativo é separado e exige EOF após um único
documento antes de retornar uma operação executável. Testar mensagens
fragmentadas, limites, versões incompatíveis, ações/campos desconhecidos e
tentativas de cruzar os canais. Esses testes de codec não provam elevação,
processos de VPN ou instalação de sudoers.

## Runtime privado dos clientes

```bash
python3 scripts/macos/build-runtime.py
python3 scripts/macos/build-runtime.py --verify-only
```

O build fica em `target/`, incluindo o pkgconf local e fontes verificadas por
SHA-256. O strongSwan é compilado com os plugins necessários incorporados; seu
PID padrão fica em um prefixo próprio. O patch versionado permite ao futuro
driver indicar um PID diferente por perfil em configuração privada. A fonte
é extraída novamente do arquivo verificado antes de cada build. O openfortivpn é copiado da versão local
declarada no README. Nenhum comando instala em `/Library` ou inicia túneis.

A verificação confere inventário/hashes, dependências Mach-O com prefixos
privados ou do sistema, assinaturas ad hoc e a versão mínima real do macOS.
Executa apenas `--version` sem privilégios, com bibliotecas da cópia de staging
e um arquivo de configuração fictício regular. O manifest não pode presumir
compatibilidade com um macOS anterior ao mínimo dos componentes.

O bundle de CAs contém somente certificados públicos exportados do chaveiro de
raízes do sistema. Exportação vazia ou inválida interrompe o build; o sandbox
pode retornar uma lista vazia sem erro. O bundle e o patch de PID integram a
verificação do manifest. Isso não prova que o driver já os utiliza.

Esses checks não provam carregamento dos plugins privilegiados, criação de SAs,
PPP, tráfego pelo túnel ou cleanup de rotas. O controle de filhos tem testes de
processos reais para ambiente limpo, TERM, KILL após prazo e reap; isso prova
saída do processo direto, enquanto cada driver ainda deve verificar seus recursos.

A admissão em Rust repete inventário, SHA-256, proprietário, permissões e ACLs,
rejeita links e verifica os comandos de carregamento Mach-O. Os fixtures incluem
binários sintéticos inválidos e dependências em caminhos mutáveis. Para aplicar
esse mesmo código ao artefato nativo preparado, execute separadamente:

```bash
cargo test --locked --no-default-features --test runtime_policy -- --ignored
```

O cliente VICI usa sockets Unix com verificação do UID remoto, buffers de valores
apagados ao sair do escopo e `Debug` sem os valores. Testes exercitam o formato
binário, respostas/eventos intercalados, truncamento, fechamento do peer e prazo
total durante mensagens fragmentadas. O teste de listener precisa de permissão
de socket local. Esses fixtures não iniciam charon nem provam controle de uma SA.

O codec de pinentry implementa a troca usada por openfortivpn 1.24.1, com limite
de comandos/linha, consulta única da senha e resposta de erro fixa. Não usa
`SETKEYINFO` ou o texto do prompt para selecionar credenciais. `PinentryChild`
passa um socket anônimo pelo descritor 3 ao filho que iniciou. O adaptador
verifica o UID remoto; o helper exige o PID do filho esperado e uma única
mensagem completa antes de entregar a senha. O canal expira em cinco segundos
e é revogado em cancelamento, saída ou Drop. Cada tentativa tem um socket
diferente; não existe endpoint de senhas no filesystem.

`vpnt-pinentry` não aceita argumentos nem override de UID/caminho: exige UID real
e efetivo root e usa o canal herdado. O teste roda como usuário comum com
adaptador de fixture e UID explícito; isso não substitui a instalação e o teste
root do binário final. A ligação ao helper/driver completo continua pendente.

```bash
cargo test --locked --no-default-features --test pinentry --test pinentry_channel --test profiles --test secrets
python3 scripts/macos/check-pinentry-consumer.py
```

O segundo comando compila o leitor C original de senha do openfortivpn a partir
de fonte com SHA-256 fixado e o exercita contra o codec Rust. Verifica valores
fictícios com espaços, `%`, `+`, UTF-8 e os limites de 256 bytes. Os 12 cenários
incluem PID incorreto, protocolo/pedido duplicado, UID remoto errado, rejeição
do binário final sem root, revogação, expiração e filhos concorrentes com
senhas diferentes; não iniciam o cliente VPN. O código C fica no fixture,
separado do app. Os testes de entrada
rejeitam usuário SSL acima de 64 bytes, senha SSL acima de 256 bytes e fingerprint
fora dos 64 dígitos hexadecimais. O protocolo inicial só valida a forma dos
segredos; o tipo do perfil root determina o limite efetivo do cliente.

## Fluxos de demonstração

Use `cargo run -- --demo-server 4178` e abra o endereço local do README.
Exercite pelos controles visíveis, nos dois idiomas e temas:

- Conectar e cancelar antes da conclusão; o resultado tardio não pode religar.
- Conectar, forçar "sem resposta", reconectar e desligar todas as VPNs.
- Editar, continuar editando após Voltar e descartar sem persistir alterações.
- Cadastrar/remover um perfil e enviar senhas fictícias; dados reais ficam fora
  do modo de demonstração. Porta de teste 22 deve ser rejeitada.
- Alterar idioma e tema, recarregar e conferir persistência e traduções.
- Navegar com teclado, usar setas/Home/End nas abas do log, cancelar diálogos
  com Escape e verificar foco visível/contido.
- Medir painel de 320 px, campos alinhados e ausência de corte ou overflow
  horizontal; testar também uma viewport menor e conteúdo com rolagem.

No host nativo, verifique separadamente ícone, abertura/fechamento pelo clique,
posicionamento, Escape, diálogo antes do painel, perda de foco e saída. Uma
janela criada, um processo ativo ou a UI em Chrome não provam esses comportamentos
em WKWebView. Se a captura ou automação nativa estiver bloqueada pelo macOS,
registre o limite em vez de declarar a revisão visual nativa aprovada.

## VPN real

Ainda pendente. Antes de declarar essa camada pronta, testar o consumidor real
de perfis/chaveiro/helper e os clientes strongSwan/openfortivpn. Exercitar conectar,
cancelar durante a conexão, reconectar, desligar e túnel sem tráfego. Confirmar
que só o teste pelo túnel permite exibir "conectada", sem depender apenas de PID,
porta pública ou rota. Preservar configurações existentes e impedir acesso a
segredos por arquivos, argumentos, logs ou snapshots de UI.

Instalação privilegiada e conexão com configurações reais exigem a autorização
específica aplicável. Fixtures e simulações devem ser identificadas como tais.

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

## Limites do protótipo

Renderização, lint e propagação de componentes não provam conexões de VPN ou
transições funcionais; os controles de `vpnt.fig` são estáticos.
