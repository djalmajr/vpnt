#!/usr/bin/env bun
// Gera o protótipo do vpnt no OpenPencil pelas mesmas ferramentas que o MCP do
// OpenPencil expõe (`openpencil tool call`).
//
// Uso, com o OpenPencil aberto num documento vazio:
//   bun design/build-proto.mjs
//   bunx @open-pencil/cli documents save --path vpnt.fig
//
// O que ele monta:
//   - "0 · Componentes claros" e "0 · Componentes escuros": os componentes
//     principais (interruptor, botão, seletor,
//     campo, cabeçalho, barra, rodapé, cartão de VPN em cada estado, ícone da
//     barra), nos temas claro e escuro. Mudar um deles muda todas as telas.
//   - Uma página por assunto, feita de instâncias desses componentes.
//
// Cores e medidas partem do tema "classic" do popover de referência (superfície
// opaca, cartões preenchidos sem contorno, controles de 24 px), ajustadas ao
// lint do OpenPencil: texto de 12 px ou mais, contraste AA, espaçamento em
// múltiplos de 4, raios 4/6/8/12 e no máximo 6 níveis de camadas.
// Nomes, endereços e usuários são fictícios de propósito.
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const COMPONENTS_PREFIX = "0 · Componentes";
const componentsPage = (t) => `${COMPONENTS_PREFIX} ${t.key === "Claro" ? "claros" : "escuros"}`;
const COL = 320;

// --- temas -------------------------------------------------------------------

const light = {
  key: "Claro",
  canvas: "#ECECEF",
  caption: "#4B5563",
  heading: "#111827",
  surface: "#FFFFFF",
  card: "#F2F2F2",
  menu: "#FFFFFF",
  sep: "#E3E3E3",
  l1: "#262626",
  l2: "#636363",
  control: "#E3E3E3", // preenchimento de controle sobre o cartão
  controlSurface: "#F0F0F0", // sobre a superfície
  field: "#FFFFFF",
  switchOff: "#D9D9D9",
  blue: "#007AFF", // interruptor, pontos e ícones
  action: "#0066D6", // fundo de botão com texto branco
  link: "#0062CC",
  green: "#34C759",
  orange: "#FF9500",
  orangeText: "#8F4C00",
  red: "#FF3B30",
  redText: "#B8221A",
  redFill: "#C92A20",
  gray: "#A3A3A3",
  warnBg: "#FFF1D6",
  warnFg: "#7A4A00",
  errBg: "#FFE5E3",
  errFg: "#A8201A",
  infoBg: "#E3F0FF",
  infoFg: "#00529E",
  bar: "#DADADD",
  barFg: "#1F1F1F",
};

const dark = {
  key: "Escuro",
  canvas: "#111113",
  caption: "#A7AEBB",
  heading: "#F3F4F6",
  surface: "#1E1E1E",
  card: "#292929",
  menu: "#2B2B2B",
  sep: "#3A3A3A",
  l1: "#DEDEDE",
  l2: "#ABABAB",
  control: "#3B3B3B",
  controlSurface: "#303030",
  field: "#1E1E1E",
  switchOff: "#454545",
  blue: "#0A84FF",
  action: "#0A69D1",
  link: "#5CADFF",
  green: "#30D158",
  orange: "#FF9F0A",
  orangeText: "#FFB340",
  red: "#FF453A",
  redText: "#FF8F87",
  redFill: "#C92A20",
  gray: "#7A7A7A",
  warnBg: "#3B2C12",
  warnFg: "#FFC266",
  errBg: "#3E1F1C",
  errFg: "#FF9A91",
  infoBg: "#14283D",
  infoFg: "#7CBCFF",
  bar: "#2A2A2C",
  barFg: "#F2F2F2",
};

// --- JSX ---------------------------------------------------------------------

const attrs = (o) =>
  Object.entries(o)
    .filter(([, v]) => v !== undefined && v !== false && v !== null)
    .map(([k, v]) => (typeof v === "number" ? `${k}={${v}}` : `${k}="${String(v).replace(/"/g, "'")}"`))
    .join(" ");

const F = (props, ...kids) => {
  const body = kids.flat(Infinity).filter(Boolean).join("");
  return body ? `<Frame ${attrs(props)}>${body}</Frame>` : `<Frame ${attrs(props)} />`;
};

// Todo texto leva altura de linha par, para centralizar sem meio pixel.
const T = (text, props = {}) => {
  const size = props.size || 12;
  const lineHeight = size >= 20 ? 32 : 16;
  return `<Text ${attrs({ name: text.slice(0, 48), size, lineHeight, ...props })}>${text}</Text>`;
};

const SHIELD =
  "M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z";
// Um caminho por ícone: assim o ícone é uma camada só.
const ICONS = {
  chevronLeft: "M15 18l-6-6 6-6",
  chevronRight: "M9 18l6-6-6-6",
  chevronDown: "M6 9l6 6 6-6",
  plus: "M12 5v14 M5 12h14",
  sliders: "M21 4h-7 M10 4H3 M21 12h-9 M8 12H3 M21 20h-5 M12 20H3 M14 2v4 M8 10v4 M16 18v4",
  loader: "M21 12a9 9 0 1 1-6.219-8.56",
  refresh: "M3 12a9 9 0 0 1 15-6.7L21 8 M21 3v5h-5 M21 12a9 9 0 0 1-15 6.7L3 16 M3 21v-5h5",
  shield: SHIELD,
  shieldCheck: `${SHIELD} M9 12l2 2 4-4`,
  shieldDots: `${SHIELD} M8 12h1.5 M11.25 12h1.5 M14.5 12h1.5`,
  shieldAlert: `${SHIELD} M12 7.5v4.5 M12 15v1.5`,
  shieldX: `${SHIELD} M9.5 9.5l5 5 M14.5 9.5l-5 5`,
};

const icon = (name, color, size = 16, width = 2) =>
  `<svg name="${name}" viewBox="0 0 24 24" size={${size}}><path d="${ICONS[name]}" stroke="${color}" strokeWidth={${width}} fill="none" /></svg>`;

// --- instâncias --------------------------------------------------------------

// Cada lote de desenho junta aqui as instâncias pedidas; o JSX leva um
// marcador `@i|n` que depois é trocado pela instância do componente.
let slots = [];
const I = (comp, opts = {}) => {
  slots.push({ comp, fill: !!opts.fill, text: opts.text || {} });
  return F({ name: `@i|${slots.length - 1}`, w: opts.fill ? "fill" : 8, h: 8 });
};

const cn = (t, name) => `${t.key}/${name}`;

const BUTTON_KINDS = {
  plain: "Botão/Padrão",
  primary: "Botão/Primário",
  danger: "Botão/Perigo",
  "danger-fill": "Botão/Perigo cheio",
  disabled: "Botão/Apagado",
};
const btn = (t, label, kind = "plain", surface = false, fill = false) =>
  I(cn(t, BUTTON_KINDS[kind] + (surface && (kind === "plain" || kind === "danger" || kind === "disabled") ? " na superfície" : "")), { text: { rótulo: label }, fill });

const toggle = (t, on, dim = false) => I(cn(t, `Interruptor/${on ? "Ligado" : "Desligado"}${dim ? " travado" : ""}`));
const picker = (t, label) => I(cn(t, "Seletor"), { text: { valor: label } });
const header = (t) => I(cn(t, "Cabeçalho"), { fill: true });
const topBar = (t, title, refresh = false) => I(cn(t, refresh ? "Barra de título/Com atualizar" : "Barra de título/Simples"), { fill: true, text: { título: title } });
const footer = (t, line2) => I(cn(t, line2 ? "Rodapé/Com estado" : "Rodapé/Simples"), { fill: true, text: line2 ? { estado: line2 } : {} });
const field = (t, label, value, variant = "Texto") => I(cn(t, `Campo/${variant}`), { fill: true, text: { rótulo: label, valor: value } });
const trayIcon = (t, state) => I(cn(t, `Ícone da barra/${state}`));

const IPSEC = "IPsec IKEv2 · 10.20.0.0/24";
const SSL = "SSL VPN · túnel completo";
const cluster = (t, state) => I(cn(t, `Cartão de VPN/${state}`), { fill: true });
const office = (t, state) => I(cn(t, `Cartão de VPN/${state}`), { fill: true, text: { nome: "Escritório", tipo: SSL } });

// --- peças que não viram componente --------------------------------------------

const dot = (color) => F({ name: "ponto", w: 8, h: 8, rounded: 4, bg: color });

const notice = (t, tone, message, buttons = []) => {
  const bg = { warn: t.warnBg, err: t.errBg, info: t.infoBg }[tone];
  const fg = { warn: t.warnFg, err: t.errFg, info: t.infoFg }[tone];
  return F(
    { name: `aviso ${tone}`, flex: "col", w: "fill", p: 8, gap: 8, rounded: 6, bg },
    T(message, { w: "fill", color: fg }),
    buttons.length ? F({ name: "ações", flex: "row", gap: 8 }, buttons) : null,
  );
};

const panelShell = (t, name, ...kids) => F({ name, flex: "col", w: COL, p: 8, gap: 8, rounded: 12, bg: t.surface, stroke: t.sep }, kids);
const panel = (t, name, cards, line2, banner = null) => panelShell(t, name, header(t), banner, cards, footer(t, line2));

const menu = (t, items) =>
  F(
    { name: "menu", flex: "col", w: 196, p: 4, rounded: 8, bg: t.menu, stroke: t.sep },
    items.map((it) =>
      it === "-"
        ? F({ name: "separador", flex: "col", w: "fill", py: 4 }, F({ name: "linha", w: "fill", h: 1, bg: t.sep }))
        : F(
            { name: `item ${it[0]}`, flex: "row", w: "fill", h: 28, px: 8, justify: "between", items: "center", rounded: 6 },
            T(it[0], { size: 13, color: it[2] === "disabled" ? t.l2 : t.l1 }),
            it[1] ? T(it[1], { color: t.l2 }) : null,
          ),
    ),
  );

const sectionTitle = (t, text) => F({ name: `seção ${text}`, flex: "row", w: "fill", px: 8, pt: 4 }, T(text, { weight: 600, color: t.l2 }));
const noteLine = (t, text) => F({ name: "nota", flex: "row", w: "fill", px: 8 }, T(text, { w: "fill", color: t.l2 }));

const row = (t, label, control, sub = null) =>
  F(
    { name: `linha ${label}`, flex: "row", w: "fill", minH: 32, gap: 8, justify: "between", items: "center" },
    F({ name: "rótulo", flex: "col" }, T(label, { size: 13, color: t.l1 }), sub ? T(sub, { color: t.l2 }) : null),
    control,
  );

const group = (t, ...rows) => F({ name: "grupo", flex: "col", w: "fill", px: 12, py: 8, gap: 8, rounded: 8, bg: t.card }, rows);
const fieldNote = (t, text, error = false) => T(text, { w: "fill", color: error ? t.redText : t.l2 });

const secretRow = (t, label, stored) =>
  F(
    { name: `segredo ${label}`, flex: "row", w: "fill", minH: 32, gap: 8, justify: "between", items: "center" },
    F({ name: "rótulo", flex: "col" }, T(label, { color: t.l1 }), T(stored ? "Guardada no chaveiro" : "Não informada", { color: stored ? t.l2 : t.orangeText })),
    btn(t, stored ? "Trocar" : "Informar"),
  );

const dialog = (t, name, title, text, body, buttons) =>
  F(
    { name, flex: "col", w: 280, p: 16, gap: 12, rounded: 12, bg: t.menu, stroke: t.sep },
    T(title, { w: "fill", size: 13, weight: 600, color: t.l1 }),
    text ? T(text, { w: "fill", color: t.l2 }) : null,
    body,
    F({ name: "ações", flex: "row", w: "fill", gap: 8, justify: "end" }, buttons),
  );

const centerBlock = (t, iconName, iconColor, title, text, actions) =>
  F(
    { name: "conteúdo", flex: "col", w: "fill", p: 16, gap: 8, items: "center", rounded: 8, bg: t.card },
    icon(iconName, iconColor, 32, 1.75),
    T(title, { w: "fill", size: 13, weight: 600, color: t.l1, textAlign: "center" }),
    T(text, { w: "fill", color: t.l2, textAlign: "center" }),
    actions ? F({ name: "ações", flex: "row", w: "fill", gap: 8, pt: 4 }, actions) : null,
  );

// --- componentes ---------------------------------------------------------------

const CARD_STATES = (t) => ({
  Desligado: { on: false, color: t.gray, status: "Desligado" },
  Conectando: { on: true, dim: true, spin: true, color: t.blue, status: "Conectando…", note: "Cancelar" },
  Verificando: { on: true, spin: true, color: t.green, status: "Conectado · testando o túnel…" },
  Conectado: { on: true, color: t.green, status: "Conectado há 2 h 14 min", note: "testado há 8 s" },
  "Sem resposta": {
    on: true,
    color: t.orange,
    status: "Sem resposta pelo túnel",
    note: "há 40 s",
    notice: { tone: "warn", text: "O túnel parece ligado, mas nada passa por ele.", buttons: [["Reconectar", "primary"], ["Desligar"]] },
  },
  Reconectando: { on: true, dim: true, spin: true, color: t.blue, status: "Reconectando…", note: "Cancelar" },
  Desligando: { on: false, dim: true, spin: true, color: t.gray, status: "Desligando…" },
  Caiu: { on: false, color: t.orange, status: "Caiu às 14:32", notice: { tone: "warn", text: "O servidor encerrou a conexão.", buttons: [["Reconectar", "primary"], ["Ver log"]] } },
  "Falha de credenciais": {
    on: false,
    color: t.red,
    status: "Não conectou",
    notice: { tone: "err", text: "O servidor recusou o usuário ou a senha.", buttons: [["Tentar de novo", "primary"], ["Trocar senha"]] },
  },
  "Gateway mudo": { on: false, color: t.red, status: "Não conectou", notice: { tone: "err", text: "O gateway não respondeu em 30 s.", buttons: [["Tentar de novo", "primary"], ["Ver log"]] } },
  "Falta segredo": { on: false, color: t.orange, status: "Falta a senha", notice: { tone: "warn", text: "A senha desta VPN não está no chaveiro.", buttons: [["Informar senha", "primary"]] } },
  "Falta programa": {
    on: false,
    dim: true,
    color: t.orange,
    status: "Falta o strongSwan",
    notice: { tone: "warn", text: "Instale com: brew install strongswan", buttons: [["Copiar comando"], ["Verificar de novo"]] },
  },
  "Sem rede": { on: false, dim: true, color: t.gray, status: "Sem rede no computador" },
  "Sem componente": { on: false, dim: true, color: t.gray, status: "Aguardando o componente" },
});

const CARD_NOTES = {
  Desligado: "Clique liga.",
  Conectando: "Negociando com o gateway. Clique cancela.",
  Verificando: "O túnel subiu; o primeiro teste pelo plano de dados ainda roda.",
  Conectado: "O teste passou. Clique desliga.",
  "Sem resposta": "Túnel de pé, mas o teste falhou. Reconectar é a ação principal.",
  Reconectando: "Derruba e sobe de novo.",
  Desligando: "Interruptor travado até terminar.",
  Caiu: "O túnel fechou sem pedido do usuário.",
  "Falha de credenciais": "Usuário, senha ou chave recusados.",
  "Gateway mudo": "Sem resposta do gateway.",
  "Falta segredo": "Nada no chaveiro para este perfil.",
  "Falta programa": "strongSwan ou openfortivpn não instalado.",
  "Sem rede": "Interruptor travado.",
  "Sem componente": "Interruptor travado até instalar ou atualizar.",
};

// Nível 1: não dependem de outros componentes.
const leafComponents = (t) => {
  const out = [];
  for (const [on, dim] of [[true, false], [false, false], [true, true], [false, true]]) {
    out.push([
      `Interruptor/${on ? "Ligado" : "Desligado"}${dim ? " travado" : ""}`,
      F(
        { name: "interruptor", flex: "row", w: 32, h: 20, p: 4, items: "center", justify: on ? "end" : "start", rounded: 12, bg: on ? t.blue : t.switchOff, opacity: dim ? 0.45 : undefined },
        F({ name: "botão", w: 12, h: 12, rounded: 6, bg: "#FFFFFF" }),
      ),
    ]);
  }
  const button = (name, bg, fg) =>
    out.push([name, F({ name: "botão", flex: "row", h: 24, px: 12, items: "center", justify: "center", rounded: 6, bg }, T("Botão", { name: "rótulo", weight: 500, color: fg }))]);
  button("Botão/Padrão", t.control, t.l1);
  button("Botão/Padrão na superfície", t.controlSurface, t.l1);
  button("Botão/Primário", t.action, "#FFFFFF");
  button("Botão/Perigo", t.control, t.redText);
  button("Botão/Perigo na superfície", t.controlSurface, t.redText);
  button("Botão/Perigo cheio", t.redFill, "#FFFFFF");
  button("Botão/Apagado", t.control, t.l2);
  button("Botão/Apagado na superfície", t.controlSurface, t.l2);
  out.push([
    "Seletor",
    F({ name: "seletor", flex: "row", h: 24, px: 8, gap: 4, items: "center", rounded: 6, bg: t.control }, T("Valor", { name: "valor", color: t.l1 }), icon("chevronDown", t.l2, 12)),
  ]);
  const input = (name, stroke) =>
    out.push([
      name,
      F(
        { name: "campo", flex: "row", w: 288, gap: 8, items: "center" },
        T("Rótulo", { name: "rótulo", w: 92, color: t.l1 }),
        F({ name: "entrada", flex: "row", w: "fill", h: 24, px: 8, items: "center", rounded: 6, bg: t.field, stroke }, T("Valor", { name: "valor", color: name.endsWith("azio") ? t.l2 : t.l1 })),
      ),
    ]);
  input("Campo/Texto", t.sep);
  input("Campo/Vazio", t.sep);
  input("Campo/Erro", t.red);
  input("Campo/Erro vazio", t.red);
  out.push([
    "Campo/Seletor",
    F(
      { name: "campo", flex: "row", w: 288, gap: 8, items: "center" },
      T("Rótulo", { name: "rótulo", w: 92, color: t.l1 }),
      F({ name: "seletor", flex: "row", h: 24, px: 8, gap: 4, items: "center", rounded: 6, bg: t.control }, T("Valor", { name: "valor", color: t.l1 }), icon("chevronDown", t.l2, 12)),
    ),
  ]);
  out.push([
    "Cabeçalho",
    F(
      { name: "cabeçalho", flex: "row", w: 304, h: 24, pl: 4, justify: "between", items: "center" },
      T("VPNs", { size: 13, weight: 600, color: t.l1 }),
      F({ name: "botão preferências", flex: "row", w: 24, h: 24, items: "center", justify: "center", rounded: 6 }, icon("sliders", t.l1, 16)),
    ),
  ]);
  const bar = (name, refresh) =>
    out.push([
      name,
      F(
        { name: "barra de título", flex: "row", w: 304, h: 24, pr: refresh ? 0 : 24, items: "center" },
        F({ name: "botão voltar", flex: "row", w: 24, h: 24, items: "center", justify: "center", rounded: 6 }, icon("chevronLeft", t.l1, 16)),
        T("Título", { name: "título", w: "fill", size: 13, weight: 600, color: t.l1, textAlign: "center" }),
        refresh ? F({ name: "botão atualizar", flex: "row", w: 24, h: 24, items: "center", justify: "center", rounded: 6 }, icon("refresh", t.l1, 16)) : null,
      ),
    ]);
  bar("Barra de título/Simples", false);
  bar("Barra de título/Com atualizar", true);
  const foot = (name, state) =>
    out.push([
      name,
      F(
        { name: "rodapé", flex: "row", w: 304, pl: 4, justify: "between", items: "center" },
        F({ name: "versão", flex: "col" }, T("vpnt 0.1.0", { color: t.l2 }), state ? T("Túneis testados há 8 s", { name: "estado", color: t.l2 }) : null),
        F({ name: "Opções", flex: "row", h: 24, px: 12, gap: 4, items: "center", rounded: 6, bg: t.controlSurface }, T("Opções", { weight: 500, color: t.l1 }), icon("chevronDown", t.l1, 12)),
      ),
    ]);
  foot("Rodapé/Simples", false);
  foot("Rodapé/Com estado", true);
  for (const [state, glyph, opacity] of [["Desligado", "shield", 0.5], ["Conectando", "shieldDots"], ["Conectado", "shieldCheck"], ["Sem resposta", "shieldAlert"], ["Falha", "shieldX"]]) {
    out.push([`Ícone da barra/${state}`, F({ name: "ícone da barra", flex: "row", w: 24, h: 24, items: "center", justify: "center", opacity }, icon(glyph, t.barFg, 16))]);
  }
  return out;
};

// Nível 2: usam os do nível 1.
const cardComponents = (t) =>
  Object.entries(CARD_STATES(t)).map(([state, v]) => [
    `Cartão de VPN/${state}`,
    F(
      { name: "cartão de VPN", flex: "col", w: 304, p: 12, gap: 8, rounded: 8, bg: t.card },
      F(
        { name: "título", flex: "row", w: "fill", justify: "between", items: "center" },
        F({ name: "identificação", flex: "col" }, T("Cluster", { name: "nome", size: 13, weight: 600, color: t.l1 }), T(IPSEC, { name: "tipo", color: t.l2 })),
        toggle(t, v.on, v.dim),
      ),
      F(
        { name: "estado", flex: "row", w: "fill", justify: "between", items: "center" },
        F({ name: "situação", flex: "row", gap: 8, items: "center" }, v.spin ? icon("loader", v.color, 12, 3) : dot(v.color), T(v.status, { color: t.l1 })),
        v.note ? T(v.note, { color: t.l2 }) : null,
      ),
      v.notice ? notice(t, v.notice.tone, v.notice.text, v.notice.buttons.map(([l, k]) => btn(t, l, k))) : null,
    ),
  ]);

// --- telas ---------------------------------------------------------------------

const preferences = (t, helper = "ok") =>
  panelShell(
    t,
    "Preferências",
    topBar(t, "Preferências"),
    sectionTitle(t, "Geral"),
    group(t, row(t, "Abrir ao iniciar a sessão", toggle(t, true)), row(t, "Tema", picker(t, "Sistema"))),
    sectionTitle(t, "Teste do túnel"),
    group(
      t,
      row(t, "Testar a cada", picker(t, "10 s")),
      row(t, "Avisar se ficar sem resposta", toggle(t, true)),
      row(t, "Reconectar sozinho", toggle(t, false), "Depois de 3 testes sem resposta"),
    ),
    sectionTitle(t, "VPNs"),
    group(
      t,
      row(t, "Cluster", icon("chevronRight", t.l2, 16), "IPsec IKEv2"),
      row(t, "Escritório", icon("chevronRight", t.l2, 16), "SSL VPN Fortinet"),
      F({ name: "linha Adicionar VPN", flex: "row", w: "fill", h: 32, gap: 8, items: "center" }, icon("plus", t.link, 16), T("Adicionar VPN", { size: 13, color: t.link })),
    ),
    sectionTitle(t, "Acesso de administrador"),
    helper === "ok"
      ? group(t, row(t, "Componente instalado", T("0.1.0", { color: t.l2 }), "Liga e desliga sem pedir senha"), row(t, "Remover componente", btn(t, "Remover", "danger")))
      : group(t, row(t, "Componente não instalado", btn(t, "Instalar", "primary"), "Sem ele não dá para ligar túneis")),
    footer(t),
  );

const profileActions = (t, canSave = true) =>
  F({ name: "ações", flex: "row", w: "fill", justify: "between", items: "center" }, btn(t, "Remover VPN", "danger", true), btn(t, "Salvar", canSave ? "primary" : "disabled", true));

const profileIpsec = (t, bad = false) =>
  panelShell(
    t,
    bad ? "Perfil IPsec com erros" : "Perfil IPsec",
    topBar(t, "Cluster"),
    group(
      t,
      field(t, "Nome", "Cluster"),
      field(t, "Tipo", "IPsec IKEv2", "Seletor"),
      bad ? field(t, "Gateway", "vpn.exemplo.com", "Erro vazio") : field(t, "Gateway", "vpn.exemplo.com"),
      bad ? fieldNote(t, "Informe o gateway.", true) : null,
      field(t, "Usuário", "nome.sobrenome"),
      bad ? field(t, "Redes", "10.20.0.0/33", "Erro") : field(t, "Redes", "10.20.0.0/24"),
      bad ? fieldNote(t, "Rede inválida. Exemplo: 10.20.0.0/24", true) : fieldNote(t, "Só estas redes passam pelo túnel. Vazio: túnel completo."),
    ),
    sectionTitle(t, "Teste do túnel"),
    group(
      t,
      field(t, "Endereço", "10.20.0.15"),
      fieldNote(t, "Uma máquina do destino, não o roteador."),
      field(t, "Método", "Ping, depois TCP", "Seletor"),
      field(t, "Porta TCP", "8443"),
      fieldNote(t, "Nunca a 22: o servidor pode banir o endereço."),
    ),
    sectionTitle(t, "Segredos"),
    group(t, secretRow(t, "Chave do gateway (PSK)", true), secretRow(t, "Senha do usuário", !bad)),
    noteLine(t, "Salvar pede a senha de administrador."),
    profileActions(t, !bad),
  );

const profileSsl = (t) =>
  panelShell(
    t,
    "Perfil SSL VPN",
    topBar(t, "Escritório"),
    group(
      t,
      field(t, "Nome", "Escritório"),
      field(t, "Tipo", "SSL VPN Fortinet", "Seletor"),
      field(t, "Gateway", "vpn.exemplo.com"),
      field(t, "Porta", "443"),
      field(t, "Usuário", "nome.sobrenome"),
      field(t, "Certificado", "sha256 3f9a…c21e"),
      fieldNote(t, "Impressão digital aceita do servidor."),
      field(t, "Rotas", "Túnel completo", "Seletor"),
    ),
    sectionTitle(t, "Teste do túnel"),
    group(t, field(t, "Endereço", "10.30.0.10"), field(t, "Método", "Ping, depois TCP", "Seletor"), field(t, "Porta TCP", "443")),
    sectionTitle(t, "Segredos"),
    group(t, secretRow(t, "Senha do usuário", true)),
    noteLine(t, "Salvar pede a senha de administrador."),
    profileActions(t),
  );

const newProfile = (t) =>
  panelShell(
    t,
    "Nova VPN",
    topBar(t, "Nova VPN"),
    sectionTitle(t, "Escolha o tipo"),
    group(t, row(t, "IPsec IKEv2", icon("chevronRight", t.l2, 16), "strongSwan: usuário, senha e chave")),
    group(t, row(t, "SSL VPN Fortinet", icon("chevronRight", t.l2, 16), "openfortivpn: usuário e senha")),
    noteLine(t, "Os dois programas são instalados à parte, pelo Homebrew."),
  );

const LOG_LINES = [
  "14:31:02 IKE iniciando cluster",
  "14:31:02 IKE enviando IKE_SA_INIT",
  "14:31:03 IKE gateway autenticado por PSK",
  "14:31:03 IKE EAP-MSCHAPv2 aceito",
  "14:31:04 IKE endereço virtual 10.99.0.7",
  "14:31:04 CHD túnel cluster estabelecido",
  "14:31:04 CHD redes 10.20.0.0/24",
  "14:31:34 IKE verificação de par: ok",
  "14:32:04 IKE verificação de par: ok",
];

const logScreen = (t, mode) =>
  panelShell(
    t,
    `Log · ${mode}`,
    topBar(t, "Log", true),
    F({ name: "abas", flex: "row", w: "fill", gap: 8 }, btn(t, "Cluster", "primary"), btn(t, "Escritório", "plain", true)),
    mode === "cheio"
      ? F({ name: "linhas", flex: "col", w: "fill", p: 12, gap: 4, rounded: 8, bg: t.card }, LOG_LINES.map((l) => T(l, { w: "fill", color: t.l1 })))
      : mode === "vazio"
        ? centerBlock(t, "shield", t.gray, "Ainda não há log", "Nenhuma conexão foi feita com esta VPN.", null)
        : centerBlock(t, "loader", t.blue, "Lendo o log…", "O log é guardado só para o administrador.", null),
    mode === "cheio" ? F({ name: "ações", flex: "row", w: "fill", justify: "between", items: "center", pl: 4 }, T("Últimas 60 linhas", { color: t.l2 }), btn(t, "Copiar", "plain", true)) : null,
  );

const secretDialog = (t, kind) =>
  dialog(
    t,
    kind === "ipsec" ? "Diálogo: segredos do IPsec" : "Diálogo: senha da SSL VPN",
    kind === "ipsec" ? "Segredos de Cluster" : "Senha de Escritório",
    "Ficam no chaveiro do sistema, nunca em arquivo.",
    F(
      { name: "campos", flex: "col", w: "fill", gap: 8 },
      kind === "ipsec" ? field(t, "Chave (PSK)", "••••••••••••") : null,
      kind === "ipsec" ? field(t, "Senha", "Senha do usuário", "Vazio") : field(t, "Senha", "••••••••"),
    ),
    [btn(t, "Cancelar"), btn(t, kind === "ipsec" ? "Guardar" : "Guardar e conectar", kind === "ipsec" ? "disabled" : "primary")],
  );

const removeDialog = (t) =>
  dialog(t, "Diálogo: remover VPN", "Remover a VPN Cluster?", "O perfil e os segredos dela no chaveiro são apagados. O túnel é desligado antes.", null, [btn(t, "Cancelar"), btn(t, "Remover", "danger-fill")]);

const discardDialog = (t) =>
  dialog(t, "Diálogo: descartar mudanças", "Descartar as mudanças?", "O perfil Cluster foi alterado e ainda não foi salvo.", null, [btn(t, "Continuar editando"), btn(t, "Descartar", "danger")]);

const onboarding = (t, step) => {
  const two = (a, b) => [btn(t, a, "plain", false, true), btn(t, b, "primary", false, true)];
  const one = (a, kind = "primary") => [btn(t, a, kind, false, true)];
  if (step === "details") {
    return panelShell(
      t,
      "O que é instalado",
      topBar(t, "Componente"),
      sectionTitle(t, "O que é instalado"),
      group(
        t,
        row(t, "/usr/local/libexec/vpnt-helper", null, "O componente. Só o administrador altera."),
        row(t, "/etc/sudoers.d/vpnt", null, "Libera só esse componente, sem senha."),
        row(t, "/etc/vpnt/", null, "Perfis das VPNs. Mudar um perfil pede senha."),
      ),
      noteLine(t, "Dá para remover tudo em Preferências."),
      F({ name: "ações", flex: "row", w: "fill", justify: "end" }, btn(t, "Instalar", "primary")),
    );
  }
  const steps = {
    welcome: () =>
      centerBlock(
        t,
        "shield",
        t.blue,
        "Falta um passo",
        "Ligar um túnel exige acesso de administrador. O vpnt instala um componente pequeno para não pedir a senha toda vez. Ele só liga, desliga e lê o log das VPNs cadastradas.",
        two("Ver detalhes", "Instalar"),
      ),
    installing: () => centerBlock(t, "loader", t.blue, "Instalando…", "Confirme com a senha de administrador na janela do sistema.", one("Cancelar", "plain")),
    done: () => centerBlock(t, "shieldCheck", t.green, "Componente instalado", "Agora cadastre a primeira VPN.", one("Adicionar VPN")),
    failed: () => centerBlock(t, "shieldX", t.red, "Não foi possível instalar", "A autenticação foi cancelada. Nada foi alterado no sistema.", one("Tentar de novo")),
    outdated: () =>
      centerBlock(t, "shieldAlert", t.orange, "Componente desatualizado", "O componente instalado é da versão 0.1.0 e o app é 0.2.0. Atualize para continuar ligando túneis.", one("Atualizar")),
  };
  const names = { welcome: "Primeiro uso", installing: "Instalando", done: "Instalado", failed: "Falha na instalação", outdated: "Componente desatualizado" };
  const head = header(t);
  const body = steps[step]();
  return panelShell(t, names[step], head, body, footer(t));
};

const emptyPanel = (t) => {
  const head = header(t);
  const body = centerBlock(t, "shield", t.gray, "Nenhuma VPN cadastrada", "Cadastre uma VPN IPsec IKEv2 ou SSL VPN Fortinet para ligar por aqui.", [btn(t, "Adicionar VPN", "primary", false, true)]);
  return panelShell(t, "Sem VPNs", head, body, footer(t));
};

const about = (t) => {
  const head = topBar(t, "Sobre");
  return panelShell(
    t,
    "Sobre",
    head,
    centerBlock(t, "shieldCheck", t.blue, "vpnt 0.1.0", "Liga, desliga e acompanha VPNs pela barra de menus. Código aberto, licença MIT.", [
      btn(t, "Página do projeto", "plain", false, true),
      btn(t, "Atualizações", "plain", false, true),
    ]),
  );
};

const menuBar = (t, state) =>
  F(
    { name: `barra de menus · ${state}`, flex: "row", w: 220, h: 28, px: 12, gap: 12, items: "center", justify: "end", rounded: 6, bg: t.bar },
    F({ name: "outro ícone", w: 16, h: 16, rounded: 4, bg: t.barFg, opacity: 0.25 }),
    trayIcon(t, state),
    F({ name: "outro ícone", w: 16, h: 16, rounded: 8, bg: t.barFg, opacity: 0.25 }),
    T("Qua 14:32", { weight: 500, color: t.barFg }),
  );

const tooltip = (text) => F({ name: "dica", flex: "row", px: 8, py: 4, rounded: 6, bg: "#4A4A4A" }, T(text, { color: "#FFFFFF" }));

const cardBox = (t, card) => F({ name: "moldura", flex: "col", w: COL, p: 8, rounded: 12, bg: t.surface, stroke: t.sep }, card);
const helperBanner = (t) => notice(t, "info", "Falta instalar o componente que liga os túneis. É uma vez só, com a senha de administrador.", [btn(t, "Instalar", "primary")]);
const outdatedBanner = (t) => notice(t, "warn", "O componente instalado é de uma versão anterior.", [btn(t, "Atualizar", "primary")]);

const panelOf = (t, name, states, line2, banner = null) => {
  const head = header(t);
  const top = banner ? banner(t) : null;
  const cards = [cluster(t, states[0]), office(t, states[1])];
  return panelShell(t, name, head, top, cards, footer(t, line2));
};

// --- páginas -------------------------------------------------------------------

// Uma amostra: legenda, nota opcional e um ou mais corpos, todos soltos na página.
const spec = (label, bodies, note = null) => ({ label, note, bodies: [].concat(bodies) });

const TESTED = "Túneis testados há 8 s";
const panelSpecs = (t) => [
  spec("Tudo desligado", panelOf(t, "Painel · tudo desligado", ["Desligado", "Desligado"])),
  spec("Uma conectada", panelOf(t, "Painel · uma conectada", ["Conectado", "Desligado"], TESTED)),
  spec("Duas conectadas", panelOf(t, "Painel · duas conectadas", ["Conectado", "Conectado"], TESTED)),
  spec("Conectando", panelOf(t, "Painel · conectando", ["Conectando", "Desligado"]), "Clicar de novo no cartão cancela."),
  spec("Túnel sem resposta", panelOf(t, "Painel · sem resposta", ["Sem resposta", "Conectado"], TESTED), "A ação principal vira Reconectar; Desligar fica ao lado."),
  spec("Falha ao conectar", panelOf(t, "Painel · falha", ["Falha de credenciais", "Desligado"])),
  spec("Sem rede", panelOf(t, "Painel · sem rede", ["Sem rede", "Sem rede"], "Sem rede no computador")),
  spec("Componente não instalado", panelOf(t, "Painel · sem componente", ["Sem componente", "Sem componente"], null, helperBanner)),
  spec("Componente desatualizado", panelOf(t, "Painel · componente antigo", ["Sem componente", "Sem componente"], null, outdatedBanner)),
  spec("Nenhuma VPN cadastrada", emptyPanel(t)),
  spec(
    "Menu Opções aberto",
    [panelOf(t, "Painel · menu aberto", ["Conectado", "Desligado"], TESTED), menu(t, [["Desligar tudo"], ["Testar agora"], ["Ver log"], "-", ["Preferências"], ["Sobre"], "-", ["Sair"]])],
    "Desligar tudo fica apagado quando nada está ligado.",
  ),
];

const cardSpecs = (t) => Object.keys(CARD_STATES(t)).map((state) => spec(state, cardBox(t, cluster(t, state)), CARD_NOTES[state]));

const traySpec = (state, tip, note = null) => spec(state, [menuBar(light, state), menuBar(dark, state), tooltip(tip)], note);

const pages = [
  {
    name: "1 · Painel",
    theme: light,
    title: "Painel",
    lead: "O popover que abre ao clicar no ícone. Um cartão por VPN; o cartão inteiro liga e desliga.",
    specs: () => panelSpecs(light),
  },
  { name: "2 · Estados do cartão", theme: light, title: "Estados do cartão", lead: "Todos os estados que uma VPN pode mostrar, isolados.", specs: () => cardSpecs(light) },
  {
    name: "3 · Preferências e perfis",
    theme: light,
    title: "Preferências e perfis",
    lead: "Telas que abrem dentro do mesmo popover.",
    specs: () => [
      spec("Preferências", preferences(light)),
      spec("Preferências sem componente", preferences(light, "missing")),
      spec("Nova VPN: tipo", newProfile(light)),
      spec("Sobre", about(light)),
      spec("Perfil IPsec IKEv2", profileIpsec(light)),
      spec("Perfil SSL VPN", profileSsl(light)),
      spec("Perfil com erros", profileIpsec(light, true), "Salvar fica apagado até corrigir."),
    ],
  },
  {
    name: "4 · Primeiro uso",
    theme: light,
    title: "Primeiro uso e componente",
    lead: "Instalação única do componente de administrador e seus desfechos.",
    specs: () => [
      spec("Primeiro uso", onboarding(light, "welcome")),
      spec("O que é instalado", onboarding(light, "details")),
      spec("Instalando", onboarding(light, "installing")),
      spec("Instalado", onboarding(light, "done")),
      spec("Falha na instalação", onboarding(light, "failed")),
      spec("Componente desatualizado", onboarding(light, "outdated")),
      spec("Nenhuma VPN cadastrada", emptyPanel(light)),
    ],
  },
  {
    name: "5 · Log e diálogos",
    theme: light,
    title: "Log e diálogos",
    lead: "Leitura do log e janelas de confirmação.",
    specs: () => [
      spec("Log", logScreen(light, "cheio")),
      spec("Log vazio", logScreen(light, "vazio")),
      spec("Log carregando", logScreen(light, "lendo")),
      spec("Senha da SSL VPN", secretDialog(light, "ssl")),
      spec("Segredos do IPsec", secretDialog(light, "ipsec"), "Guardar fica apagado até preencher tudo."),
      spec("Remover VPN", removeDialog(light)),
      spec("Descartar mudanças", discardDialog(light)),
    ],
  },
  {
    name: "6 · Ícone e menu",
    theme: light,
    title: "Ícone e menu",
    lead: "O ícone é monocromático, como pede a barra de menus do macOS: o estado está no desenho, não na cor.",
    specs: () => [
      traySpec("Desligado", "vpnt: tudo desligado", "Escudo vazio, apagado."),
      traySpec("Conectando", "vpnt: conectando Cluster"),
      traySpec("Conectado", "vpnt: Cluster e Escritório conectados", "Igual para uma ou mais VPNs ligadas."),
      traySpec("Sem resposta", "vpnt: Cluster sem resposta", "Vale também quando só uma das ligadas falha."),
      traySpec("Falha", "vpnt: Cluster não conectou", "Some quando o aviso é visto ou a VPN liga."),
      spec("Menu do clique direito", menu(light, [["Cluster", "Conectado"], ["Escritório", "Desligado"], "-", ["Desligar tudo"], ["Abrir painel"], ["Preferências"], "-", ["Sair"]]), "Clicar numa VPN liga ou desliga."),
      spec("Menu com tudo desligado", menu(light, [["Cluster", "Desligado"], ["Escritório", "Desligado"], "-", ["Desligar tudo", null, "disabled"], ["Abrir painel"], ["Preferências"], "-", ["Sair"]])),
    ],
  },
  {
    name: "7 · Tema escuro",
    theme: dark,
    title: "Tema escuro",
    lead: "As mesmas telas no tema escuro. O app segue o sistema por padrão.",
    specs: () => [
      ...panelSpecs(dark),
      spec("Preferências", preferences(dark)),
      spec("Perfil IPsec IKEv2", profileIpsec(dark)),
      spec("Perfil com erros", profileIpsec(dark, true)),
      spec("Log", logScreen(dark, "cheio")),
      spec("Primeiro uso", onboarding(dark, "welcome")),
      spec("Senha da SSL VPN", secretDialog(dark, "ssl")),
      spec("Remover VPN", removeDialog(dark)),
    ],
  },
  { name: "8 · Cartão no tema escuro", theme: dark, title: "Estados do cartão no tema escuro", lead: "Todos os estados do cartão, no tema escuro.", specs: () => cardSpecs(dark) },
];

// --- execução ------------------------------------------------------------------

function cli(args) {
  const r = spawnSync("bunx", ["@open-pencil/cli", ...args], { encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
  if (r.status !== 0) throw new Error(`${args.slice(0, 3).join(" ")}: ${r.stderr || r.stdout}`);
  return r.stdout;
}

function call(tool, args, pageId) {
  const dir = mkdtempSync(join(tmpdir(), "vpnt-proto-"));
  const file = join(dir, "args.json");
  writeFileSync(file, JSON.stringify(args));
  try {
    // Cada chamada é um processo novo e a página atual não persiste entre
    // elas: todo desenho leva o identificador da página.
    return JSON.parse(cli(["tool", "call", tool, "--args-file", file, "--json", "--document-id", doc.id, ...(pageId ? ["--page-id", pageId] : [])]));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

// Roda dentro do OpenPencil: solta os nós na página, troca os marcadores por
// instâncias, transforma em componentes quando pedido e distribui em grade.
const PLACE = `
const page = figma.currentPage;
const wrap = page.children.find((n) => n.name === "zz-lote");
const items = [...wrap.children];
for (const n of items) page.appendChild(n);
wrap.remove();
const comps = {};
for (const p of figma.root.children) {
  if (!p.name.startsWith(plan.componentsPrefix)) continue;
  for (const n of p.children) if (n.type === "COMPONENT") comps[n.name] = n;
}
const missing = [];
const marks = [];
for (const n of items) {
  if (n.name.startsWith("@i|")) marks.push(n);
  else if (n.findAll) marks.push(...n.findAll((x) => x.name.startsWith("@i|")));
}
for (const mark of marks) {
  const slot = plan.slots[Number(mark.name.slice(3))];
  const comp = comps[slot.comp];
  if (!comp) { missing.push(slot.comp); continue; }
  const inst = comp.createInstance();
  const parent = mark.parent;
  parent.insertChild(parent.children.indexOf(mark), inst);
  const at = items.indexOf(mark);
  if (at >= 0) items[at] = inst;
  mark.remove();
  if (slot.fill) inst.layoutSizingHorizontal = "FILL";
  for (const [name, value] of Object.entries(slot.text)) {
    const t = inst.findOne((x) => x.type === "TEXT" && x.name === name);
    if (!t) { missing.push(slot.comp + " #" + name); continue; }
    await figma.loadFontAsync(t.fontName);
    t.characters = value;
  }
}
let k = 0;
let y = plan.y0;
if (plan.title) {
  for (const gap of [8, 40]) { const n = items[k++]; n.x = 0; n.y = y; y += Math.round(n.height) + gap; }
}
let col = 0;
let rowH = 0;
for (const s of plan.specs) {
  const x = col * (plan.colW + 40);
  let yy = y;
  const label = items[k++];
  label.x = x; label.y = yy; yy += Math.round(label.height) + 4;
  if (s.note) { const n = items[k++]; n.x = x; n.y = yy; yy += Math.round(n.height) + 4; }
  yy += 4;
  for (let i = 0; i < s.bodies; i++) {
    let n = items[k++];
    if (s.component) { n = figma.createComponentFromNode(n); n.name = s.component; }
    n.x = x; n.y = yy; yy += Math.round(n.height) + 8;
  }
  rowH = Math.max(rowH, yy - y);
  if (++col >= plan.per) { col = 0; y += rowH + 40; rowH = 0; }
}
if (col) y += rowH + 40;
const hex = plan.bg;
page.backgrounds = [{ type: "SOLID", color: { r: parseInt(hex.slice(1, 3), 16) / 255, g: parseInt(hex.slice(3, 5), 16) / 255, b: parseInt(hex.slice(5, 7), 16) / 255 } }];
return { y, missing: [...new Set(missing)], placed: k };
`;

function draw(pageId, t, { title, lead, specs, per = 4, y0 = 0, bg }) {
  const kids = [];
  if (title) kids.push(T(title, { size: 24, weight: 700, color: t.heading }), T(lead, { size: 13, color: t.caption }));
  for (const s of specs) {
    kids.push(T(s.label, { w: COL, weight: 600, color: t.caption }));
    if (s.note) kids.push(T(s.note, { w: COL, color: t.caption }));
    kids.push(...s.bodies);
  }
  const plan = {
    componentsPrefix: COMPONENTS_PREFIX,
    slots,
    title: !!title,
    per,
    y0,
    colW: COL,
    bg: bg || t.canvas,
    specs: specs.map((s) => ({ note: !!s.note, bodies: s.bodies.length, component: s.component })),
  };
  slots = [];
  call("render", { jsx: F({ name: "zz-lote" }, kids), x: 0, y: 0 }, pageId);
  const out = call("eval", { code: `const plan = ${JSON.stringify(plan)};${PLACE}` }, pageId);
  if (out.missing?.length) throw new Error(`Componentes ou textos não encontrados: ${out.missing.join(", ")}`);
  return out;
}

const docs = JSON.parse(cli(["documents", "list", "--json"]));
const doc = docs.find((d) => d.active) || docs[0];
if (!doc?.pages.length) throw new Error("Open an empty document in OpenPencil first.");
const pageIds = Object.fromEntries(doc.pages.map((p) => [p.name, p.id]));
const anyPage = doc.pages[0].id;
let initialPage = doc.pages.length === 1 && /^Page \d+$/.test(doc.pages[0].name)
  && call("eval", { code: "return figma.currentPage.children.length" }, anyPage) === 0
  ? doc.pages[0]
  : null;
const ensurePage = (name) => {
  if (!pageIds[name]) {
    if (initialPage) {
      // Reuse the empty default page so a fresh document has no unnamed extra page.
      call("eval", { code: `figma.currentPage.name = ${JSON.stringify(name)}; return 0` }, initialPage.id);
      delete pageIds[initialPage.name];
      pageIds[name] = initialPage.id;
      initialPage = null;
    } else {
      pageIds[name] = call("create_page", { name }, anyPage).id;
    }
  }
  call("eval", { code: "for (const n of [...figma.currentPage.children]) n.remove(); return 0" }, pageIds[name]);
  return pageIds[name];
};

const only = process.argv.find((a) => a.startsWith("--only="))?.slice(7);

if (!only || only === "0") {
  for (const t of [light, dark]) {
    const id = ensurePage(componentsPage(t));
    let y = 0;
    for (const [what, defs] of [["Componentes de base", leafComponents], ["Cartão de VPN", cardComponents]]) {
      slots = [];
      const list = defs(t);
      const out = draw(id, t, {
        title: `${what} · tema ${t.key.toLowerCase()}`,
        lead: "Componentes principais: alterar aqui altera todas as telas que os usam.",
        specs: list.map(([name, jsx]) => ({ label: cn(t, name), note: null, bodies: [jsx], component: cn(t, name) })),
        y0: y,
      });
      y = out.y + 40;
      console.log(componentsPage(t), what, list.length);
    }
  }
}

for (const p of pages) {
  if (only && !p.name.startsWith(only)) continue;
  const id = ensurePage(p.name);
  slots = [];
  const out = draw(id, p.theme, { title: p.title, lead: p.lead, specs: p.specs() });
  console.log(p.name, id, `nós posicionados: ${out.placed}`);
}

// As páginas de componentes são criadas por último quando o documento começa
// vazio; elas vão para o início da lista.
call(
  "eval",
  {
    code: `const ps = figma.root.children.filter((c) => c.name.startsWith(${JSON.stringify(COMPONENTS_PREFIX)})).sort((a, b) => (a.name < b.name ? -1 : 1)); ps.forEach((p, i) => figma.root.insertChild(i, p)); return 0`,
  },
  anyPage,
);
