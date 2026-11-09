import { deriveKey, exportKey, importKey, seal, open, randomBytes, unb64, isEnvelope, KDF_ITERATIONS } from "./lib/crypto.js";
import { totp } from "./lib/totp.js";
import { generatePassword, strength } from "./lib/generator.js";

// ---------- Estado ----------
const S = {
  envelope: null, // sobre cifrado guardado en storage.local
  key: null, // CryptoKey AES-GCM (solo en memoria / storage.session)
  salt: null,
  iterations: KDF_ITERATIONS,
  vault: null, // { items: [], settings: { autoLockMin } }
  tab: null, // { id, url, host }
  query: "",
  failed: 0,
};
const DEFAULT_SETTINGS = { autoLockMin: 15, clipboardClearSec: 30 };
const app = document.getElementById("app");
const IN_TAB = location.hash === "#import";
if (IN_TAB) document.body.classList.add("tab");

// ---------- Utilidades DOM (nunca innerHTML con datos del usuario) ----------
function h(tag, attrs = {}, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v == null || v === false) continue;
    if (k.startsWith("on")) el.addEventListener(k.slice(2).toLowerCase(), v);
    else if (k === "class") el.className = v;
    else if (k in el && k !== "list") el[k] = v;
    else el.setAttribute(k, v === true ? "" : v);
  }
  for (const c of children.flat()) if (c != null && c !== false) el.append(c instanceof Node ? c : String(c));
  return el;
}
function render(...nodes) {
  app.replaceChildren(...nodes);
  app.querySelector("[autofocus]")?.focus();
}
let toastTimer;
function toast(msg) {
  const t = document.getElementById("toast");
  t.textContent = msg;
  t.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => (t.hidden = true), 1800);
}
let clipTimer;
async function copy(text, what) {
  await navigator.clipboard.writeText(text);
  toast(`${what} copiado`);
  clearTimeout(clipTimer);
  const sec = S.vault?.settings?.clipboardClearSec ?? 30;
  // Solo funciona mientras el popup siga abierto (Chrome lo cierra al perder foco).
  if (sec > 0) clipTimer = setTimeout(() => navigator.clipboard.writeText("").catch(() => {}), sec * 1000);
}
function hostOf(url) {
  if (!url) return "";
  try {
    const u = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(url) ? url : `https://${url}`);
    return u.hostname.replace(/^www\./, "").toLowerCase();
  } catch {
    return "";
  }
}
function matchesHost(tabHost, itemHost) {
  return !!tabHost && !!itemHost && (tabHost === itemHost || tabHost.endsWith(`.${itemHost}`));
}
const uid = () => Array.from(randomBytes(12), (b) => b.toString(16).padStart(2, "0")).join("");
const brand = (subtitle) =>
  h("div", { class: "brand" }, h("img", { src: "icons/48.png", alt: "" }),
    h("div", {}, h("h1", {}, "Bóveda CB"), subtitle && h("div", { class: "muted" }, subtitle)));

// ---------- Persistencia ----------
async function persist() {
  S.envelope = await seal(S.key, S.salt, S.iterations, S.vault);
  await chrome.storage.local.set({ vault: S.envelope });
}
async function startSession() {
  await chrome.storage.session.set({ sessionKey: await exportKey(S.key) });
  touch();
}
function touch() {
  const min = S.vault?.settings?.autoLockMin ?? DEFAULT_SETTINGS.autoLockMin;
  if (min > 0) chrome.alarms.create("autolock", { delayInMinutes: min });
  else chrome.alarms.clear("autolock");
}
async function lock() {
  await chrome.runtime.sendMessage({ type: "lock" });
  S.key = null;
  S.vault = null;
  viewUnlock();
}
function loadEnvelope(env) {
  S.envelope = env;
  S.salt = unb64(env.salt);
  S.iterations = env.kdf.iterations;
}

// ---------- Inicio ----------
async function init() {
  const [{ vault }, { sessionKey }] = await Promise.all([
    chrome.storage.local.get("vault"),
    chrome.storage.session.get("sessionKey"),
  ]);
  if (!IN_TAB) {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab?.url && /^https?:/.test(tab.url)) S.tab = { id: tab.id, url: tab.url, host: hostOf(tab.url) };
  }
  if (IN_TAB) return viewImport(!vault);
  if (!vault) return viewSetup();
  loadEnvelope(vault);
  if (sessionKey) {
    try {
      S.key = await importKey(sessionKey);
      S.vault = await open(S.key, S.envelope);
      S.vault.settings = { ...DEFAULT_SETTINGS, ...S.vault.settings };
      touch();
      return viewList();
    } catch {
      await chrome.storage.session.remove("sessionKey");
    }
  }
  viewUnlock();
}

// ---------- Vistas ----------
function viewSetup() {
  const p1 = h("input", { type: "password", autocomplete: "new-password", autofocus: true, required: true });
  const p2 = h("input", { type: "password", autocomplete: "new-password", required: true });
  const meter = h("div");
  const err = h("p", { class: "error" });
  p1.addEventListener("input", () => {
    const s = strength(p1.value);
    meter.replaceChildren(h("div", { class: "meter" }, h("div", { class: `lvl${s.level}`, style: `width:${s.level * 25}%` })),
      h("div", { class: "muted" }, `${s.label} · ~${s.bits} bits`));
  });
  const form = h("form", { class: "stack", onsubmit: async (e) => {
    e.preventDefault();
    err.textContent = "";
    if (p1.value.length < 10) return (err.textContent = "Usa al menos 10 caracteres (mejor una frase larga).");
    if (p1.value !== p2.value) return (err.textContent = "Las contraseñas no coinciden.");
    btn.disabled = true;
    btn.textContent = "Creando…";
    S.salt = randomBytes(16);
    S.iterations = KDF_ITERATIONS;
    S.key = await deriveKey(p1.value, S.salt, S.iterations);
    S.vault = { items: [], settings: { ...DEFAULT_SETTINGS } };
    await persist();
    await startSession();
    viewList();
  } },
  h("div", {}, h("label", {}, "Contraseña maestra"), p1, meter),
  h("div", {}, h("label", {}, "Repetir contraseña"), p2),
  err);
  const btn = h("button", { class: "primary block", type: "submit" }, "Crear bóveda");
  form.append(btn);
  render(brand("Crea tu bóveda"),
    h("p", {}, "Todo se cifra en este navegador con tu contraseña maestra. ",
      h("strong", {}, "Si la olvidas no hay forma de recuperar los datos.")),
    form,
    h("p", { class: "muted", style: "margin-top:14px" }, "¿Ya tienes un respaldo? ",
      h("a", { href: "#", onclick: (e) => { e.preventDefault(); openImportTab(); } }, "Restaurar desde archivo")));
}

function viewUnlock() {
  const pw = h("input", { type: "password", autocomplete: "current-password", autofocus: true, placeholder: "Contraseña maestra" });
  const err = h("p", { class: "error" });
  const btn = h("button", { class: "primary block", type: "submit" }, "Desbloquear");
  render(brand(S.tab ? S.tab.host : "Bloqueada"),
    h("form", { class: "stack", onsubmit: async (e) => {
      e.preventDefault();
      if (!pw.value) return;
      btn.disabled = true;
      btn.textContent = "Verificando…";
      err.textContent = "";
      try {
        const key = await deriveKey(pw.value, S.salt, S.iterations);
        const vault = await open(key, S.envelope);
        S.key = key;
        S.vault = vault;
        S.vault.settings = { ...DEFAULT_SETTINGS, ...vault.settings };
        S.failed = 0;
        await startSession();
        viewList();
      } catch {
        S.failed++;
        // Pequeña espera creciente tras errores repetidos.
        await new Promise((r) => setTimeout(r, Math.min(S.failed, 5) * 400));
        err.textContent = "Contraseña incorrecta.";
        btn.disabled = false;
        btn.textContent = "Desbloquear";
        pw.select();
      }
    } }, pw, err, btn));
}

function itemRow(item, { showFill }) {
  const actions = h("div", { class: "row" });
  if (showFill) actions.append(h("button", { class: "primary icon", title: "Rellenar en esta página",
    onclick: (e) => { e.stopPropagation(); fill(item); } }, "Rellenar"));
  if (item.username) actions.append(h("button", { class: "icon", title: "Copiar usuario",
    onclick: (e) => { e.stopPropagation(); copy(item.username, "Usuario"); } }, "👤"));
  if (item.password) actions.append(h("button", { class: "icon", title: "Copiar contraseña",
    onclick: (e) => { e.stopPropagation(); copy(item.password, "Contraseña"); } }, "🔑"));
  const li = h("li", { class: "item", tabIndex: 0, onclick: () => viewDetail(item.id),
    onkeydown: (e) => { if (e.key === "Enter") viewDetail(item.id); } },
    h("div", { class: "avatar", "aria-hidden": "true" }, (item.title || hostOf(item.url) || "?")[0]),
    h("div", { class: "grow" }, h("div", { class: "title" }, item.title || hostOf(item.url) || "(sin título)"),
      h("div", { class: "sub" }, item.username || hostOf(item.url))),
    actions);
  return li;
}

function viewList() {
  touch();
  const search = h("input", { type: "search", placeholder: "Buscar…", value: S.query, autofocus: true, "aria-label": "Buscar" });
  const listBox = h("div");
  const draw = () => {
    const q = S.query.trim().toLowerCase();
    const items = [...S.vault.items].sort((a, b) => (a.title || "").localeCompare(b.title || "", "es"));
    const here = S.tab ? items.filter((i) => matchesHost(S.tab.host, hostOf(i.url))) : [];
    const filtered = q
      ? items.filter((i) => [i.title, i.url, i.username, i.notes].some((f) => (f || "").toLowerCase().includes(q)))
      : items;
    const out = [];
    if (!q && here.length) {
      out.push(h("h2", {}, `En ${S.tab.host}`), h("ul", { class: "list" }, here.map((i) => itemRow(i, { showFill: true }))));
    }
    out.push(h("h2", {}, q ? `Resultados (${filtered.length})` : `Todos (${items.length})`));
    if (!filtered.length) {
      out.push(h("div", { class: "empty" }, q ? "Sin resultados." : "Aún no hay elementos. Crea el primero con «+ Nuevo»."));
    } else {
      const tabHost = S.tab?.host;
      out.push(h("ul", { class: "list" }, filtered.map((i) => itemRow(i, { showFill: matchesHost(tabHost, hostOf(i.url)) }))));
    }
    listBox.replaceChildren(...out);
  };
  search.addEventListener("input", () => { S.query = search.value; draw(); });
  search.addEventListener("keydown", (e) => {
    if (e.key === "Enter") app.querySelector(".item")?.click();
  });
  draw();
  render(
    h("div", { class: "toolbar" },
      h("button", { class: "primary", onclick: () => viewEdit(null) }, "+ Nuevo"),
      h("button", { onclick: () => viewGenerator() }, "Generador"),
      h("div", { class: "grow" }),
      h("button", { class: "icon", title: "Ajustes", onclick: () => viewSettings() }, "⚙"),
      h("button", { class: "icon", title: "Bloquear", onclick: lock }, "🔒")),
    search, listBox);
}

function field(labelText, value, { secret = false, copyLabel, mono = true } = {}) {
  const val = h("div", { class: mono ? "value" : "" }, secret ? "••••••••••••" : value);
  let shown = !secret;
  const btns = h("div", { class: "row" });
  if (secret) btns.append(h("button", { class: "icon", title: "Mostrar/ocultar", onclick: () => {
    shown = !shown;
    val.textContent = shown ? value : "••••••••••••";
  } }, "👁"));
  if (copyLabel) btns.append(h("button", { class: "icon", title: "Copiar", onclick: () => copy(value, copyLabel) }, "Copiar"));
  return h("div", { class: "field" }, h("label", {}, labelText), h("div", { class: "row" }, h("div", { class: "grow" }, val), btns));
}

let totpTimer;
function viewDetail(id) {
  touch();
  clearInterval(totpTimer);
  const item = S.vault.items.find((i) => i.id === id);
  if (!item) return viewList();
  const host = hostOf(item.url);
  const parts = [];
  if (item.username) parts.push(field("Usuario", item.username, { copyLabel: "Usuario" }));
  if (item.password) parts.push(field("Contraseña", item.password, { secret: true, copyLabel: "Contraseña" }));
  if (item.totp) {
    const code = h("div", { class: "value totp" }, "······");
    const left = h("div", { class: "muted" });
    let current = "";
    const tick = async () => {
      try {
        const r = await totp(item.totp);
        current = r.code;
        code.textContent = `${r.code.slice(0, 3)} ${r.code.slice(3)}`;
        left.textContent = `Cambia en ${r.remaining} s`;
      } catch (e) {
        code.textContent = "—";
        left.textContent = e.message;
      }
    };
    tick();
    totpTimer = setInterval(tick, 1000);
    parts.push(h("div", { class: "field" }, h("label", {}, "Código 2FA"),
      h("div", { class: "row" }, h("div", { class: "grow" }, code, left),
        h("button", { class: "icon", onclick: () => current && copy(current, "Código") }, "Copiar"))));
  }
  if (item.url) parts.push(h("div", { class: "field" }, h("label", {}, "Sitio web"),
    h("div", { class: "row" }, h("div", { class: "grow value" }, item.url),
      h("button", { class: "icon", onclick: () => chrome.tabs.create({ url: /^https?:\/\//i.test(item.url) ? item.url : `https://${item.url}` }) }, "Abrir"))));
  if (item.notes) parts.push(field("Notas", item.notes, { copyLabel: "Nota", mono: false }));
  const canFill = S.tab && matchesHost(S.tab.host, host);
  render(
    h("div", { class: "toolbar" },
      h("button", { onclick: () => { clearInterval(totpTimer); viewList(); } }, "← Volver"),
      h("div", { class: "grow" }),
      canFill && h("button", { class: "primary", onclick: () => fill(item) }, "Rellenar"),
      h("button", { onclick: () => { clearInterval(totpTimer); viewEdit(item.id); } }, "Editar")),
    h("div", { class: "row", style: "margin-bottom:10px" },
      h("div", { class: "avatar", "aria-hidden": "true" }, (item.title || host || "?")[0]),
      h("div", { class: "grow" }, h("div", { class: "title" }, item.title || host || "(sin título)"),
        h("div", { class: "sub" }, `Modificado ${new Date(item.updatedAt).toLocaleString("es")}`))),
    h("div", { class: "stack" }, parts));
}

function viewEdit(id) {
  touch();
  const existing = id ? S.vault.items.find((i) => i.id === id) : null;
  const draft = existing ? { ...existing } : {
    title: S.tab?.host || "", url: S.tab ? new URL(S.tab.url).origin : "", username: "", password: "", totp: "", notes: "",
  };
  const inp = (name, attrs = {}) => {
    const el = h(attrs.multiline ? "textarea" : "input", { ...attrs, multiline: null, value: draft[name] || "" });
    el.addEventListener("input", () => (draft[name] = el.value));
    return el;
  };
  const pass = inp("password", { type: "password", autocomplete: "off", spellcheck: false });
  const meter = h("div");
  const updMeter = () => {
    const s = strength(pass.value);
    meter.replaceChildren(h("div", { class: "meter" }, h("div", { class: `lvl${s.level}`, style: `width:${s.level * 25}%` })),
      h("div", { class: "muted" }, pass.value ? `${s.label} · ~${s.bits} bits` : ""));
  };
  pass.addEventListener("input", updMeter);
  updMeter();
  const err = h("p", { class: "error" });
  const save = async (e) => {
    e.preventDefault();
    if (!draft.title.trim() && !draft.url.trim()) return (err.textContent = "Pon al menos un título o un sitio.");
    if (draft.totp?.trim()) {
      try { await totp(draft.totp); } catch { return (err.textContent = "El secreto 2FA no es válido (base32 u otpauth://)."); }
    }
    const now = new Date().toISOString();
    if (existing) Object.assign(existing, draft, { updatedAt: now });
    else S.vault.items.push({ ...draft, id: uid(), createdAt: now, updatedAt: now });
    await persist();
    toast("Guardado");
    existing ? viewDetail(existing.id) : viewList();
  };
  render(
    h("div", { class: "toolbar" },
      h("button", { onclick: () => (existing ? viewDetail(existing.id) : viewList()) }, "← Cancelar"),
      h("div", { class: "grow" }),
      existing && h("button", { class: "danger", onclick: async () => {
        if (!confirm(`¿Eliminar «${existing.title || hostOf(existing.url)}»? No se puede deshacer.`)) return;
        S.vault.items = S.vault.items.filter((i) => i.id !== existing.id);
        await persist();
        toast("Eliminado");
        viewList();
      } }, "Eliminar")),
    h("form", { class: "stack", onsubmit: save },
      h("div", {}, h("label", {}, "Título"), inp("title", { autofocus: true })),
      h("div", {}, h("label", {}, "Sitio web"), inp("url", { placeholder: "https://ejemplo.com", spellcheck: false })),
      h("div", {}, h("label", {}, "Usuario / correo"), inp("username", { autocomplete: "off", spellcheck: false })),
      h("div", {}, h("label", {}, "Contraseña"),
        h("div", { class: "row" }, h("div", { class: "grow" }, pass),
          h("button", { type: "button", class: "icon", title: "Mostrar/ocultar",
            onclick: () => (pass.type = pass.type === "password" ? "text" : "password") }, "👁"),
          h("button", { type: "button", class: "icon", title: "Generar", onclick: () => {
            pass.value = draft.password = generatePassword({ length: 20 });
            pass.type = "text";
            updMeter();
          } }, "🎲")),
        meter),
      h("div", {}, h("label", {}, "Secreto 2FA (opcional)"), inp("totp", { placeholder: "JBSWY3DP… u otpauth://…", spellcheck: false })),
      h("div", {}, h("label", {}, "Notas"), inp("notes", { multiline: true })),
      err,
      h("button", { class: "primary block", type: "submit" }, existing ? "Guardar cambios" : "Guardar")));
}

function viewGenerator() {
  touch();
  const opts = { length: 20, upper: true, digits: true, symbols: true, ambiguous: false };
  const out = h("div", { class: "gen-out" });
  const meter = h("div");
  let current = "";
  const regen = () => {
    current = generatePassword(opts);
    out.textContent = current;
    const s = strength(current);
    meter.replaceChildren(h("div", { class: "meter" }, h("div", { class: `lvl${s.level}`, style: `width:${s.level * 25}%` })),
      h("div", { class: "muted" }, `${s.label} · ~${s.bits} bits`));
  };
  const lenLabel = h("span", {}, String(opts.length));
  const range = h("input", { type: "range", min: 8, max: 64, value: opts.length, class: "grow",
    oninput: () => { opts.length = Number(range.value); lenLabel.textContent = range.value; regen(); } });
  const check = (key, text) => h("label", { class: "row", style: "color:var(--text);font-size:14px" },
    h("input", { type: "checkbox", checked: opts[key], onchange: (e) => { opts[key] = e.target.checked; regen(); } }), text);
  regen();
  render(
    h("div", { class: "toolbar" }, h("button", { onclick: viewList }, "← Volver")),
    h("div", { class: "field" }, out, meter),
    h("div", { class: "row", style: "margin:12px 0" }, h("span", {}, "Longitud"), range, lenLabel),
    h("div", { class: "stack" }, check("upper", "Mayúsculas (A-Z)"), check("digits", "Números (0-9)"),
      check("symbols", "Símbolos (!@#…)"), check("ambiguous", "Incluir caracteres parecidos (l, 1, O, 0)")),
    h("div", { class: "row", style: "margin-top:14px" },
      h("button", { class: "grow", onclick: regen }, "Otra"),
      h("button", { class: "primary grow", onclick: () => copy(current, "Contraseña") }, "Copiar")));
}

function viewSettings() {
  touch();
  const st = S.vault.settings;
  const lockSel = h("select", { onchange: async () => { st.autoLockMin = Number(lockSel.value); await persist(); touch(); toast("Guardado"); } },
    [[1, "1 minuto"], [5, "5 minutos"], [15, "15 minutos"], [60, "1 hora"], [240, "4 horas"], [0, "Solo al cerrar el navegador"]]
      .map(([v, t]) => h("option", { value: v, selected: st.autoLockMin === v }, t)));
  const oldPw = h("input", { type: "password", autocomplete: "current-password", placeholder: "Actual" });
  const newPw = h("input", { type: "password", autocomplete: "new-password", placeholder: "Nueva (mín. 10)" });
  const newPw2 = h("input", { type: "password", autocomplete: "new-password", placeholder: "Repetir nueva" });
  const pwMsg = h("p", { class: "error" });
  render(
    h("div", { class: "toolbar" }, h("button", { onclick: viewList }, "← Volver")),
    h("h2", {}, "Bloqueo automático"),
    lockSel,
    h("h2", {}, "Cambiar contraseña maestra"),
    h("form", { class: "stack", onsubmit: async (e) => {
      e.preventDefault();
      pwMsg.textContent = "";
      try { await open(await deriveKey(oldPw.value, S.salt, S.iterations), S.envelope); }
      catch { return (pwMsg.textContent = "La contraseña actual no es correcta."); }
      if (newPw.value.length < 10) return (pwMsg.textContent = "La nueva debe tener al menos 10 caracteres.");
      if (newPw.value !== newPw2.value) return (pwMsg.textContent = "Las nuevas no coinciden.");
      S.salt = randomBytes(16);
      S.iterations = KDF_ITERATIONS;
      S.key = await deriveKey(newPw.value, S.salt, S.iterations);
      await persist();
      await startSession();
      oldPw.value = newPw.value = newPw2.value = "";
      toast("Contraseña maestra cambiada");
    } }, oldPw, newPw, newPw2, pwMsg, h("button", { type: "submit" }, "Cambiar")),
    h("h2", {}, "Respaldo"),
    h("p", { class: "muted" }, "El archivo queda cifrado con tu contraseña maestra actual."),
    h("div", { class: "row" },
      h("button", { class: "grow", onclick: exportBackup }, "Exportar respaldo"),
      h("button", { class: "grow", onclick: openImportTab }, "Restaurar…")),
    h("h2", {}, "Zona peligrosa"),
    h("button", { class: "danger block", onclick: async () => {
      const t = prompt("Esto borra la bóveda de este navegador. Escribe BORRAR para confirmar.");
      if (t !== "BORRAR") return;
      await chrome.storage.local.remove("vault");
      await chrome.runtime.sendMessage({ type: "lock" });
      S.key = S.vault = S.envelope = null;
      viewSetup();
    } }, "Borrar bóveda"));
}

// ---------- Respaldo ----------
function exportBackup() {
  const blob = new Blob([JSON.stringify(S.envelope, null, 2)], { type: "application/json" });
  const a = h("a", { href: URL.createObjectURL(blob), download: `boveda-cb-${new Date().toISOString().slice(0, 10)}.json` });
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 5000);
  toast("Respaldo descargado");
}
function openImportTab() {
  // El selector de archivos cierra el popup, por eso la restauración se hace en una pestaña.
  chrome.tabs.create({ url: chrome.runtime.getURL("popup.html#import") });
  window.close();
}
function viewImport(isEmpty) {
  const file = h("input", { type: "file", accept: "application/json,.json" });
  const pw = h("input", { type: "password", placeholder: "Contraseña maestra del respaldo", autocomplete: "off" });
  const err = h("p", { class: "error" });
  render(brand("Restaurar respaldo"),
    h("p", {}, isEmpty ? "Elige el archivo de respaldo y escribe su contraseña maestra."
      : h("strong", {}, "Esto reemplaza la bóveda actual de este navegador por la del respaldo.")),
    h("form", { class: "stack", onsubmit: async (e) => {
      e.preventDefault();
      err.textContent = "";
      const f = file.files?.[0];
      if (!f) return (err.textContent = "Elige un archivo.");
      let env;
      try { env = JSON.parse(await f.text()); } catch { return (err.textContent = "El archivo no es JSON válido."); }
      if (!isEnvelope(env)) return (err.textContent = "No parece un respaldo de Bóveda CB.");
      try {
        const key = await deriveKey(pw.value, unb64(env.salt), env.kdf.iterations);
        const vault = await open(key, env);
        if (!Array.isArray(vault.items)) throw new Error("formato");
        await chrome.storage.local.set({ vault: env });
        await chrome.storage.session.remove("sessionKey");
        render(brand("Listo"), h("p", {}, `Restaurados ${vault.items.length} elementos. Ya puedes cerrar esta pestaña y abrir la extensión.`));
      } catch {
        err.textContent = "Contraseña incorrecta o archivo dañado.";
      }
    } }, file, pw, err, h("button", { class: "primary block", type: "submit" }, "Restaurar")));
}

// ---------- Autocompletar ----------
async function fill(item) {
  if (!S.tab || !matchesHost(S.tab.host, hostOf(item.url))) return toast("El sitio no coincide; no se rellena.");
  if (!S.tab.url.startsWith("https:") && !confirm("Esta página NO usa HTTPS. ¿Rellenar de todos modos?")) return;
  try {
    const [res] = await chrome.scripting.executeScript({
      target: { tabId: S.tab.id },
      func: fillCredentials,
      args: [item.username || "", item.password || "", hostOf(item.url)],
    });
    const r = res?.result;
    if (!r?.ok) return toast(r?.reason || "No encontré campos de login.");
    window.close();
  } catch (e) {
    console.error("[boveda] fill", e);
    toast("No se pudo rellenar esta página.");
  }
}

// Se ejecuta DENTRO de la página: debe ser autocontenida.
function fillCredentials(username, password, expectedHost) {
  const host = location.hostname.replace(/^www\./, "").toLowerCase();
  if (!(host === expectedHost || host.endsWith(`.${expectedHost}`))) return { ok: false, reason: "El sitio cambió; no se rellena." };
  const visible = (el) => {
    const r = el.getBoundingClientRect();
    const s = getComputedStyle(el);
    return r.width > 0 && r.height > 0 && s.visibility !== "hidden" && s.display !== "none";
  };
  const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value").set;
  const setVal = (el, v) => {
    el.focus();
    setter.call(el, v);
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
  };
  const inputs = [...document.querySelectorAll("input")].filter((i) => !i.disabled && !i.readOnly && visible(i));
  const isText = (i) => ["text", "email", "tel", ""].includes(i.type);
  const looksUser = (i) => /user|email|login|correo|usuario|account|identifier/i
    .test(`${i.name} ${i.id} ${i.autocomplete} ${i.placeholder} ${i.getAttribute("aria-label") || ""}`);
  const pwd = inputs.find((i) => i.type === "password");
  let user = null;
  if (pwd) {
    const before = inputs.slice(0, inputs.indexOf(pwd)).filter(isText);
    user = before.reverse().find(looksUser) || before[0] || null;
  } else {
    user = inputs.find((i) => isText(i) && (i.type === "email" || i.autocomplete === "username" || looksUser(i))) || null;
  }
  if (!user && !pwd) return { ok: false, reason: "No encontré campos de login." };
  if (user && username) setVal(user, username);
  if (pwd && password) setVal(pwd, password);
  return { ok: true };
}

init().catch((e) => {
  console.error("[boveda] init", e);
  render(h("p", { class: "error" }, "Error al iniciar la bóveda."));
});
