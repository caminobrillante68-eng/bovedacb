import {
  deriveKey, exportKey, importKey, open, unb64, isEnvelope,
  encryptJson, decryptJson, newTeamKey, unlockTeamKey, CHECK_VALUE,
} from "./lib/crypto.js";
import { totp } from "./lib/totp.js";
import { generatePassword, strength } from "./lib/generator.js";
import { signIn, signOut, getSession, api, rpc, ApiError } from "./lib/supabase.js";

// ---------- Estado ----------
const S = {
  session: null, // { user: { id, email } }
  role: null, // 'admin' | 'member'
  meta: null, // vault_meta (sal, iteraciones, verificador, key_version)
  key: null, // CryptoKey del equipo (solo en memoria / storage.session)
  rows: [], // vault_items cifrados
  items: [], // descifrados
  members: [], // team_members
  offline: false,
  settings: { autoLockMin: 15, clipboardClearSec: 30 },
  tab: null,
  query: "",
  failed: 0,
};
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
  app.replaceChildren(...nodes.flat(2).filter((n) => n != null && n !== false));
  app.querySelector("[autofocus]")?.focus();
}
let toastTimer;
function toast(msg) {
  const t = document.getElementById("toast");
  t.textContent = msg;
  t.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => (t.hidden = true), 2200);
}
let clipTimer;
async function copy(text, what) {
  await navigator.clipboard.writeText(text);
  toast(`${what} copiado`);
  clearTimeout(clipTimer);
  const sec = S.settings.clipboardClearSec;
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
const brand = (subtitle) =>
  h("div", { class: "brand" }, h("img", { src: "icons/48.png", alt: "" }),
    h("div", {}, h("h1", {}, "Bóveda CB"), subtitle && h("div", { class: "muted" }, subtitle)));
const emailOf = (uid) => S.members.find((m) => m.user_id === uid)?.email || "alguien que ya no está en el equipo";
const meter = (pw) => {
  const s = strength(pw);
  return [h("div", { class: "meter" }, h("div", { class: `lvl${s.level}`, style: `width:${s.level * 25}%` })),
    h("div", { class: "muted" }, pw ? `${s.label} · ~${s.bits} bits` : "")];
};

const ERRORS = {
  offline: "Sin conexión. Inténtalo de nuevo cuando tengas internet.",
  not_admin: "Solo un admin del equipo puede hacer esto.",
  last_admin: "No puedes quitar al último admin del equipo.",
  bad_email: "Email no válido.",
  stale_key: "La clave del equipo cambió. Desbloquea con la nueva.",
  key_changed: "La clave del equipo cambió mientras tanto. Vuelve a intentarlo.",
  items_changed: "Alguien modificó la bóveda mientras tanto. Vuelve a intentarlo.",
  no_session: "Tu sesión terminó. Vuelve a entrar.",
};
function errMsg(e) {
  const m = e?.message || "";
  if (ERRORS[m]) return ERRORS[m];
  if (ERRORS[e?.code]) return ERRORS[e.code];
  if (/invalid login credentials|invalid_credentials/i.test(m + e?.code)) return "Email o contraseña incorrectos.";
  if (/email not confirmed/i.test(m)) return "Tu email no está confirmado. Pide al admin que lo confirme en Supabase.";
  if (e?.status === 429) return "Demasiados intentos. Espera un momento.";
  console.error("[boveda]", e);
  return "Algo salió mal. Inténtalo de nuevo.";
}
async function guard(fn) {
  try {
    return await fn();
  } catch (e) {
    if (e?.message === "stale_key") return lockKey("La clave del equipo cambió. Desbloquea con la nueva.");
    if (e?.code === "no_session") return viewLogin(ERRORS.no_session);
    toast(errMsg(e));
  }
}

// ---------- Sesión de la clave (bloqueo automático en background.js) ----------
async function saveKeySession() {
  await chrome.storage.session.set({
    sessionKey: { key: await exportKey(S.key), kv: S.meta.key_version, uid: S.session.user.id },
  });
  touch();
}
function touch() {
  const min = S.settings.autoLockMin;
  if (min > 0) chrome.alarms.create("autolock", { delayInMinutes: min });
  else chrome.alarms.clear("autolock");
}
async function lockKey(message) {
  await chrome.runtime.sendMessage({ type: "lock" });
  S.key = null;
  S.items = [];
  // La clave pudo haber cambiado (rotación): traer la sal/verificador actuales.
  try {
    if (!(await loadTeam())) return viewNoAccess();
  } catch { /* sin conexión: se usa lo que ya hay */ }
  viewUnlock(message);
}

// ---------- Datos del equipo ----------
async function saveCache() {
  await chrome.storage.local.set({
    cache: { uid: S.session.user.id, role: S.role, meta: S.meta, rows: S.rows, members: S.members, at: Date.now() },
  });
}
async function clearLocal() {
  await chrome.storage.local.remove("cache");
  await chrome.storage.session.remove("sessionKey");
}
/** Carga rol, meta y miembros. Sin conexión usa la caché (solo lectura). */
async function loadTeam() {
  try {
    S.role = await rpc("my_role");
    if (!S.role) return false;
    const [meta, members] = await Promise.all([
      api("/rest/v1/vault_meta?select=*"),
      api("/rest/v1/team_members?select=user_id,email,role&order=email"),
    ]);
    S.meta = meta[0] || null;
    S.members = members;
    S.offline = false;
    return true;
  } catch (e) {
    if (e.code !== "offline") throw e;
    const { cache } = await chrome.storage.local.get("cache");
    if (!cache || cache.uid !== S.session.user.id) throw e;
    Object.assign(S, { role: cache.role, meta: cache.meta, members: cache.members, rows: cache.rows, offline: true });
    return true;
  }
}
async function loadItems() {
  if (!S.offline) {
    S.rows = await api("/rest/v1/vault_items?select=*&order=updated_at.desc");
    await saveCache();
  }
  const out = [];
  for (const r of S.rows) {
    try {
      out.push(rowToItem(r, await decryptJson(S.key, r.iv, r.data)));
    } catch {
      console.error("[boveda] no se pudo descifrar", r.id);
    }
  }
  S.items = out;
}
const rowToItem = (r, data) => ({
  ...data, id: r.id, version: r.version, updatedAt: r.updated_at, updatedBy: r.updated_by, createdBy: r.created_by,
});
const ITEM_FIELDS = ["title", "url", "username", "password", "totp", "notes"];
const pickFields = (o) => Object.fromEntries(ITEM_FIELDS.map((k) => [k, (o[k] || "").toString()]));

async function upsertItem(draft, existing) {
  const enc = await encryptJson(S.key, pickFields(draft));
  const body = { iv: enc.iv, data: enc.data, key_version: S.meta.key_version };
  const headers = { prefer: "return=representation" };
  let row;
  if (existing) {
    [row] = await api(`/rest/v1/vault_items?id=eq.${existing.id}&version=eq.${existing.version}`,
      { method: "PATCH", body, headers });
    if (!row) {
      await loadItems();
      throw new Error("conflict");
    }
  } else {
    [row] = await api("/rest/v1/vault_items", { method: "POST", body, headers });
  }
  S.rows = [row, ...S.rows.filter((r) => r.id !== row.id)];
  await saveCache();
  const item = rowToItem(row, pickFields(draft));
  S.items = [item, ...S.items.filter((i) => i.id !== row.id)];
  return item;
}

// ---------- Inicio ----------
async function init() {
  const { settings } = await chrome.storage.local.get("settings");
  Object.assign(S.settings, settings);
  if (!IN_TAB) {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab?.url && /^https?:/.test(tab.url)) S.tab = { id: tab.id, url: tab.url, host: hostOf(tab.url) };
  }
  S.session = await getSession().catch(() => null);
  if (!S.session) {
    // Sin conexión con sesión guardada: getSession falla al renovar; intentar con la caché.
    const { sb_session: stored } = await chrome.storage.local.get("sb_session");
    if (!stored) return viewLogin();
    S.session = stored;
  }
  await afterLogin();
}

async function afterLogin() {
  render(brand("Cargando…"));
  let ok;
  try {
    ok = await loadTeam();
  } catch (e) {
    if (e.code === "no_session" || e.status === 401) return viewLogin(ERRORS.no_session);
    return render(brand("Error"), h("p", { class: "error" }, errMsg(e)),
      h("button", { class: "block", onclick: afterLogin }, "Reintentar"));
  }
  if (!ok) return viewNoAccess();
  if (!S.meta) return S.role === "admin" ? viewCreateTeamVault() : viewWaiting();
  const { sessionKey } = await chrome.storage.session.get("sessionKey");
  if (sessionKey && sessionKey.kv === S.meta.key_version && sessionKey.uid === S.session.user.id) {
    try {
      S.key = await importKey(sessionKey.key);
      if ((await decryptJson(S.key, S.meta.check_iv, S.meta.check_data)) !== CHECK_VALUE) throw new Error("bad_key");
      await loadItems();
      touch();
      return IN_TAB ? viewImport() : viewList();
    } catch (e) {
      if (e instanceof ApiError) return viewLogin(errMsg(e));
      await chrome.storage.session.remove("sessionKey");
    }
  }
  viewUnlock(sessionKey && sessionKey.kv !== S.meta.key_version ? "La clave del equipo cambió. Pide la nueva al admin." : "");
}

// ---------- Vistas: acceso ----------
function viewLogin(message = "") {
  const email = h("input", { type: "email", autocomplete: "username", autofocus: true, required: true, placeholder: "tu@email.com" });
  const pw = h("input", { type: "password", autocomplete: "current-password", required: true });
  const err = h("p", { class: "error" }, message);
  const btn = h("button", { class: "primary block", type: "submit" }, "Entrar");
  render(brand("Bóveda del equipo"),
    h("form", { class: "stack", onsubmit: async (e) => {
      e.preventDefault();
      btn.disabled = true;
      err.textContent = "";
      try {
        S.session = await signIn(email.value.trim(), pw.value);
        await afterLogin();
      } catch (ex) {
        err.textContent = errMsg(ex);
        btn.disabled = false;
      }
    } },
    h("div", {}, h("label", {}, "Email"), email),
    h("div", {}, h("label", {}, "Contraseña de tu cuenta"), pw),
    err, btn),
    h("p", { class: "muted", style: "margin-top:14px" },
      "¿No tienes cuenta? Pide al admin del equipo que te invite."));
}

function viewNoAccess() {
  clearLocal();
  render(brand(S.session.user.email),
    h("p", {}, "Tu cuenta no forma parte del equipo (o te quitaron el acceso)."),
    h("p", { class: "muted" }, "Pide a un admin que te invite desde la pestaña Equipo."),
    h("button", { class: "block", onclick: logout }, "Cerrar sesión"));
}

function viewWaiting() {
  render(brand(S.session.user.email),
    h("p", {}, "Ya estás en el equipo, pero la bóveda todavía no se creó."),
    h("p", { class: "muted" }, "Un admin debe abrir la extensión y crear la clave del equipo."),
    h("div", { class: "row" },
      h("button", { class: "grow", onclick: afterLogin }, "Reintentar"),
      h("button", { class: "grow", onclick: logout }, "Cerrar sesión")));
}

function viewCreateTeamVault() {
  const p1 = h("input", { type: "password", autocomplete: "new-password", autofocus: true });
  const p2 = h("input", { type: "password", autocomplete: "new-password" });
  const m = h("div");
  p1.addEventListener("input", () => m.replaceChildren(...meter(p1.value)));
  const err = h("p", { class: "error" });
  const btn = h("button", { class: "primary block", type: "submit" }, "Crear bóveda del equipo");
  render(brand("Crear bóveda del equipo"),
    h("p", {}, "Elige la ", h("strong", {}, "clave del equipo"), ": la contraseña que todos usarán para desbloquear. ",
      "Se la darás a cada persona en privado (en persona o por llamada, no por chat)."),
    h("p", { class: "muted" }, "Nadie puede recuperarla, ni siquiera Supabase: guárdala en un lugar seguro."),
    h("form", { class: "stack", onsubmit: async (e) => {
      e.preventDefault();
      err.textContent = "";
      if (p1.value.length < 12) return (err.textContent = "Usa al menos 12 caracteres (mejor una frase larga).");
      if (p1.value !== p2.value) return (err.textContent = "Las claves no coinciden.");
      btn.disabled = true;
      btn.textContent = "Creando…";
      try {
        const { key, meta } = await newTeamKey(p1.value);
        const [row] = await api("/rest/v1/vault_meta", {
          method: "POST", body: { ...meta, key_version: 1 }, headers: { prefer: "return=representation" },
        });
        S.meta = row;
        S.key = key;
        S.rows = [];
        S.items = [];
        await saveCache();
        await saveKeySession();
        viewList();
      } catch (ex) {
        err.textContent = ex.status === 409 ? "Otro admin ya creó la bóveda. Cierra y vuelve a abrir." : errMsg(ex);
        btn.disabled = false;
        btn.textContent = "Crear bóveda del equipo";
      }
    } },
    h("div", {}, h("label", {}, "Clave del equipo"), p1, m),
    h("div", {}, h("label", {}, "Repetir clave"), p2),
    err, btn));
}

function viewUnlock(message = "") {
  const pw = h("input", { type: "password", autocomplete: "current-password", autofocus: true, placeholder: "Clave del equipo" });
  const err = h("p", { class: "error" }, message);
  const btn = h("button", { class: "primary block", type: "submit" }, "Desbloquear");
  render(brand(S.session.user.email + (S.offline ? " · sin conexión" : "")),
    h("form", { class: "stack", onsubmit: async (e) => {
      e.preventDefault();
      if (!pw.value) return;
      btn.disabled = true;
      btn.textContent = "Verificando…";
      err.textContent = "";
      try {
        try {
          S.key = await unlockTeamKey(pw.value, S.meta);
        } catch (first) {
          // Quizá la clave rotó desde que se cargó la vista: reintentar con los datos actuales.
          if (S.offline || !(await loadTeam().catch(() => false)) || !S.meta) throw first;
          S.key = await unlockTeamKey(pw.value, S.meta);
        }
      } catch {
        S.failed++;
        await new Promise((r) => setTimeout(r, Math.min(S.failed, 5) * 400));
        err.textContent = "Clave del equipo incorrecta.";
        btn.disabled = false;
        btn.textContent = "Desbloquear";
        return pw.select();
      }
      S.failed = 0;
      await saveKeySession();
      await guard(loadItems);
      IN_TAB ? viewImport() : viewList();
    } }, pw, err, btn),
    h("p", { class: "muted", style: "margin-top:14px" }, "¿No la tienes? Pídela a un admin del equipo. ",
      h("a", { href: "#", onclick: (e) => { e.preventDefault(); logout(); } }, "Cerrar sesión")));
}

async function logout() {
  await chrome.runtime.sendMessage({ type: "lock" });
  await clearLocal();
  await signOut();
  Object.assign(S, { session: null, role: null, meta: null, key: null, rows: [], items: [], members: [] });
  viewLogin();
}

// ---------- Vistas: bóveda ----------
function itemRow(item, { showFill }) {
  const actions = h("div", { class: "row" });
  if (showFill) actions.append(h("button", { class: "primary icon", title: "Rellenar en esta página",
    onclick: (e) => { e.stopPropagation(); fill(item); } }, "Rellenar"));
  if (item.username) actions.append(h("button", { class: "icon", title: "Copiar usuario",
    onclick: (e) => { e.stopPropagation(); copy(item.username, "Usuario"); } }, "👤"));
  if (item.password) actions.append(h("button", { class: "icon", title: "Copiar contraseña",
    onclick: (e) => { e.stopPropagation(); copy(item.password, "Contraseña"); } }, "🔑"));
  return h("li", { class: "item", tabIndex: 0, onclick: () => viewDetail(item.id),
    onkeydown: (e) => { if (e.key === "Enter") viewDetail(item.id); } },
    h("div", { class: "avatar", "aria-hidden": "true" }, (item.title || hostOf(item.url) || "?")[0]),
    h("div", { class: "grow" }, h("div", { class: "title" }, item.title || hostOf(item.url) || "(sin título)"),
      h("div", { class: "sub" }, item.username || hostOf(item.url))),
    actions);
}

function viewList() {
  touch();
  const search = h("input", { type: "search", placeholder: "Buscar…", value: S.query, autofocus: true, "aria-label": "Buscar" });
  const listBox = h("div");
  const draw = () => {
    const q = S.query.trim().toLowerCase();
    const items = [...S.items].sort((a, b) => (a.title || "").localeCompare(b.title || "", "es"));
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
      out.push(h("ul", { class: "list" }, filtered.map((i) => itemRow(i, { showFill: matchesHost(S.tab?.host, hostOf(i.url)) }))));
    }
    listBox.replaceChildren(...out);
  };
  search.addEventListener("input", () => { S.query = search.value; draw(); });
  search.addEventListener("keydown", (e) => { if (e.key === "Enter") app.querySelector(".item")?.click(); });
  draw();
  render(
    S.offline && h("p", { class: "muted" }, "Sin conexión: solo lectura con la última copia."),
    h("div", { class: "toolbar" },
      h("button", { class: "primary", disabled: S.offline, onclick: () => viewEdit(null) }, "+ Nuevo"),
      h("button", { onclick: () => viewGenerator() }, "Generador"),
      h("div", { class: "grow" }),
      h("button", { class: "icon", title: "Actualizar", disabled: S.offline,
        onclick: () => guard(async () => { await loadItems(); draw(); toast("Actualizado"); }) }, "↻"),
      h("button", { class: "icon", title: "Equipo", onclick: () => viewTeam() }, "👥"),
      h("button", { class: "icon", title: "Ajustes", onclick: () => viewSettings() }, "⚙"),
      h("button", { class: "icon", title: "Bloquear", onclick: () => lockKey() }, "🔒")),
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
  const item = S.items.find((i) => i.id === id);
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
      h("button", { disabled: S.offline, onclick: () => { clearInterval(totpTimer); viewEdit(item.id); } }, "Editar")),
    h("div", { class: "row", style: "margin-bottom:10px" },
      h("div", { class: "avatar", "aria-hidden": "true" }, (item.title || host || "?")[0]),
      h("div", { class: "grow" }, h("div", { class: "title" }, item.title || host || "(sin título)"),
        h("div", { class: "sub" }, `Modificado ${new Date(item.updatedAt).toLocaleString("es")} por ${emailOf(item.updatedBy)}`))),
    h("div", { class: "stack" }, parts));
}

function viewEdit(id) {
  touch();
  const existing = id ? S.items.find((i) => i.id === id) : null;
  const draft = existing ? { ...existing } : {
    title: S.tab?.host || "", url: S.tab ? new URL(S.tab.url).origin : "", username: "", password: "", totp: "", notes: "",
  };
  const inp = (name, attrs = {}) => {
    const el = h(attrs.multiline ? "textarea" : "input", { ...attrs, multiline: null, value: draft[name] || "" });
    el.addEventListener("input", () => (draft[name] = el.value));
    return el;
  };
  const pass = inp("password", { type: "password", autocomplete: "off", spellcheck: false });
  const m = h("div");
  const updMeter = () => m.replaceChildren(...meter(pass.value));
  pass.addEventListener("input", updMeter);
  updMeter();
  const err = h("p", { class: "error" });
  const saveBtn = h("button", { class: "primary block", type: "submit" }, existing ? "Guardar cambios" : "Guardar");
  const save = async (e) => {
    e.preventDefault();
    err.textContent = "";
    if (!draft.title.trim() && !draft.url.trim()) return (err.textContent = "Pon al menos un título o un sitio.");
    if (draft.totp?.trim()) {
      try { await totp(draft.totp); } catch { return (err.textContent = "El secreto 2FA no es válido (base32 u otpauth://)."); }
    }
    saveBtn.disabled = true;
    try {
      const item = await upsertItem(draft, existing);
      toast("Guardado para todo el equipo");
      viewDetail(item.id);
    } catch (ex) {
      saveBtn.disabled = false;
      if (ex.message === "conflict") {
        err.textContent = "Otra persona cambió este elemento mientras editabas. Vuelve a abrirlo para ver su versión.";
      } else if (ex.message === "stale_key") {
        lockKey(ERRORS.stale_key);
      } else {
        err.textContent = errMsg(ex);
      }
    }
  };
  render(
    h("div", { class: "toolbar" },
      h("button", { onclick: () => (existing ? viewDetail(existing.id) : viewList()) }, "← Cancelar"),
      h("div", { class: "grow" }),
      existing && h("button", { class: "danger", onclick: () => guard(async () => {
        if (!confirm(`¿Eliminar «${existing.title || hostOf(existing.url)}» para TODO el equipo? No se puede deshacer.`)) return;
        await api(`/rest/v1/vault_items?id=eq.${existing.id}`, { method: "DELETE" });
        S.rows = S.rows.filter((r) => r.id !== existing.id);
        S.items = S.items.filter((i) => i.id !== existing.id);
        await saveCache();
        toast("Eliminado");
        viewList();
      }) }, "Eliminar")),
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
        m),
      h("div", {}, h("label", {}, "Secreto 2FA (opcional)"), inp("totp", { placeholder: "JBSWY3DP… u otpauth://…", spellcheck: false })),
      h("div", {}, h("label", {}, "Notas"), inp("notes", { multiline: true })),
      err, saveBtn));
}

function viewGenerator() {
  touch();
  const opts = { length: 20, upper: true, digits: true, symbols: true, ambiguous: false };
  const out = h("div", { class: "gen-out" });
  const m = h("div");
  let current = "";
  const regen = () => {
    current = generatePassword(opts);
    out.textContent = current;
    m.replaceChildren(...meter(current));
  };
  const lenLabel = h("span", {}, String(opts.length));
  const range = h("input", { type: "range", min: 8, max: 64, value: opts.length, class: "grow",
    oninput: () => { opts.length = Number(range.value); lenLabel.textContent = range.value; regen(); } });
  const check = (key, text) => h("label", { class: "row", style: "color:var(--text);font-size:14px" },
    h("input", { type: "checkbox", checked: opts[key], onchange: (e) => { opts[key] = e.target.checked; regen(); } }), text);
  regen();
  render(
    h("div", { class: "toolbar" }, h("button", { onclick: viewList }, "← Volver")),
    h("div", { class: "field" }, out, m),
    h("div", { class: "row", style: "margin:12px 0" }, h("span", {}, "Longitud"), range, lenLabel),
    h("div", { class: "stack" }, check("upper", "Mayúsculas (A-Z)"), check("digits", "Números (0-9)"),
      check("symbols", "Símbolos (!@#…)"), check("ambiguous", "Incluir caracteres parecidos (l, 1, O, 0)")),
    h("div", { class: "row", style: "margin-top:14px" },
      h("button", { class: "grow", onclick: regen }, "Otra"),
      h("button", { class: "primary grow", onclick: () => copy(current, "Contraseña") }, "Copiar")));
}

// ---------- Equipo ----------
async function viewTeam() {
  touch();
  const isAdmin = S.role === "admin";
  let invites = [];
  if (isAdmin && !S.offline) {
    const r = await guard(async () => {
      S.members = await api("/rest/v1/team_members?select=user_id,email,role&order=email");
      return api("/rest/v1/team_invites?select=email,role&order=email");
    });
    if (r === undefined) return;
    invites = r;
  }
  const me = S.session.user.id;
  const memberRow = (mb) => h("li", { class: "item", style: "cursor:default" },
    h("div", { class: "avatar", "aria-hidden": "true" }, mb.email[0]),
    h("div", { class: "grow" }, h("div", { class: "title" }, mb.email + (mb.user_id === me ? " (tú)" : "")),
      h("div", { class: "sub" }, mb.role === "admin" ? "Admin" : "Miembro")),
    isAdmin && !S.offline && mb.user_id !== me && h("button", { class: "icon danger", onclick: () => guard(async () => {
      if (!confirm(`¿Quitar a ${mb.email} del equipo?\n\nDeja de poder descargar la bóveda. Como conoce la clave del equipo, `
        + "conviene cambiarla después (Ajustes) y cambiar las contraseñas importantes.")) return;
      await rpc("remove_member", { p_user: mb.user_id });
      toast("Quitado del equipo");
      viewTeam();
    }) }, "Quitar"));
  const inviteRow = (iv) => h("li", { class: "item", style: "cursor:default" },
    h("div", { class: "avatar", "aria-hidden": "true", style: "opacity:.5" }, iv.email[0]),
    h("div", { class: "grow" }, h("div", { class: "title" }, iv.email),
      h("div", { class: "sub" }, `Invitado (${iv.role === "admin" ? "admin" : "miembro"}) · falta crear su usuario`)),
    h("button", { class: "icon", onclick: () => guard(async () => {
      await rpc("cancel_invite", { p_email: iv.email });
      viewTeam();
    }) }, "Cancelar"));
  const email = h("input", { type: "email", placeholder: "email@ejemplo.com", required: true });
  const role = h("select", { style: "width:auto;flex:none" }, h("option", { value: "member" }, "Miembro"), h("option", { value: "admin" }, "Admin"));
  const msg = h("p", { class: "muted" });
  render(
    h("div", { class: "toolbar" }, h("button", { onclick: viewList }, "← Volver")),
    h("h2", {}, `Miembros (${S.members.length})`),
    h("ul", { class: "list" }, S.members.map(memberRow)),
    invites.length > 0 && [h("h2", {}, "Invitaciones pendientes"), h("ul", { class: "list" }, invites.map(inviteRow))],
    isAdmin && !S.offline && [
      h("h2", {}, "Invitar"),
      h("form", { class: "stack", onsubmit: (e) => {
        e.preventDefault();
        guard(async () => {
          const r = await rpc("invite_member", { p_email: email.value, p_role: role.value });
          if (r === "added") {
            toast("Agregado al equipo");
            return viewTeam();
          }
          await viewTeam();
          toast("Invitación creada");
        });
      } }, h("div", { class: "row" }, h("div", { class: "grow" }, email), role),
      h("button", { class: "primary block", type: "submit" }, "Invitar")),
      msg,
      h("p", { class: "muted" },
        "Después crea su usuario en Supabase → Authentication → Users → Add user → Create new user ",
        "(con el mismo email, una contraseña inicial y «Auto Confirm User» marcado). ",
        "Al crearlo entra solo al equipo. Pásale en privado su contraseña de cuenta y la clave del equipo."),
    ],
    !isAdmin && h("p", { class: "muted" }, "Solo un admin puede invitar o quitar personas."));
}

// ---------- Ajustes ----------
function viewSettings() {
  touch();
  const st = S.settings;
  const saveSettings = async () => { await chrome.storage.local.set({ settings: st }); touch(); toast("Guardado"); };
  const lockSel = h("select", { onchange: () => { st.autoLockMin = Number(lockSel.value); saveSettings(); } },
    [[1, "1 minuto"], [5, "5 minutos"], [15, "15 minutos"], [60, "1 hora"], [240, "4 horas"], [0, "Solo al cerrar el navegador"]]
      .map(([v, t]) => h("option", { value: v, selected: st.autoLockMin === v }, t)));
  const isAdmin = S.role === "admin";
  const cur = h("input", { type: "password", autocomplete: "off", placeholder: "Clave actual del equipo" });
  const n1 = h("input", { type: "password", autocomplete: "new-password", placeholder: "Nueva clave (mín. 12)" });
  const n2 = h("input", { type: "password", autocomplete: "new-password", placeholder: "Repetir nueva" });
  const rotMsg = h("p", { class: "error" });
  const rotBtn = h("button", { type: "submit" }, "Cambiar clave del equipo");
  render(
    h("div", { class: "toolbar" }, h("button", { onclick: viewList }, "← Volver")),
    h("p", { class: "muted" }, `Sesión: ${S.session.user.email} · ${isAdmin ? "admin" : "miembro"}`),
    h("h2", {}, "Bloqueo automático (este navegador)"),
    lockSel,
    isAdmin && !S.offline && [
      h("h2", {}, "Cambiar clave del equipo"),
      h("p", { class: "muted" }, "Re-cifra toda la bóveda. Hazlo al sacar a alguien del equipo. "
        + "Todos tendrán que desbloquear con la nueva clave."),
      h("form", { class: "stack", onsubmit: async (e) => {
        e.preventDefault();
        rotMsg.textContent = "";
        try { await unlockTeamKey(cur.value, S.meta); } catch { return (rotMsg.textContent = "La clave actual no es correcta."); }
        if (n1.value.length < 12) return (rotMsg.textContent = "La nueva debe tener al menos 12 caracteres.");
        if (n1.value !== n2.value) return (rotMsg.textContent = "Las nuevas no coinciden.");
        rotBtn.disabled = true;
        rotBtn.textContent = "Re-cifrando…";
        try {
          await rotateKey(n1.value);
          cur.value = n1.value = n2.value = "";
          toast("Clave del equipo cambiada");
        } catch (ex) {
          rotMsg.textContent = errMsg(ex);
        }
        rotBtn.disabled = false;
        rotBtn.textContent = "Cambiar clave del equipo";
      } }, cur, n1, n2, rotMsg, rotBtn),
    ],
    h("h2", {}, "Respaldo"),
    h("p", { class: "muted" }, "El archivo queda cifrado con la clave del equipo actual."),
    h("div", { class: "row" },
      h("button", { class: "grow", onclick: exportBackup }, "Exportar respaldo"),
      h("button", { class: "grow", disabled: S.offline, onclick: openImportTab }, "Importar…")),
    h("h2", {}, "Cuenta"),
    h("button", { class: "block", onclick: logout }, "Cerrar sesión en este navegador"));
}

async function rotateKey(newPassword) {
  // Trae la versión más reciente para no perder cambios de otros.
  const rows = await api("/rest/v1/vault_items?select=*");
  const plain = [];
  for (const r of rows) plain.push({ id: r.id, data: await decryptJson(S.key, r.iv, r.data) });
  const { key, meta } = await newTeamKey(newPassword);
  const items = [];
  for (const p of plain) items.push({ id: p.id, ...(await encryptJson(key, p.data)) });
  const kv = await rpc("rotate_team_key", {
    p_salt: meta.salt, p_iterations: meta.iterations, p_check_iv: meta.check_iv, p_check_data: meta.check_data,
    p_expected_key_version: S.meta.key_version, p_items: items,
  });
  S.meta = { ...S.meta, ...meta, key_version: kv };
  S.key = key;
  await saveKeySession();
  await loadItems();
}

// ---------- Respaldo / importación ----------
function exportBackup() {
  const file = {
    v: 2, kind: "bovedacb-team", exported_at: new Date().toISOString(),
    meta: { salt: S.meta.salt, iterations: S.meta.iterations, check_iv: S.meta.check_iv, check_data: S.meta.check_data },
    items: S.rows.filter((r) => r.key_version === S.meta.key_version).map((r) => ({ iv: r.iv, data: r.data })),
  };
  const blob = new Blob([JSON.stringify(file, null, 2)], { type: "application/json" });
  const a = h("a", { href: URL.createObjectURL(blob), download: `boveda-equipo-${new Date().toISOString().slice(0, 10)}.json` });
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 5000);
  toast("Respaldo descargado");
}
function openImportTab() {
  // El selector de archivos cierra el popup, por eso la importación se hace en una pestaña.
  chrome.tabs.create({ url: chrome.runtime.getURL("popup.html#import") });
  window.close();
}
/** Descifra un archivo de respaldo (equipo v2 o bóveda local v1) y devuelve los elementos en claro. */
async function readBackup(file, password) {
  if (file?.kind === "bovedacb-team" && file.v === 2 && file.meta && Array.isArray(file.items)) {
    const key = await unlockTeamKey(password, file.meta);
    const out = [];
    for (const it of file.items) out.push(await decryptJson(key, it.iv, it.data));
    return out;
  }
  if (isEnvelope(file)) {
    const key = await deriveKey(password, unb64(file.salt), file.kdf.iterations);
    const vault = await open(key, file);
    if (!Array.isArray(vault.items)) throw new Error("formato");
    return vault.items;
  }
  throw new Error("not_backup");
}
async function viewImport() {
  const { vault: localVault } = await chrome.storage.local.get("vault"); // bóveda local de la versión 0.1
  const file = h("input", { type: "file", accept: "application/json,.json" });
  const pw = h("input", { type: "password", placeholder: "Contraseña con la que se cifró", autocomplete: "off" });
  const err = h("p", { class: "error" });
  const btn = h("button", { class: "primary block", type: "submit" }, "Importar al equipo");
  const run = async (data) => {
    let items;
    try {
      items = await readBackup(data, pw.value);
    } catch (e) {
      return (err.textContent = e.message === "not_backup" ? "No parece un respaldo de Bóveda CB." : "Contraseña incorrecta o archivo dañado.");
    }
    btn.disabled = true;
    btn.textContent = `Importando ${items.length}…`;
    let n = 0;
    try {
      for (const it of items) {
        await upsertItem(pickFields(it), null);
        n++;
      }
      render(brand("Listo"), h("p", {}, `Se importaron ${n} elementos a la bóveda del equipo. Ya puedes cerrar esta pestaña.`));
    } catch (e) {
      err.textContent = `Se importaron ${n} de ${items.length}. ${errMsg(e)}`;
      btn.disabled = false;
      btn.textContent = "Importar al equipo";
    }
  };
  render(brand("Importar a la bóveda del equipo"),
    h("p", {}, "Los elementos se agregan a la bóveda compartida (no reemplazan lo que ya hay)."),
    localVault && h("div", { class: "field", style: "margin-bottom:12px" },
      h("p", {}, "Este navegador tiene una bóveda personal de la versión anterior."),
      h("button", { class: "block", onclick: () => run(localVault) }, "Importar mi bóveda anterior (usa su contraseña maestra)")),
    h("form", { class: "stack", onsubmit: async (e) => {
      e.preventDefault();
      err.textContent = "";
      const f = file.files?.[0];
      if (!f) return (err.textContent = "Elige un archivo.");
      let data;
      try { data = JSON.parse(await f.text()); } catch { return (err.textContent = "El archivo no es JSON válido."); }
      await run(data);
    } }, h("div", {}, h("label", {}, "Archivo de respaldo"), file), pw, err, btn));
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
