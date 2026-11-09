// Cliente mínimo de Supabase (Auth + PostgREST) con fetch, sin dependencias.
import { SUPABASE_URL, SUPABASE_KEY } from "../config.js";

const SESSION = "sb_session";

export class ApiError extends Error {
  constructor(message, status, code) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

async function raw(path, { method = "GET", body, token, headers = {} } = {}) {
  let res;
  try {
    res = await fetch(SUPABASE_URL + path, {
      method,
      headers: {
        apikey: SUPABASE_KEY,
        "content-type": "application/json",
        ...(token ? { authorization: `Bearer ${token}` } : {}),
        ...headers,
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  } catch {
    throw new ApiError("offline", 0, "offline");
  }
  const text = await res.text();
  let json = null;
  try { json = text ? JSON.parse(text) : null; } catch { /* respuesta no JSON */ }
  if (!res.ok) {
    const msg = json?.message || json?.msg || json?.error_description || json?.error || `HTTP ${res.status}`;
    throw new ApiError(msg, res.status, json?.code || json?.error_code);
  }
  return json;
}

async function saveSession(s) {
  const session = {
    access_token: s.access_token,
    refresh_token: s.refresh_token,
    expires_at: s.expires_at || Math.floor(Date.now() / 1000) + (s.expires_in || 3600),
    user: { id: s.user.id, email: s.user.email },
  };
  await chrome.storage.local.set({ [SESSION]: session });
  return session;
}

export async function signIn(email, password) {
  return saveSession(await raw("/auth/v1/token?grant_type=password", { method: "POST", body: { email, password } }));
}

/** Sesión vigente (renueva el token si está por vencer) o null si no hay / fue revocada. */
export async function getSession() {
  const { [SESSION]: s } = await chrome.storage.local.get(SESSION);
  if (!s) return null;
  if (s.expires_at - 60 > Date.now() / 1000) return s;
  try {
    return await saveSession(await raw("/auth/v1/token?grant_type=refresh_token", {
      method: "POST", body: { refresh_token: s.refresh_token },
    }));
  } catch (e) {
    if (e.status >= 400 && e.status < 500) {
      await chrome.storage.local.remove(SESSION);
      return null;
    }
    throw e;
  }
}

export async function signOut() {
  const { [SESSION]: s } = await chrome.storage.local.get(SESSION);
  await chrome.storage.local.remove(SESSION);
  if (s) await raw("/auth/v1/logout", { method: "POST", token: s.access_token }).catch(() => {});
}

export async function api(path, opts = {}) {
  const s = await getSession();
  if (!s) throw new ApiError("no_session", 401, "no_session");
  return raw(path, { ...opts, token: s.access_token });
}

export const rpc = (name, args = {}) => api(`/rest/v1/rpc/${name}`, { method: "POST", body: args });
