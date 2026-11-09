// Cifrado de la bóveda: PBKDF2-SHA256 (600k iteraciones) → clave AES-256-GCM.
// Todo con Web Crypto nativo; sin dependencias.

const enc = new TextEncoder();
const dec = new TextDecoder();

export const KDF_ITERATIONS = 600_000;

export function b64(bytes) {
  let s = "";
  const u = new Uint8Array(bytes);
  for (let i = 0; i < u.length; i++) s += String.fromCharCode(u[i]);
  return btoa(s);
}

export function unb64(str) {
  const s = atob(str);
  const u = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) u[i] = s.charCodeAt(i);
  return u;
}

export function randomBytes(n) {
  return crypto.getRandomValues(new Uint8Array(n));
}

/** Deriva la clave AES desde la contraseña maestra. Exportable para guardarla en storage.session. */
export async function deriveKey(password, salt, iterations = KDF_ITERATIONS) {
  const base = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations },
    base,
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"],
  );
}

export async function exportKey(key) {
  return b64(await crypto.subtle.exportKey("raw", key));
}

export async function importKey(rawB64) {
  return crypto.subtle.importKey("raw", unb64(rawB64), { name: "AES-GCM" }, true, ["encrypt", "decrypt"]);
}

/** Cifra un objeto JSON. Devuelve el sobre que se guarda en storage.local. */
export async function seal(key, salt, iterations, obj) {
  const iv = randomBytes(12);
  const data = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, enc.encode(JSON.stringify(obj)));
  return {
    v: 1,
    kdf: { name: "PBKDF2", hash: "SHA-256", iterations },
    salt: b64(salt),
    iv: b64(iv),
    data: b64(data),
  };
}

/** Descifra el sobre. Lanza si la clave es incorrecta (falla la etiqueta GCM). */
export async function open(key, envelope) {
  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: unb64(envelope.iv) },
    key,
    unb64(envelope.data),
  );
  return JSON.parse(dec.decode(plain));
}

export function isEnvelope(x) {
  return !!x && x.v === 1 && x.kdf?.name === "PBKDF2" && typeof x.salt === "string"
    && typeof x.iv === "string" && typeof x.data === "string"
    && Number.isInteger(x.kdf.iterations) && x.kdf.iterations >= 100_000;
}

/** Cifra un objeto con la clave dada; IV nuevo cada vez. */
export async function encryptJson(key, obj) {
  const iv = randomBytes(12);
  const data = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, enc.encode(JSON.stringify(obj)));
  return { iv: b64(iv), data: b64(data) };
}

export async function decryptJson(key, iv, data) {
  const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64(iv) }, key, unb64(data));
  return JSON.parse(dec.decode(plain));
}

// Verificador de la clave del equipo: se guarda cifrado en vault_meta.
export const CHECK_VALUE = "bovedacb-check-v1";

/** Parámetros nuevos para una clave del equipo: sal, clave derivada y verificador. */
export async function newTeamKey(password) {
  const salt = randomBytes(16);
  const key = await deriveKey(password, salt, KDF_ITERATIONS);
  const check = await encryptJson(key, CHECK_VALUE);
  return { key, meta: { salt: b64(salt), iterations: KDF_ITERATIONS, check_iv: check.iv, check_data: check.data } };
}

/** Deriva la clave desde vault_meta y la comprueba. Lanza si la contraseña no es correcta. */
export async function unlockTeamKey(password, meta) {
  const key = await deriveKey(password, unb64(meta.salt), meta.iterations);
  if ((await decryptJson(key, meta.check_iv, meta.check_data)) !== CHECK_VALUE) throw new Error("bad_key");
  return key;
}
