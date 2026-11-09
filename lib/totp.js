// Códigos 2FA (TOTP, RFC 6238). Acepta un secreto base32 o un URI otpauth://.

const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

function base32Decode(input) {
  const clean = input.toUpperCase().replace(/[\s=-]/g, "");
  let bits = 0, value = 0;
  const out = [];
  for (const ch of clean) {
    const idx = B32.indexOf(ch);
    if (idx < 0) throw new Error("Secreto 2FA inválido");
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  if (!out.length) throw new Error("Secreto 2FA vacío");
  return new Uint8Array(out);
}

export function parseTotp(raw) {
  const s = (raw || "").trim();
  if (!s) return null;
  if (s.toLowerCase().startsWith("otpauth://")) {
    const u = new URL(s);
    const p = u.searchParams;
    return {
      secret: p.get("secret") || "",
      digits: Number(p.get("digits")) || 6,
      period: Number(p.get("period")) || 30,
      algorithm: (p.get("algorithm") || "SHA1").toUpperCase().replace("SHA", "SHA-"),
    };
  }
  return { secret: s, digits: 6, period: 30, algorithm: "SHA-1" };
}

export async function totp(raw, now = Date.now()) {
  const cfg = parseTotp(raw);
  if (!cfg) return null;
  const key = await crypto.subtle.importKey(
    "raw", base32Decode(cfg.secret), { name: "HMAC", hash: cfg.algorithm }, false, ["sign"],
  );
  const counter = Math.floor(now / 1000 / cfg.period);
  const msg = new ArrayBuffer(8);
  const view = new DataView(msg);
  view.setUint32(0, Math.floor(counter / 2 ** 32));
  view.setUint32(4, counter >>> 0);
  const h = new Uint8Array(await crypto.subtle.sign("HMAC", key, msg));
  const off = h[h.length - 1] & 0x0f;
  const bin = ((h[off] & 0x7f) << 24) | (h[off + 1] << 16) | (h[off + 2] << 8) | h[off + 3];
  const code = String(bin % 10 ** cfg.digits).padStart(cfg.digits, "0");
  const remaining = cfg.period - (Math.floor(now / 1000) % cfg.period);
  return { code, remaining, period: cfg.period };
}
