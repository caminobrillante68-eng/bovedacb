// Generador de contraseñas con crypto.getRandomValues (muestreo sin sesgo).

const SETS = {
  lower: "abcdefghijkmnopqrstuvwxyz",
  upper: "ABCDEFGHJKLMNPQRSTUVWXYZ",
  digits: "23456789",
  symbols: "!@#$%^&*()-_=+[]{};:,.?",
};
const AMBIGUOUS = { lower: "l", upper: "IO", digits: "01" };

function randInt(max) {
  const limit = Math.floor(2 ** 32 / max) * max;
  const buf = new Uint32Array(1);
  do crypto.getRandomValues(buf); while (buf[0] >= limit);
  return buf[0] % max;
}

export function generatePassword({ length = 20, upper = true, digits = true, symbols = true, ambiguous = false } = {}) {
  const pools = ["lower", upper && "upper", digits && "digits", symbols && "symbols"]
    .filter(Boolean)
    .map((k) => SETS[k] + (ambiguous ? AMBIGUOUS[k] || "" : ""));
  const all = pools.join("");
  const n = Math.max(length, pools.length);
  // Al menos un carácter de cada grupo elegido; el resto, de todos.
  const chars = pools.map((p) => p[randInt(p.length)]);
  while (chars.length < n) chars.push(all[randInt(all.length)]);
  for (let i = chars.length - 1; i > 0; i--) {
    const j = randInt(i + 1);
    [chars[i], chars[j]] = [chars[j], chars[i]];
  }
  return chars.join("");
}

/** Estimación simple de fuerza: bits de entropía por tamaño del alfabeto usado. */
export function strength(pw) {
  if (!pw) return { bits: 0, label: "—", level: 0 };
  let pool = 0;
  if (/[a-z]/.test(pw)) pool += 26;
  if (/[A-Z]/.test(pw)) pool += 26;
  if (/[0-9]/.test(pw)) pool += 10;
  if (/[^a-zA-Z0-9]/.test(pw)) pool += 32;
  const bits = Math.round(pw.length * Math.log2(pool || 1));
  const level = bits < 40 ? 1 : bits < 60 ? 2 : bits < 80 ? 3 : 4;
  return { bits, level, label: ["—", "Débil", "Regular", "Buena", "Excelente"][level] };
}
