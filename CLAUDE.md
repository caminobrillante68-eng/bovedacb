# CLAUDE.md — Bóveda CB (extensión de Chrome)

Gestor de contraseñas **compartido por el equipo**, como extensión de Chrome Manifest V3. No oficial;
nombre y diseño propios (no imitar marcas de otros gestores). Separado del dashboard `cb-dashboard-metrics`.

## Reglas
- **Cifrado de extremo a extremo**: todo se cifra en la extensión con la clave del equipo antes de salir.
  Supabase (proyecto `bovedacb`, ref `ohubfaeiokgcdomncwym`) solo guarda texto cifrado. Nunca enviar texto
  en claro, la clave del equipo ni la clave derivada al servidor. Ninguna otra llamada de red (CSP `connect-src`).
- **Sin build ni dependencias**: JS de módulos ES plano + Web Crypto + `fetch` (cliente mínimo en
  `lib/supabase.js`, no `@supabase/supabase-js`). Se carga con «Cargar descomprimida».
- **Cripto**: PBKDF2-SHA256 (`KDF_ITERATIONS` en `lib/crypto.js`, hoy 600 000) → AES-256-GCM, IV nuevo por
  cada cifrado. `vault_meta` guarda sal, iteraciones, un verificador cifrado (`CHECK_VALUE`) y `key_version`.
  La clave desbloqueada vive en `chrome.storage.session.sessionKey` ({key, kv, uid}); se borra con el bloqueo
  automático (`background.js`). `chrome.storage.local`: sesión de Supabase (`sb_session`), caché cifrada
  (`cache`) y ajustes por navegador (`settings`).
- **Dos credenciales**: cuenta de Supabase Auth por persona (acceso) + clave del equipo compartida (descifrar).
- **Base de datos** (`supabase/migrations/`, aplicar con el MCP de Supabase `apply_migration`): `team_members`
  (admin/member), `team_invites` (trigger en `auth.users` las convierte en miembros), `vault_meta` (una fila),
  `vault_items` (iv + data cifrados; trigger fija auditoría, sube `version` y rechaza `key_version` vieja con
  `stale_key`). RPC: `my_role`, `invite_member`, `remove_member`, `cancel_invite`, `rotate_team_key` (admin,
  re-cifra todo en una transacción). RLS en todo; `anon` sin permisos. Las cuentas las crea el admin a mano
  en Supabase Auth (con Auto Confirm).
- Edición concurrente: `PATCH ... ?version=eq.N`; si no devuelve fila, es conflicto (no pisar).
- **Permisos mínimos**: `activeTab` + `scripting` para rellenar solo cuando el usuario lo pide. No agregar
  `<all_urls>`, content scripts permanentes ni `tabs` sin pedirlo.
- El relleno (`fillCredentials` en `popup.js`) corre dentro de la página: debe ser autocontenido y volver
  a comprobar el dominio antes de escribir.
- **Nunca `innerHTML` con datos del usuario**: usar el helper `h()` de `popup.js`.
- Interfaz en español; colores con las variables de `popup.css` (claro/oscuro).

## Archivos
- `manifest.json`, `config.js` (URL + clave publicable de Supabase, públicas), `background.js` (bloqueo
  automático), `popup.html/css/js` (toda la UI: login, desbloqueo, lista, detalle, edición, Equipo, Ajustes).
- `lib/crypto.js`, `lib/supabase.js`, `lib/totp.js` (RFC 6238), `lib/generator.js`. `icons/`.
- El selector de archivos cierra el popup: la importación se abre en una pestaña (`popup.html#import`).

## Probar
Chromium headless con `channel: 'chromium'` y `--load-extension`; Node necesita `NODE_USE_ENV_PROXY=1` para
llegar a Supabase desde la nube. Usuarios de prueba: `qa-*@example.test` (crearlos y borrarlos por SQL);
nunca tocar la invitación/cuenta del dueño.
