# CLAUDE.md — Bóveda CB (extensión de Chrome)

Gestor de contraseñas local y cifrado, como extensión de Chrome Manifest V3. No oficial; nombre y
diseño propios (no imitar marcas de otros gestores).

## Reglas
- **Solo local**: los datos no salen del navegador. Nada de servidores, analítica ni llamadas de red.
- **Sin build ni dependencias**: JS de módulos ES plano + Web Crypto. Se carga con «Cargar descomprimida».
- **Cripto**: PBKDF2-SHA256 (`KDF_ITERATIONS` en `lib/crypto.js`, hoy 600 000) → AES-256-GCM, IV nuevo
  en cada guardado. En `chrome.storage.local` solo el sobre cifrado (`vault`). La clave desbloqueada vive
  en `chrome.storage.session` (`sessionKey`), que se borra con el bloqueo automático (`background.js`).
- **Permisos mínimos**: `activeTab` + `scripting` para rellenar solo cuando el usuario lo pide. No agregar
  `<all_urls>`, content scripts permanentes ni `tabs` sin pedirlo.
- El relleno (`fillCredentials` en `popup.js`) corre dentro de la página: debe ser autocontenido y volver
  a comprobar el dominio antes de escribir.
- **Nunca `innerHTML` con datos del usuario**: usar el helper `h()` de `popup.js`.
- Interfaz en español; colores con las variables de `popup.css` (claro/oscuro).

## Archivos
- `manifest.json`, `background.js` (bloqueo automático), `popup.html/css/js` (toda la UI).
- `lib/crypto.js`, `lib/totp.js` (RFC 6238), `lib/generator.js`. `icons/`.
- El selector de archivos cierra el popup: la restauración de respaldos se abre en una pestaña (`popup.html#import`).
