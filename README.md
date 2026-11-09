# Bóveda CB — gestor de contraseñas (extensión de Chrome, no oficial)

Bóveda local y cifrada, estilo gestor de contraseñas. **Independiente del dashboard**: no usa
Supabase ni ningún servidor; los datos nunca salen del navegador.

## Instalar (sin publicar en la Chrome Web Store)
1. Abre `chrome://extensions` y activa **Modo de desarrollador** (arriba a la derecha).
2. **Cargar descomprimida** → elige la carpeta `vault-extension/`.
3. Fija el ícono en la barra. Atajo: `Ctrl+Shift+L` (`⌘+Shift+L` en Mac).

## Qué hace
- Contraseña maestra → crea / desbloquea la bóveda.
- Elementos con título, sitio, usuario, contraseña, código 2FA (TOTP) y notas.
- **Rellenar**: sobre la página de login, abre la extensión y pulsa «Rellenar» en el elemento
  del sitio (se muestra arriba, en «En <sitio>»). Solo rellena si el dominio coincide.
- Generador de contraseñas, medidor de fuerza, búsqueda y copiar al portapapeles
  (se borra a los 30 s si el popup sigue abierto).
- Bloqueo automático (1 min – 4 h, o al cerrar el navegador) y al bloquear la computadora.
- Respaldo cifrado (exportar / restaurar) y cambio de contraseña maestra en ⚙ Ajustes.

## Seguridad
- Clave: PBKDF2-SHA256 con 600 000 iteraciones y sal aleatoria → AES-256-GCM (Web Crypto nativo,
  sin dependencias). En `chrome.storage.local` solo se guarda el sobre cifrado.
- La clave desbloqueada vive en `chrome.storage.session` (en memoria, no accesible a páginas web,
  se borra al cerrar el navegador o al vencer el bloqueo automático).
- Permisos mínimos: sin acceso permanente a los sitios. Solo inyecta el relleno en la pestaña
  activa cuando tú lo pides (`activeTab`), y vuelve a comprobar el dominio dentro de la página
  (protección contra phishing). Avisa si la página no usa HTTPS.
- Sin `innerHTML` con datos del usuario y CSP estricta en las páginas de la extensión.
- **Si olvidas la contraseña maestra, no hay recuperación.** Exporta un respaldo de vez en cuando:
  la bóveda vive en el perfil de Chrome y se pierde si desinstalas la extensión.

## Límites (v0.1)
- Sin sincronización entre dispositivos (usa Exportar/Restaurar para moverla).
- No detecta ni ofrece guardar logins nuevos automáticamente (requeriría permiso sobre todos los sitios).
- El relleno funciona en el marco principal de la página, no dentro de iframes.
