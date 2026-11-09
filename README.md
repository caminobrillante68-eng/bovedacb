# Bóveda CB — contraseñas compartidas del equipo (extensión de Chrome, no oficial)

Todo el equipo ve y usa las mismas contraseñas. Se cifran **en el navegador** con la clave del
equipo antes de subirse a Supabase: el servidor solo guarda texto cifrado y nunca ve la clave.

## Dos contraseñas distintas
| | Para qué | Quién la tiene |
|---|---|---|
| **Contraseña de tu cuenta** | Entrar (email + contraseña). Sin cuenta del equipo no se descarga nada. | Cada persona la suya |
| **Clave del equipo** | Desbloquear y descifrar la bóveda. | La misma para todos; la da el admin en privado |

## Primera vez (admin)
1. En Supabase → proyecto **bovedacb** → *Authentication → Users → Add user → Create new user*:
   tu email (el que ya está invitado como admin), una contraseña, y marca **Auto Confirm User**.
2. Recomendado: *Authentication → Sign In / Providers* → desactiva **Allow new users to sign up**
   (las cuentas las creas tú; así nadie de fuera puede registrarse).
3. Instala la extensión (abajo), entra con tu cuenta y crea la **clave del equipo**.

## Agregar a alguien
1. En la extensión → 👥 Equipo → **Invitar** con su email (Miembro o Admin).
2. En Supabase → *Authentication → Users → Add user*: mismo email, una contraseña inicial,
   **Auto Confirm User** marcado. Al crearse, entra solo al equipo.
3. Pásale en privado su contraseña de cuenta y la clave del equipo, y el ZIP de la extensión.

## Sacar a alguien
👥 Equipo → **Quitar**. Deja de poder descargar la bóveda al instante y su extensión borra la copia
local. Como conocía la clave del equipo, después ve a ⚙ Ajustes → **Cambiar clave del equipo**
(re-cifra todo) y cambia las contraseñas más importantes.

## Instalar en cada computadora
1. Descarga el repo (GitHub → *Code → Download ZIP*) y descomprímelo; o comparte ese ZIP con el equipo.
2. `chrome://extensions` → activa **Modo de desarrollador** → **Cargar descomprimida** → elige la carpeta.
3. Fija el ícono. Atajo: `Ctrl+Shift+L` (`⌘+Shift+L` en Mac).

## Qué hace
- Elementos con título, sitio, usuario, contraseña, código 2FA (TOTP) y notas; quién y cuándo lo cambió.
- **Rellenar** en la página de login (solo si el dominio coincide), generador, búsqueda, copiar.
- Si dos personas editan lo mismo a la vez, la segunda recibe un aviso en vez de pisar el cambio.
- Sin internet: muestra la última copia (cifrada) en solo lectura.
- Bloqueo automático (1 min – 4 h, o al cerrar el navegador) y al bloquear la computadora.
- Respaldo cifrado (exportar) e importación a la bóveda del equipo (también desde la bóveda personal de la v0.1).

## Seguridad
- Clave del equipo → PBKDF2-SHA256 (600 000 iteraciones) → AES-256-GCM, IV nuevo por elemento y guardado.
- Supabase: RLS en todas las tablas; solo miembros leen; `anon` no tiene permisos. Las escrituras con
  una clave vieja se rechazan en la base. Esquema en `supabase/migrations/`.
- La extensión solo se conecta a `ohubfaeiokgcdomncwym.supabase.co` (CSP) y solo toca la pestaña activa
  cuando pulsas «Rellenar».
- **Si se pierde la clave del equipo, no hay recuperación.** Guárdala en un lugar seguro.
- Proyecto gratuito de Supabase: se pausa tras ~1 semana sin uso; se reactiva desde el panel.
