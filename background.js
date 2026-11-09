// Service worker: bloqueo automático. La clave de la sesión vive en chrome.storage.session
// (solo memoria, se borra al cerrar el navegador y no es accesible desde páginas web).

const LOCK_ALARM = "autolock";

chrome.alarms.onAlarm.addListener(async (alarm) => {
  if (alarm.name === LOCK_ALARM) await chrome.storage.session.remove("sessionKey");
});

chrome.runtime.onMessage.addListener((msg, sender, reply) => {
  if (sender.id !== chrome.runtime.id) return;
  if (msg?.type === "lock") {
    chrome.alarms.clear(LOCK_ALARM).then(() => chrome.storage.session.remove("sessionKey")).then(() => reply({ ok: true }));
    return true;
  }
});

// Bloquear también si la computadora queda inactiva/bloqueada.
if (chrome.idle?.onStateChanged) {
  chrome.idle.onStateChanged.addListener((state) => {
    if (state === "locked") chrome.storage.session.remove("sessionKey");
  });
}
