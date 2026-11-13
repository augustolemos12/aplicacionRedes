// Script estático de demostración servido con Content-Type: application/javascript
document.addEventListener("DOMContentLoaded", () => {
  const statusEl = document.getElementById("js-status");
  if (statusEl) {
    const now = new Date().toLocaleTimeString();
    statusEl.textContent = `[OK] Recurso /app.js descargado y ejecutado correctamente por el navegador (${now}).`;
  }
});
