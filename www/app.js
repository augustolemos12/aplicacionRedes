// Script estático de verificación servido con Content-Type: application/javascript
document.addEventListener("DOMContentLoaded", () => {
  const statusEl = document.getElementById("js-status");
  if (statusEl) {
    const now = new Date().toISOString().replace("T", " ").slice(0, 19);
    statusEl.textContent = `[DIAG ${now} UTC] STATIC ASSET /app.js EXECUTED — MIME: application/javascript — STATUS: ONLINE`;
  }
});
