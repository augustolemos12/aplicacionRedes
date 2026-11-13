/**
 * Cliente JavaScript sin frameworks para el Panel Administrativo del Servidor HTTP.
 * Consume /admin/api/status, /admin/api/logs y POST /admin/api/config.
 */

let currentCsrfToken = "";

function formatUptime(seconds) {
  const s = Math.max(0, Number(seconds) || 0);
  const hrs = Math.floor(s / 3600);
  const mins = Math.floor((s % 3600) / 60);
  const secs = s % 60;
  return `${hrs}h ${mins}m ${secs}s`;
}

function showFeedback(message, isError = false) {
  const box = document.getElementById("form-feedback");
  if (!box) return;
  box.textContent = message;
  box.className = `feedback ${isError ? "error" : "success"}`;
}

async function fetchStatus() {
  try {
    const res = await fetch("/admin/api/status", {
      headers: { Accept: "application/json" },
    });
    const data = await res.json();
    if (!res.ok || !data.ok) {
      showFeedback(data.detail || "No se pudo obtener el estado del servidor.", true);
      return;
    }

    currentCsrfToken = data.csrf_token || "";

    const active = data.active_binding || {};
    const cfg = data.config || {};

    document.getElementById("stat-status").textContent = "ACTIVO (ESCUCHANDO)";
    document.getElementById("stat-binding").textContent = `Socket activo: ${active.host}:${active.port}`;
    document.getElementById("stat-docroot").textContent = active.document_root || cfg.document_root || "www";
    document.getElementById("stat-uptime").textContent = formatUptime(data.uptime_seconds);
    document.getElementById("stat-requests").textContent = String(data.total_requests ?? 0);

    // Poblar campos del formulario
    document.getElementById("cfg-host").value = cfg.host || "0.0.0.0";
    document.getElementById("cfg-port").value = cfg.port ?? 8080;
    document.getElementById("cfg-docroot").value = cfg.document_root || "www";
    document.getElementById("cfg-maxsize").value = cfg.max_request_size ?? 1048576;
    document.getElementById("cfg-timeout").value = cfg.socket_timeout ?? 10;
    document.getElementById("cfg-protected").value = (cfg.protected_directories || []).join(", ");

    const restartBanner = document.getElementById("restart-alert");
    if (Array.isArray(data.pending_restart_fields) && data.pending_restart_fields.length > 0) {
      restartBanner.classList.remove("hidden");
    } else {
      restartBanner.classList.add("hidden");
    }
  } catch (err) {
    showFeedback(`Error de red al consultar estado: ${err.message}`, true);
  }
}

async function fetchLogs() {
  const limitSelect = document.getElementById("log-limit");
  const limit = limitSelect ? limitSelect.value : "40";
  const accessBox = document.getElementById("access-log-box");
  const errorBox = document.getElementById("error-log-box");

  try {
    const res = await fetch(`/admin/api/logs?limit=${encodeURIComponent(limit)}`, {
      headers: { Accept: "application/json" },
    });
    const data = await res.json();
    if (!res.ok || !data.ok) {
      accessBox.textContent = "Error al cargar logs.";
      errorBox.textContent = data.detail || "Error al cargar logs.";
      return;
    }

    const accessLines = data.access_log || [];
    const errorLines = data.error_log || [];

    accessBox.textContent = accessLines.length > 0 ? accessLines.join("\n") : "(Sin registros en access.log)";
    errorBox.textContent = errorLines.length > 0 ? errorLines.join("\n") : "(Sin registros en error.log)";
  } catch (err) {
    accessBox.textContent = `Error al consultar logs: ${err.message}`;
  }
}

async function handleConfigSubmit(event) {
  event.preventDefault();
  const host = document.getElementById("cfg-host").value.trim();
  const port = Number(document.getElementById("cfg-port").value);
  const documentRoot = document.getElementById("cfg-docroot").value.trim();
  const maxRequestSize = Number(document.getElementById("cfg-maxsize").value);
  const socketTimeout = Number(document.getElementById("cfg-timeout").value);
  const rawProtected = document.getElementById("cfg-protected").value;
  const newPassword = document.getElementById("cfg-newpass").value;

  const protectedDirectories = rawProtected
    .split(",")
    .map((item) => item.trim())
    .filter((item) => item.length > 0);

  const payload = {
    host,
    port,
    document_root: documentRoot,
    max_request_size: maxRequestSize,
    socket_timeout: socketTimeout,
    protected_directories: protectedDirectories,
    csrf_token: currentCsrfToken,
  };

  if (newPassword && newPassword.length > 0) {
    payload.new_password = newPassword;
  }

  try {
    const res = await fetch("/admin/api/config", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-CSRF-Token": currentCsrfToken,
      },
      body: JSON.stringify(payload),
    });

    const data = await res.json();
    if (!res.ok || !data.ok) {
      showFeedback(`Error (${res.status}): ${data.detail || "Configuración rechazada."}`, true);
      await fetchLogs();
      return;
    }

    document.getElementById("cfg-newpass").value = "";
    let msg = data.message || "Configuración actualizada.";
    if (data.requires_restart) {
      msg += ` Campos pendientes de reinicio manual: ${data.pending_restart_fields.join(", ")}.`;
    }
    showFeedback(msg, false);
    await fetchStatus();
    await fetchLogs();
  } catch (err) {
    showFeedback(`No se pudo guardar la configuración: ${err.message}`, true);
  }
}

document.addEventListener("DOMContentLoaded", () => {
  fetchStatus();
  fetchLogs();

  document.getElementById("config-form").addEventListener("submit", handleConfigSubmit);
  document.getElementById("btn-refresh").addEventListener("click", () => {
    fetchStatus();
    fetchLogs();
  });
  document.getElementById("btn-reload-logs").addEventListener("click", fetchLogs);
  document.getElementById("log-limit").addEventListener("change", fetchLogs);
});
