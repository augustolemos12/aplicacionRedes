/**
 * Cliente de Consola de Administración HTTP (Sin frameworks).
 * Consume /admin/api/status, /admin/api/logs y POST /admin/api/config.
 */

let currentCsrfToken = "";

function formatUptime(seconds) {
  const s = Math.max(0, Number(seconds) || 0);
  const hrs = String(Math.floor(s / 3600)).padStart(2, "0");
  const mins = String(Math.floor((s % 3600) / 60)).padStart(2, "0");
  const secs = String(s % 60).padStart(2, "0");
  return `${hrs}h ${mins}m ${secs}s`;
}

function showFeedback(message, isError = false) {
  const box = document.getElementById("form-feedback");
  if (!box) return;
  const prefix = isError ? "[FAULT]" : "[OK]";
  box.textContent = `${prefix} ${message}`;
  box.className = `feedback ${isError ? "error" : "success"}`;
}

function setConsoleOnlineState(isOnline) {
  const led = document.getElementById("activity-led");
  const badge = document.getElementById("header-state-badge");
  const statStatus = document.getElementById("stat-status");

  if (isOnline) {
    if (led) led.classList.remove("fault");
    if (badge) {
      badge.textContent = "STATE: RUNNING";
      badge.className = "state-badge running";
    }
    if (statStatus) {
      statStatus.textContent = "ONLINE // RUNNING";
      statStatus.className = "stat-value text-green";
    }
  } else {
    if (led) led.classList.add("fault");
    if (badge) {
      badge.textContent = "STATE: OFFLINE";
      badge.className = "state-badge offline";
    }
    if (statStatus) {
      statStatus.textContent = "OFFLINE // STOPPED";
      statStatus.className = "stat-value text-red";
    }
  }
}

function renderTerminalLines(container, lines, isErrorStream = false) {
  container.textContent = "";
  if (!Array.isArray(lines) || lines.length === 0) {
    container.textContent = isErrorStream
      ? "-- NO ERROR/SECURITY EVENTS RECORDED --"
      : "-- NO ACCESS TRANSACTIONS RECORDED --";
    return;
  }

  lines.forEach((rawLine, idx) => {
    const span = document.createElement("span");
    span.className = "log-line";
    const lineNum = String(idx + 1).padStart(3, "0");

    if (isErrorStream) {
      if (rawLine.includes("SECURITY_") || rawLine.includes("INTERNAL_") || rawLine.includes("ERROR")) {
        span.classList.add("log-err");
      } else {
        span.classList.add("log-warn");
      }
    } else {
      if (/"\s2\d\d\s/.test(rawLine)) {
        span.classList.add("log-ok");
      } else if (/"\s4\d\d\s/.test(rawLine)) {
        span.classList.add("log-warn");
      } else if (/"\s5\d\d\s/.test(rawLine)) {
        span.classList.add("log-err");
      }
    }

    span.textContent = `${lineNum} | ${rawLine}\n`;
    container.appendChild(span);
  });
}

async function fetchStatus() {
  try {
    const res = await fetch("/admin/api/status", {
      headers: { Accept: "application/json" },
    });
    const data = await res.json();
    if (!res.ok || !data.ok) {
      setConsoleOnlineState(false);
      showFeedback(data.detail || "No se pudo obtener la telemetría del servidor.", true);
      return;
    }

    setConsoleOnlineState(true);
    currentCsrfToken = data.csrf_token || "";

    const active = data.active_binding || {};
    const cfg = data.config || {};
    const bindStr = `${active.host || cfg.host}:${active.port || cfg.port}`;

    document.getElementById("stat-binding").textContent = `BIND: ${bindStr}`;
    const sideBind = document.getElementById("side-bind");
    if (sideBind) sideBind.textContent = bindStr;

    document.getElementById("stat-docroot").textContent = active.document_root || cfg.document_root || "www";
    document.getElementById("stat-uptime").textContent = formatUptime(data.uptime_seconds);
    document.getElementById("stat-requests").textContent = String(data.total_requests ?? 0);

    // Poblar campos del formulario de configuración
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
    setConsoleOnlineState(false);
    showFeedback(`Fallo de conexión con el servidor: ${err.message}`, true);
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
      accessBox.textContent = "[FAULT] UNABLE TO READ ACCESS LOG STREAM.";
      errorBox.textContent = data.detail || "[FAULT] UNABLE TO READ ERROR LOG STREAM.";
      return;
    }

    renderTerminalLines(accessBox, data.access_log || [], false);
    renderTerminalLines(errorBox, data.error_log || [], true);
  } catch (err) {
    accessBox.textContent = `[FAULT] LOG QUERY FAILED: ${err.message}`;
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
      showFeedback(`HTTP ${res.status}: ${data.detail || "Configuración rechazada."}`, true);
      await fetchLogs();
      return;
    }

    document.getElementById("cfg-newpass").value = "";
    let msg = data.message || "Configuración persistida en server.json.";
    if (data.requires_restart) {
      msg += ` [RESTART REQUIRED FOR: ${data.pending_restart_fields.join(", ")}]`;
    }
    showFeedback(msg, false);
    await fetchStatus();
    await fetchLogs();
  } catch (err) {
    showFeedback(`No se pudo transmitir la configuración: ${err.message}`, true);
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
