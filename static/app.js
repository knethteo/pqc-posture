// ── Verdict helpers ──────────────────────────────────────────────────────────
const VERDICT_LABELS = {
  red:   "Not Quantum-Safe",
  green: "Quantum-Safe",
  amber: "Review",
  grey:  "No PQC data",
};

function pillHtml(color, label) {
  return `<span class="pill ${color}">${label ?? VERDICT_LABELS[color] ?? color}</span>`;
}

// ── Date formatting ──────────────────────────────────────────────────────────
function fmtDate(iso) {
  if (!iso) return "—";
  try {
    return new Date(iso).toLocaleDateString("en-GB", {
      day: "2-digit", month: "short", year: "numeric",
    });
  } catch { return iso; }
}

// ── API fetch wrapper ─────────────────────────────────────────────────────────
async function apiFetch(path) {
  const res = await fetch(path);
  if (res.status === 401) {
    window.location.href = "/setup";
    return null;
  }
  if (!res.ok) {
    const body = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(body.detail || res.statusText);
  }
  return res.json();
}

// ── Status check — redirect to /settings if not configured ───────────────────
async function checkConfigured() {
  try {
    const s = await fetch("/api/status");
    const data = await s.json();
    if (!data.configured) window.location.href = "/settings";
  } catch {
    // ignore — backend may be starting
  }
}

// ── Escape HTML ───────────────────────────────────────────────────────────────
function esc(str) {
  return String(str ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}
