// LogLM — realtime SSE client + UI helpers

const liveIndicator = document.getElementById('live-indicator');
const liveFeed = document.getElementById('live-feed');
const statsEls = {
  events1h: document.getElementById('stat-events-1h'),
  events24h: document.getElementById('stat-events-24h'),
  errors24h: document.getElementById('stat-errors-24h'),
  alertsUnacked: document.getElementById('stat-alerts-unacked'),
};

// ── SSE connection ────────────────────────────────────────────────────────────
function connectSSE() {
  const es = new EventSource('/api/stream');

  es.onopen = () => {
    if (liveIndicator) {
      liveIndicator.classList.remove('disconnected');
      liveIndicator.classList.add('connected');
    }
  };

  es.onerror = () => {
    if (liveIndicator) {
      liveIndicator.classList.remove('connected');
      liveIndicator.classList.add('disconnected');
    }
    es.close();
    setTimeout(connectSSE, 5000); // reconnect
  };

  es.onmessage = (e) => {
    if (!e.data || e.data.startsWith(':')) return;
    try {
      const event = JSON.parse(e.data);
      appendLogLine(event);
    } catch {}
  };
}

// ── Live feed ─────────────────────────────────────────────────────────────────
function appendLogLine(event) {
  if (!liveFeed) return;
  const line = document.createElement('div');
  line.className = 'log-line';
  const ts = (event.timestamp || '').slice(11, 19);
  const host = event.host || '?';
  const msg = (event.message || '').slice(0, 200);
  const sev = (event.severity || 'info').toLowerCase();

  line.innerHTML = `
    <span class="log-ts">${escHtml(ts)}</span>
    <span class="log-host">${escHtml(host)}</span>
    <span class="badge badge-${sev}">${sev}</span>
    <span class="log-msg">${escHtml(msg)}</span>
  `;

  liveFeed.prepend(line);
  // Keep max 200 lines
  while (liveFeed.children.length > 200) {
    liveFeed.removeChild(liveFeed.lastChild);
  }
}

// ── Stats refresh ─────────────────────────────────────────────────────────────
async function refreshStats() {
  try {
    const r = await fetch('/api/stats');
    if (!r.ok) return;
    const d = await r.json();
    if (statsEls.events1h)      statsEls.events1h.textContent      = d.events_1h;
    if (statsEls.events24h)     statsEls.events24h.textContent     = d.events_24h;
    if (statsEls.errors24h)     statsEls.errors24h.textContent     = d.errors_24h;
    if (statsEls.alertsUnacked) statsEls.alertsUnacked.textContent = d.alerts_unacked;
  } catch {}
}

// ── Alert acknowledge ─────────────────────────────────────────────────────────
window.ackAlert = async function(id, btn) {
  const r = await fetch(`/alerts/${id}/acknowledge`, { method: 'POST' });
  if (r.ok) {
    btn.closest('.alert-card').classList.add('acked');
    btn.disabled = true;
    btn.textContent = 'Acknowledged';
    refreshStats();
  }
};

// ── Alias delete ──────────────────────────────────────────────────────────────
window.deleteAlias = async function(id, row) {
  if (!confirm('Delete this alias?')) return;
  const r = await fetch(`/aliases/${id}/delete`, { method: 'POST' });
  if (r.ok) row.closest('tr').remove();
};

// ── Utilities ─────────────────────────────────────────────────────────────────
function escHtml(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// ── Init ──────────────────────────────────────────────────────────────────────
connectSSE();
refreshStats();
setInterval(refreshStats, 30000);

// Highlight active nav link
document.querySelectorAll('.nav-links a').forEach(a => {
  if (a.pathname === location.pathname) a.classList.add('active');
});
