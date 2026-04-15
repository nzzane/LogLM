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
  line.dataset.fb = '1';
  line.dataset.host = event.host || '';
  line.dataset.program = event.program || '';
  line.dataset.pattern = (event.message || '').slice(0, 200);
  const ts = (event.timestamp || '').slice(11, 19);
  const host = event.host || '?';
  const msg = (event.message || '').slice(0, 200);
  const sev = (event.severity || 'info').toLowerCase();

  line.innerHTML = `
    <span class="log-ts">${escHtml(ts)}</span>
    <span class="log-host">${escHtml(host)}</span>
    <span class="badge badge-${sev}">${sev}</span>
    <span class="log-msg">${escHtml(msg)}</span>
    <span class="fb-actions">
      <button class="fb-btn fb-imp" title="Mark important" onclick="fbFromButton(this,'important')">★</button>
      <button class="fb-btn fb-ign" title="Ignore future" onclick="fbFromButton(this,'ignore')">✕</button>
    </span>
  `;

  liveFeed.prepend(line);
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

// ── Feedback (AI training: important / ignore) ────────────────────────────────
window.sendFeedback = async function(btn, payload) {
  btn.disabled = true;
  const orig = btn.textContent;
  try {
    const r = await fetch('/api/feedback', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (r.ok) {
      btn.textContent = payload.verdict === 'important' ? '★ saved' : '✕ saved';
      btn.classList.add('fb-saved');
      const sib = btn.parentElement.querySelectorAll('button');
      sib.forEach(b => { if (b !== btn) b.disabled = true; });
    } else {
      btn.textContent = 'err';
      btn.disabled = false;
    }
  } catch {
    btn.textContent = orig;
    btn.disabled = false;
  }
};

window.fbFromButton = function(btn, verdict) {
  const wrap = btn.closest('[data-fb]');
  if (!wrap) return;
  const payload = {
    verdict,
    event_id: wrap.dataset.eventId ? parseInt(wrap.dataset.eventId, 10) : null,
    host: wrap.dataset.host || null,
    program: wrap.dataset.program || null,
    pattern: wrap.dataset.pattern || null,
  };
  sendFeedback(btn, payload);
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

// ── Hover prefetch for nav links ──────────────────────────────────────────────
// Warm browser cache the moment user hovers a nav link so click feels instant.
(function() {
  const prefetched = new Set();
  function prefetch(url) {
    if (prefetched.has(url)) return;
    prefetched.add(url);
    const link = document.createElement('link');
    link.rel = 'prefetch';
    link.href = url;
    link.as = 'document';
    document.head.appendChild(link);
  }
  document.querySelectorAll('.nav-links a').forEach(a => {
    if (a.pathname === location.pathname) return;
    a.addEventListener('mouseenter', () => prefetch(a.href), { once: true });
    a.addEventListener('touchstart', () => prefetch(a.href), { once: true, passive: true });
  });
})();
