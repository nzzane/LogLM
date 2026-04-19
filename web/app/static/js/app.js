// LogLM — realtime SSE client + UI helpers

const liveIndicator = document.getElementById('live-indicator');
const liveFeed = document.getElementById('live-feed');
const statsEls = {
  events1h: document.getElementById('stat-events-1h'),
  events24h: document.getElementById('stat-events-24h'),
  errors24h: document.getElementById('stat-errors-24h'),
  alertsUnacked: document.getElementById('stat-alerts-unacked'),
};

// ── WebSocket live feed with filtering ────────────────────────────────────────
let _ws = null;
let _wsFilters = {};
let _wsReconnectTimer = null;

function connectWS() {
  if (_ws && _ws.readyState <= 1) return;
  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  _ws = new WebSocket(`${proto}//${location.host}/ws/events`);

  _ws.onopen = () => {
    if (liveIndicator) {
      liveIndicator.classList.remove('disconnected');
      liveIndicator.classList.add('connected');
    }
    if (Object.keys(_wsFilters).length) {
      _ws.send(JSON.stringify({filter: _wsFilters}));
    }
  };

  _ws.onclose = () => {
    if (liveIndicator) {
      liveIndicator.classList.remove('connected');
      liveIndicator.classList.add('disconnected');
    }
    _wsReconnectTimer = setTimeout(connectWS, 3000);
  };

  _ws.onerror = () => _ws.close();

  _ws.onmessage = (e) => {
    if (!e.data) return;
    try {
      const event = JSON.parse(e.data);
      if (event.keepalive) return;
      appendLogLine(event);
    } catch {}
  };
}

window.setLiveFilter = function(filters) {
  _wsFilters = filters || {};
  if (_ws && _ws.readyState === 1) {
    _ws.send(JSON.stringify({filter: _wsFilters}));
  }
};

// SSE fallback for browsers without WebSocket (unlikely)
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
    setTimeout(connectSSE, 5000);
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
    const card = btn.closest('.alert-card') || btn.closest('.warning-card');
    if (card) {
      card.classList.add('acked');
      // Fade then remove so the row visibly leaves the view.
      card.style.transition = 'opacity .35s';
      card.style.opacity = '0';
      setTimeout(() => card.remove(), 350);
    }
    btn.disabled = true;
    refreshStats();
    if (typeof refreshWarnings === 'function') refreshWarnings();
  }
};

// Dashboard warning card variant: same behaviour, just card-local buttons.
window.ackWarning = async function(btn, id) {
  btn.disabled = true;
  const r = await fetch(`/alerts/${id}/acknowledge`, { method: 'POST' });
  if (!r.ok) { btn.disabled = false; return; }
  const card = btn.closest('.warning-card');
  if (card) {
    card.style.transition = 'opacity .35s';
    card.style.opacity = '0';
    setTimeout(() => card.remove(), 350);
  }
  refreshStats();
  if (typeof refreshWarnings === 'function') refreshWarnings();
};

window.ignoreWarning = async function(btn, id) {
  if (!confirm('Acknowledge AND silence all future matching messages from the affected hosts?')) return;
  btn.disabled = true;
  const r = await fetch(`/api/alerts/${id}/ignore`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({}),
  });
  if (!r.ok) { btn.disabled = false; alert('ignore failed'); return; }
  const card = btn.closest('.warning-card') || btn.closest('.alert-card');
  if (card) {
    card.style.transition = 'opacity .35s';
    card.style.opacity = '0';
    setTimeout(() => card.remove(), 350);
  }
  refreshStats();
  if (typeof refreshWarnings === 'function') refreshWarnings();
};

// ── Dashboard warnings panel auto-refresh ─────────────────────────────────────
// Re-fetches every 15s so new alerts appear and acked alerts disappear without
// a full page reload.
async function refreshWarnings() {
  const mount = document.getElementById('warnings-mount');
  if (!mount) return;
  const stateEl = document.getElementById('warnings-refresh-state');
  try {
    const r = await fetch('/api/warnings');
    if (!r.ok) throw new Error('HTTP ' + r.status);
    const data = await r.json();
    if (!Array.isArray(data) || data.length === 0) {
      mount.innerHTML = '<div class="card empty-state">No active warnings — all systems nominal.</div>';
    } else {
      const cards = data.map(w => {
        const sev = (w.severity || 'low').toLowerCase();
        const hosts = (w.affected_hosts || []).join(', ') || '—';
        const seen = (w.seen_count && w.seen_count > 1)
          ? `<span class="badge badge-count">${w.seen_count}×</span>` : '';
        const desc = ((w.description || '').slice(0, 160))
          + ((w.description || '').length > 160 ? '…' : '');
        const last = w.last_seen ? new Date(w.last_seen).toLocaleString() : '';
        return `
          <div class="warning-card ${escHtml(sev)}" data-alert-id="${w.id}">
            <div class="warning-head">
              <span class="badge badge-${escHtml(sev)}">${escHtml(sev)}</span>
              <span class="warning-hosts">${escHtml(hosts)}</span>
              ${seen}
            </div>
            <div class="warning-title">${escHtml(w.title || '')}</div>
            <div class="warning-desc">${escHtml(desc)}</div>
            <div class="warning-foot">
              <span>${escHtml(last)}</span>
              <span class="warning-actions">
                <button class="btn secondary" style="font-size:.7rem;padding:.15rem .5rem;"
                        onclick="ackWarning(this, ${w.id})">Ack</button>
                <button class="btn secondary" style="font-size:.7rem;padding:.15rem .5rem;"
                        title="Acknowledge AND silence all future matching events"
                        onclick="ignoreWarning(this, ${w.id})">Ack+Ignore</button>
              </span>
            </div>
          </div>`;
      }).join('');
      mount.innerHTML = `<div class="warnings-grid">${cards}</div>`;
    }
    if (stateEl) stateEl.textContent = `updated ${new Date().toLocaleTimeString()}`;
  } catch (e) {
    if (stateEl) stateEl.textContent = 'refresh failed';
  }
}

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

// ── Streaming chat ───────────────────────────────────────────────────────────
window.sendChatStreaming = async function(message, sessionId, mode, onToken, onDone, onError) {
  // mode param is optional — detect old callers that pass onToken as 3rd arg
  if (typeof mode === 'function') {
    onError = onDone; onDone = onToken; onToken = mode; mode = 'quick';
  }
  const body = {message, session_id: sessionId || null, mode: mode || 'quick'};
  try {
    const resp = await fetch('/api/chat/stream', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(body),
    });
    if (!resp.ok) { if (onError) onError('HTTP ' + resp.status); return; }
    const reader = resp.body.getReader();
    const decoder = new TextDecoder();
    let buf = '';
    let sid = sessionId;
    while (true) {
      const {done, value} = await reader.read();
      if (done) break;
      buf += decoder.decode(value, {stream: true});
      const lines = buf.split('\n');
      buf = lines.pop();
      for (const line of lines) {
        if (!line.startsWith('data: ')) continue;
        try {
          const msg = JSON.parse(line.slice(6));
          if (msg.type === 'token' && onToken) onToken(msg.text);
          else if (msg.type === 'start' && msg.session_id) sid = msg.session_id;
          else if (msg.type === 'done') { if (onDone) onDone(sid || msg.session_id); return; }
          else if (msg.type === 'error') { if (onError) onError(msg.text); return; }
        } catch {}
      }
    }
    if (onDone) onDone(sid);
  } catch (e) {
    if (onError) onError(e.message);
  }
};

// ── Event rate sparkline (dashboard) ─────────────────────────────────────────
window.loadEventRate = async function(canvasId, hours) {
  const canvas = document.getElementById(canvasId);
  if (!canvas) return;
  try {
    const r = await fetch(`/api/event-rate?hours=${hours || 4}`);
    if (!r.ok) return;
    const data = await r.json();
    const pts = data.points || [];
    if (!pts.length) return;
    const ctx = canvas.getContext('2d');
    const w = canvas.width, h = canvas.height;
    const max = Math.max(...pts.map(p => p.count), 1);
    ctx.clearRect(0, 0, w, h);
    ctx.strokeStyle = getComputedStyle(document.documentElement).getPropertyValue('--accent').trim() || '#4fc3f7';
    ctx.lineWidth = 1.5;
    ctx.beginPath();
    pts.forEach((p, i) => {
      const x = (i / Math.max(pts.length - 1, 1)) * w;
      const y = h - (p.count / max) * (h - 4) - 2;
      i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
    });
    ctx.stroke();
    const maxErr = Math.max(...pts.map(p => p.errors), 0);
    if (maxErr > 0) {
      ctx.strokeStyle = getComputedStyle(document.documentElement).getPropertyValue('--danger').trim() || '#ff5252';
      ctx.lineWidth = 1;
      ctx.beginPath();
      pts.forEach((p, i) => {
        const x = (i / Math.max(pts.length - 1, 1)) * w;
        const y = h - (p.errors / max) * (h - 4) - 2;
        i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
      });
      ctx.stroke();
    }
  } catch {}
};

// ── Init ──────────────────────────────────────────────────────────────────────
if (typeof WebSocket !== 'undefined') {
  connectWS();
} else {
  connectSSE();
}
refreshStats();
setInterval(refreshStats, 15000);

if (document.getElementById('warnings-mount')) {
  setInterval(refreshWarnings, 15000);
}

if (document.getElementById('sparkline-events')) {
  loadEventRate('sparkline-events', 4);
  setInterval(() => loadEventRate('sparkline-events', 4), 60000);
}

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
