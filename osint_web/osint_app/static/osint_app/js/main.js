/* ═══════════════════════════════════════════════
   OSINT Platform — Frontend Controller
   ═══════════════════════════════════════════════ */

// ── Canvas Particle Network ───────────────────────────────────────────────
(function initCanvas() {
  const canvas = document.getElementById('bgCanvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  let W, H, particles = [], animId;

  function resize() {
    W = canvas.width  = window.innerWidth;
    H = canvas.height = window.innerHeight;
  }

  class Particle {
    constructor() { this.reset(); }
    reset() {
      this.x  = Math.random() * W;
      this.y  = Math.random() * H;
      this.vx = (Math.random() - 0.5) * 0.3;
      this.vy = (Math.random() - 0.5) * 0.3;
      this.r  = Math.random() * 1.5 + 0.5;
      this.a  = Math.random() * 0.5 + 0.1;
    }
    update() {
      this.x += this.vx;
      this.y += this.vy;
      if (this.x < 0 || this.x > W) this.vx *= -1;
      if (this.y < 0 || this.y > H) this.vy *= -1;
    }
    draw() {
      ctx.beginPath();
      ctx.arc(this.x, this.y, this.r, 0, Math.PI * 2);
      ctx.fillStyle = `rgba(79,156,249,${this.a})`;
      ctx.fill();
    }
  }

  function initParticles() {
    particles = Array.from({ length: 80 }, () => new Particle());
  }

  function drawConnections() {
    for (let i = 0; i < particles.length; i++) {
      for (let j = i + 1; j < particles.length; j++) {
        const dx = particles[i].x - particles[j].x;
        const dy = particles[i].y - particles[j].y;
        const dist = Math.sqrt(dx * dx + dy * dy);
        if (dist < 120) {
          ctx.beginPath();
          ctx.moveTo(particles[i].x, particles[i].y);
          ctx.lineTo(particles[j].x, particles[j].y);
          ctx.strokeStyle = `rgba(79,156,249,${0.08 * (1 - dist / 120)})`;
          ctx.lineWidth = 0.5;
          ctx.stroke();
        }
      }
    }
  }

  function loop() {
    ctx.clearRect(0, 0, W, H);
    particles.forEach(p => { p.update(); p.draw(); });
    drawConnections();
    animId = requestAnimationFrame(loop);
  }

  resize();
  initParticles();
  loop();
  window.addEventListener('resize', () => { resize(); });
})();

// ── Navbar scroll effect ──────────────────────────────────────────────────
window.addEventListener('scroll', () => {
  const nav = document.getElementById('navbar');
  if (nav) nav.classList.toggle('scrolled', window.scrollY > 40);
});

// ── Mobile hamburger ──────────────────────────────────────────────────────
const hamburger  = document.getElementById('hamburger');
const mobileMenu = document.getElementById('mobileMenu');

hamburger?.addEventListener('click', () => {
  mobileMenu.classList.toggle('open');
});

document.querySelectorAll('.mobile-link').forEach(link => {
  link.addEventListener('click', () => mobileMenu.classList.remove('open'));
});

// ── Smooth scroll for anchor links ────────────────────────────────────────
document.querySelectorAll('a[href^="#"]').forEach(a => {
  a.addEventListener('click', e => {
    const target = document.querySelector(a.getAttribute('href'));
    if (target) {
      e.preventDefault();
      target.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  });
});

// ── Investigation UI State Machine ────────────────────────────────────────
let currentJobId = null;
let pollTimer    = null;
let pollCount    = 0;
let selectedType = 'company';

// DOM refs
const formPanel     = document.getElementById('formPanel');
const progressPanel = document.getElementById('progressPanel');
const resultPanel   = document.getElementById('resultPanel');
const errorPanel    = document.getElementById('errorPanel');
const submitBtn     = document.getElementById('submitBtn');
const entityInput   = document.getElementById('entityName');
const aliasInput    = document.getElementById('aliases');
const progName      = document.getElementById('progName');
const progFill      = document.getElementById('progFill');
const progPct       = document.getElementById('progPct');
const downloadBtn   = document.getElementById('downloadBtn');

// Entity type toggle
document.querySelectorAll('.type-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.type-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    selectedType = btn.dataset.type;
  });
});

// Submit on Enter
entityInput?.addEventListener('keydown', e => {
  if (e.key === 'Enter') startInvestigation();
});

submitBtn?.addEventListener('click', startInvestigation);

async function startInvestigation() {
  // Redirect to signin if not authenticated
  if (!window.USER_AUTHENTICATED) {
    window.location.href = (window.SIGNIN_URL || '/accounts/signin/') + '?next=/';
    return;
  }

  const entity  = entityInput?.value.trim();
  const aliases = aliasInput?.value.trim();

  if (!entity) {
    shake(entityInput.closest('.iw'));
    entityInput.focus();
    return;
  }

  const adapters = [...document.querySelectorAll('.chk-item input:checked')]
    .map(cb => cb.value);

  if (adapters.length === 0) {
    showToast('Select at least one data source.');
    return;
  }

  showPanel('progress');
  if (progName) progName.textContent = entity;
  pollCount = 0;
  setProgress(5);
  setPhase(1, 'active');

  try {
    const resp = await fetch('/investigate/', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ entity_name: entity, entity_type: selectedType, aliases, adapters: adapters.join(',') }),
    });
    const data = await resp.json();
    if (!resp.ok) throw new Error(data.error || 'Submission failed');
    currentJobId = data.job_id;
    startPolling();
  } catch (err) {
    showPanel('error');
    const errEl = document.getElementById('errMsg');
    if (errEl) errEl.textContent = err.message;
  }
}

function startPolling() {
  pollTimer = setInterval(pollStatus, 3000);
}

function stopPolling() {
  clearInterval(pollTimer);
  pollTimer = null;
}

async function pollStatus() {
  if (!currentJobId) return;
  pollCount++;
  try {
    const resp = await fetch(`/status/${currentJobId}/`);
    const data = await resp.json();
    updateProgress(data.status, pollCount);
    if (data.status === 'completed') { stopPolling(); showResult(data); }
    else if (data.status === 'failed') { stopPolling(); showPanel('error'); const e = document.getElementById('errMsg'); if(e) e.textContent = (data.error_message || 'Investigation failed').substring(0,500); }
  } catch (err) {
    console.warn('Poll error:', err);
  }
}

function updateProgress(status, count) {
  if (status !== 'running') return;
  if (count <= 3)       { setPhase(1,'active'); setProgress(20); }
  else if (count <= 7)  { setPhase(1,'done'); setPhase(2,'active'); setProgress(55); }
  else                  { setPhase(1,'done'); setPhase(2,'done'); setPhase(3,'active'); setProgress(85); }
}

function setProgress(pct) {
  if (progFill) progFill.style.width = pct + '%';
  if (progPct)  progPct.textContent  = pct + '%';
}

function setPhase(n, state) {
  const el    = document.getElementById(`pp${n}`);
  const badge = document.getElementById(`pb${n}`);
  if (!el) return;
  el.classList.remove('active','done');
  if (state) el.classList.add(state);
  if (badge) {
    badge.textContent = state === 'active' ? 'Running...' : state === 'done' ? '✓ Done' : 'Waiting';
  }
}

function showResult(data) {
  setPhase(1,'done'); setPhase(2,'done'); setPhase(3,'done'); setProgress(100);
  setTimeout(() => {
    showPanel('result');
    const rEnt  = document.getElementById('resEntity');
    const mSc   = document.getElementById('mScore');
    const mSev  = document.getElementById('mSev');
    const mFind = document.getElementById('mFind');
    if (rEnt)  rEnt.textContent  = data.entity_name;
    if (mSc)   mSc.textContent   = `${data.risk_score}/100`;
    if (mSev)  { mSev.textContent = data.severity || '—'; mSev.className = `met-v met-sev ${data.severity || ''}`; }
    if (mFind) mFind.textContent  = data.findings_count;
    if (downloadBtn) downloadBtn.href = data.download_url || '#';
  }, 700);
}

function showPanel(name) {
  [formPanel, progressPanel, resultPanel, errorPanel].forEach(p => { if(p) p.style.display = 'none'; });
  const map = { form:formPanel, progress:progressPanel, result:resultPanel, error:errorPanel };
  const target = map[name];
  if (target) { target.style.display = 'block'; target.scrollIntoView({ behavior:'smooth', block:'center' }); }
}

function resetForm() {
  stopPolling();
  currentJobId = null;
  pollCount    = 0;
  showPanel('form');
  if (entityInput) entityInput.value = '';
  if (aliasInput)  aliasInput.value  = '';
  [1,2,3].forEach(n => setPhase(n, null));
  setProgress(0);
}

document.getElementById('newBtn')?.addEventListener('click', resetForm);
document.getElementById('retryBtn')?.addEventListener('click', resetForm);

// ── Helpers ───────────────────────────────────────────────────────────────

function shake(el) {
  if (!el) return;
  el.style.animation = 'none';
  el.offsetHeight; // reflow
  el.style.animation = 'shake 0.4s ease';
  el.addEventListener('animationend', () => { el.style.animation = ''; }, { once:true });
}

function showToast(msg) {
  const t = document.createElement('div');
  t.textContent = msg;
  t.style.cssText = `position:fixed;bottom:2rem;left:50%;transform:translateX(-50%);background:rgba(248,113,113,0.15);border:1px solid rgba(248,113,113,0.4);color:#f87171;padding:.65rem 1.5rem;border-radius:8px;font-size:.85rem;font-family:var(--sans);z-index:9999;backdrop-filter:blur(12px);transition:opacity .3s`;
  document.body.appendChild(t);
  setTimeout(() => { t.style.opacity = '0'; setTimeout(() => t.remove(), 300); }, 2500);
}

// Inject shake keyframe
const ks = document.createElement('style');
ks.textContent = `@keyframes shake{0%,100%{transform:translateX(0)}20%,60%{transform:translateX(-6px)}40%,80%{transform:translateX(6px)}}`;
document.head.appendChild(ks);

// ── Typing placeholder effect ─────────────────────────────────────────────
const phrases   = ['e.g. AIGeeks','e.g. Travis Haasch','e.g. OpenAI','e.g. Anthropic','e.g. Elon Musk'];
let pIdx = 0, cIdx = 0, deleting = false;

function typePlaceholder() {
  const cur = phrases[pIdx];
  cIdx += deleting ? -1 : 1;
  if (entityInput) entityInput.setAttribute('placeholder', cur.substring(0, cIdx));
  let delay = deleting ? 45 : 85;
  if (!deleting && cIdx === cur.length)    { delay = 1800; deleting = true; }
  else if (deleting && cIdx === 0)          { deleting = false; pIdx = (pIdx+1) % phrases.length; delay = 400; }
  setTimeout(typePlaceholder, delay);
}
if (entityInput) setTimeout(typePlaceholder, 1200);
