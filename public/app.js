const app = document.getElementById('app');
const sidebarLinks = document.getElementById('sidebarLinks');
const topbarRight = document.getElementById('topbarRight');
let user = null;

async function init() {
  try { const res = await fetch('/api/auth/me'); user = (await res.json()).user; } catch (e) {}
  renderNav();
  navigate('dashboard');
}

document.getElementById('menu-toggle').addEventListener('click', (e) => {
  e.preventDefault();
  document.getElementById('wrapper').classList.toggle('toggled');
});

function renderNav() {
  const adminLinks = user?.role === 'admin' ? `<div class="list-group-item" onclick="navigate('admin')"><i class="fa-solid fa-user-shield me-2"></i> Admin Panel</div>` : '';
  const authLinks = user 
    ? `<div class="list-group-item" onclick="logout()"><i class="fa-solid fa-right-from-bracket me-2"></i> Logout</div>`
    : `<div class="list-group-item" onclick="navigate('login')"><i class="fa-solid fa-right-to-bracket me-2"></i> Login / Register</div>`;

  sidebarLinks.innerHTML = `
    <div class="list-group-item" onclick="navigate('dashboard')"><i class="fa-solid fa-chart-pie me-2"></i> Dashboard</div>
    <div class="list-group-item" onclick="navigate('scanner')"><i class="fa-solid fa-magnifying-glass me-2"></i> Smart Scanner</div>
    <div class="list-group-item" onclick="navigate('email')"><i class="fa-solid fa-envelope-circle-check me-2"></i> Email Auth Analyzer</div>
    <div class="list-group-item" onclick="navigate('compare')"><i class="fa-solid fa-scale-balanced me-2"></i> Trust Comparison</div>
    <div class="list-group-item" onclick="navigate('map')"><i class="fa-solid fa-diagram-project me-2"></i> Connection Map</div>
    <div class="list-group-item" onclick="navigate('history')"><i class="fa-solid fa-clock-rotate-left me-2"></i> Incident Timeline</div>
    <div class="list-group-item" onclick="navigate('academy')"><i class="fa-solid fa-graduation-cap me-2"></i> Cyber Academy</div>
    <hr class="text-secondary mx-3">
    ${adminLinks}
    ${authLinks}
  `;

  topbarRight.innerHTML = user 
    ? `<span class="text-muted"><i class="fa-solid fa-user-circle me-1"></i> ${user.username}</span>`
    : `<span class="badge bg-secondary">Guest Mode</span>`;
}

function navigate(view) {
  document.querySelectorAll('.sidebar .list-group-item').forEach(el => el.classList.remove('active'));
  app.innerHTML = '<div class="text-center mt-5"><div class="spinner-border text-info"></div></div>';
  
  setTimeout(() => {
    switch(view) {
      case 'dashboard': renderDashboard(); break;
      case 'scanner': renderScanner(); break;
      case 'email': renderEmailAnalyzer(); break;
      case 'compare': renderCompare(); break;
      case 'map': renderMap(); break;
      case 'history': renderHistory(); break;
      case 'academy': renderAcademy(); break;
      case 'login': renderLogin(); break;
      case 'admin': if(user?.role === 'admin') renderAdmin(); else navigate('dashboard'); break;
      default: renderDashboard();
    }
  }, 200);
}

// --- Existing Dashboard (Unchanged) ---
async function renderDashboard() {
  try {
    const res = await fetch('/api/user/stats');
    const stats = await res.json();
    app.innerHTML = `
      <h2 class="fw-bold mb-4">Security Overview</h2>
      <div class="row g-4 mb-4">
        <div class="col-md-4"><div class="glass-card kpi-card"><div class="kpi-icon cyan"><i class="fa-solid fa-radar"></i></div><div><h3 class="mb-0">${stats.totalScans}</h3><small class="text-muted">Total Scans</small></div></div></div>
        <div class="col-md-4"><div class="glass-card kpi-card"><div class="kpi-icon red"><i class="fa-solid fa-triangle-exclamation"></i></div><div><h3 class="mb-0 text-danger">${stats.highRisk}</h3><small class="text-muted">High Risk Detected</small></div></div></div>
        <div class="col-md-4"><div class="glass-card kpi-card"><div class="kpi-icon gold"><i class="fa-solid fa-star"></i></div><div><h3 class="mb-0 text-warning">${stats.points}</h3><small class="text-muted">Academy Points</small></div></div></div>
      </div>
      <div class="row g-4">
        <div class="col-md-8"><div class="glass-card h-100"><h5 class="mb-3">Threat Activity</h5><canvas id="threatChart" height="100"></canvas></div></div>
        <div class="col-md-4"><div class="glass-card h-100 text-center"><h5 class="mb-4">Security Score</h5><div class="position-relative d-inline-block"><canvas id="scoreGauge" width="200" height="200"></canvas><div class="position-absolute top-50 start-50 translate-middle"><h1 class="text-cyan mb-0">${Math.min(100, 50 + stats.points)}</h1><small class="text-muted">/ 100</small></div></div></div></div>
      </div>
    `;
    new Chart(document.getElementById('threatChart'), { type: 'line', data: { labels: ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'], datasets: [{ label: 'Scans', data: [5, 10, 8, 15, 12, 20, stats.totalScans], borderColor: '#00f0ff', backgroundColor: 'rgba(0, 240, 255, 0.1)', fill: true, tension: 0.4 }] }, options: { plugins: { legend: { display: false } }, scales: { y: { display: false }, x: { grid: { display: false }, ticks: { color: '#94a3b8' } } } } });
    new Chart(document.getElementById('scoreGauge'), { type: 'doughnut', data: { datasets: [{ data: [Math.min(100, 50 + stats.points), 100 - Math.min(100, 50 + stats.points)], backgroundColor: ['#00f0ff', 'rgba(255,255,255,0.1)'], borderWidth: 0, cutout: '80%' }] }, options: { plugins: { tooltip: { enabled: false } } } });
  } catch (e) { app.innerHTML = '<div class="alert alert-danger">Error loading dashboard data.</div>'; }
}

// --- Existing Scanner (Unchanged) ---
function renderScanner() {
  app.innerHTML = `
    <h2 class="fw-bold mb-4">Smart Scam Scanner</h2>
    <div class="row g-4">
      <div class="col-md-5">
        <div class="glass-card">
          <form id="form">
            <label class="text-muted mb-2">Select Target Type</label>
            <select name="type" class="form-select mb-3">
              <option value="message">Message / Email / WhatsApp</option>
              <option value="url">Website URL</option>
              <option value="job">Job Offer / Recruitment</option>
            </select>
            <label class="text-muted mb-2">Paste Content</label>
            <textarea name="content" class="form-control mb-3" rows="6" placeholder="Paste the suspicious message, link, or text here..." required></textarea>
            <button class="btn btn-primary w-100 py-2"><i class="fa-solid fa-shield-virus me-2"></i> Analyze Threat</button>
          </form>
        </div>
      </div>
      <div class="col-md-7">
        <div class="glass-card h-100 d-flex flex-column" id="result">
          <div class="text-center m-auto text-muted"><i class="fa-solid fa-microchip fa-3x mb-3 opacity-50"></i><p>Awaiting input. The risk engine is ready.</p></div>
        </div>
      </div>
    </div>
  `;
  document.getElementById('form').onsubmit = async (e) => {
    e.preventDefault();
    document.getElementById('result').innerHTML = '<div class="m-auto"><div class="spinner-border text-info"></div><p class="mt-3 text-muted">Analyzing patterns...</p></div>';
    const res = await fetch('/api/scans/analyze', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(Object.fromEntries(new FormData(e.target))) });
    const data = await res.json();
    const colorClass = data.level === 'critical' || data.level === 'high' ? 'danger' : data.level === 'medium' ? 'warning' : 'success';
    const icon = data.level === 'critical' ? 'fa-radiation' : data.level === 'high' ? 'fa-triangle-exclamation' : 'fa-shield-check';

    // New: Evidence Confidence Meter
    const confidence = data.score > 50 ? 'High' : data.score > 20 ? 'Medium' : 'Low';

    document.getElementById('result').innerHTML = `
      <div class="d-flex justify-content-between align-items-center mb-4">
        <h4 class="mb-0">Analysis Report</h4>
        <span class="badge badge-${data.level} fs-6 px-3 py-2 text-uppercase">${data.level} Risk</span>
      </div>
      <div class="text-center mb-4 p-4 rounded" style="background: rgba(0,0,0,0.2); border: 1px solid rgba(var(--bs-${colorClass}-rgb), 0.3);">
        <i class="fa-solid ${icon} fa-3x text-${colorClass} mb-3"></i>
        <h1 class="text-${colorClass} display-4 fw-bold mb-0">${data.score}<span class="fs-4 text-muted">/100</span></h1>
        <p class="text-muted mt-2 mb-0">Evidence Confidence: <strong class="text-white">${confidence}</strong></p>
      </div>
      <h6 class="text-muted text-uppercase mb-3">Explainable Findings</h6>
      <ul class="list-group list-group-flush mb-4 bg-transparent">
        ${data.findings.map(f => `<li class="list-group-item bg-transparent text-light border-secondary px-0"><i class="fa-solid fa-angle-right text-cyan me-2"></i>${f}</li>`).join('')}
      </ul>
    `;
  };
}

// --- NEW: Email Authenticity Analyzer ---
function renderEmailAnalyzer() {
  app.innerHTML = `
    <h2 class="fw-bold mb-4">Email Authenticity Analyzer</h2>
    <div class="row g-4">
      <div class="col-md-6">
        <div class="glass-card">
          <p class="text-muted">Paste the raw email headers (SPF, DKIM, DMARC) to verify technical authenticity.</p>
          <form id="emailForm">
            <textarea name="headers" class="form-control mb-3" rows="8" placeholder="Paste raw headers here... (e.g. Authentication-Results: spf=pass...)" required></textarea>
            <button class="btn btn-primary w-100"><i class="fa-solid fa-envelope-open-text me-2"></i> Analyze Headers</button>
          </form>
        </div>
      </div>
      <div class="col-md-6">
        <div class="glass-card h-100" id="emailResult">
          <div class="text-center m-auto text-muted"><i class="fa-solid fa-server fa-3x mb-3 opacity-50"></i><p>Awaiting headers...</p></div>
        </div>
      </div>
    </div>
  `;
  document.getElementById('emailForm').onsubmit = async (e) => {
    e.preventDefault();
    document.getElementById('emailResult').innerHTML = '<div class="m-auto"><div class="spinner-border text-info"></div></div>';
    const res = await fetch('/api/analyze/email-headers', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(Object.fromEntries(new FormData(e.target))) });
    const data = await res.json();
    document.getElementById('emailResult').innerHTML = `
      <h4 class="text-${data.level === 'critical' || data.level === 'high' ? 'danger' : 'success'} mb-3">Auth Score: ${data.score}/100</h4>
      <ul class="list-group list-group-flush bg-transparent">
        ${data.findings.map(f => `<li class="list-group-item bg-transparent text-light border-secondary px-0"><i class="fa-solid fa-check-circle text-cyan me-2"></i>${f}</li>`).join('')}
      </ul>
    `;
  };
}

// --- NEW: Trust Comparison Lab ---
function renderCompare() {
  app.innerHTML = `
    <h2 class="fw-bold mb-4">Trust Comparison Lab</h2>
    <p class="text-muted mb-4">Compare two messages or URLs side-by-side to identify patterns.</p>
    <div class="row g-4">
      <div class="col-md-6">
        <div class="glass-card border-top border-4 border-info">
          <h5 class="mb-3">Item A</h5>
          <textarea id="compareA" class="form-control mb-3" rows="5" placeholder="Paste first URL or message..."></textarea>
          <div id="resultA" class="mt-3"></div>
        </div>
      </div>
      <div class="col-md-6">
        <div class="glass-card border-top border-4 border-warning">
          <h5 class="mb-3">Item B</h5>
          <textarea id="compareB" class="form-control mb-3" rows="5" placeholder="Paste second URL or message..."></textarea>
          <div id="resultB" class="mt-3"></div>
        </div>
      </div>
    </div>
    <div class="text-center mt-4">
      <button class="btn btn-primary px-5 py-2" onclick="runComparison()"><i class="fa-solid fa-code-compare me-2"></i> Compare Both</button>
    </div>
  `;
}

async function runComparison() {
  const contentA = document.getElementById('compareA').value;
  const contentB = document.getElementById('compareB').value;
  if(!contentA || !contentB) return alert("Please fill both fields.");
  
  const fetchA = fetch('/api/scans/analyze', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({type: 'message', content: contentA}) }).then(r => r.json());
  const fetchB = fetch('/api/scans/analyze', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({type: 'message', content: contentB}) }).then(r => r.json());
  
  const [resA, resB] = await Promise.all([fetchA, fetchB]);
  
  document.getElementById('resultA').innerHTML = `<span class="badge badge-${resA.level}">Score: ${resA.score}/100</span>`;
  document.getElementById('resultB').innerHTML = `<span class="badge badge-${resB.level}">Score: ${resB.score}/100</span>`;
}

// --- NEW: Scam Connection Map (Canvas API) ---
function renderMap() {
  app.innerHTML = `
    <h2 class="fw-bold mb-4">Scam Pattern Connection Map</h2>
    <div class="glass-card p-0 overflow-hidden position-relative" style="height: 500px;">
      <canvas id="mapCanvas" style="width: 100%; height: 100%;"></canvas>
      <div class="position-absolute bottom-0 start-0 p-3">
        <span class="badge bg-dark border border-info"><i class="fa-solid fa-circle text-info me-1"></i> Malicious Domain</span>
        <span class="badge bg-dark border border-warning ms-2"><i class="fa-solid fa-circle text-warning me-1"></i> Shared IP</span>
      </div>
    </div>
  `;

  const canvas = document.getElementById('mapCanvas');
  const ctx = canvas.getContext('2d');
  canvas.width = canvas.offsetWidth;
  canvas.height = canvas.offsetHeight;

  // Fictional Threat Graph Data
  const nodes = [
    { id: 0, label: "phish-bank.com", type: "malicious", x: canvas.width/2, y: canvas.height/2 },
    { id: 1, label: "update-verify.com", type: "malicious", x: canvas.width/3, y: canvas.height/3 },
    { id: 2, label: "IP: 192.168.1.1", type: "ip", x: canvas.width/2, y: canvas.height/4 },
    { id: 3, label: "login-secure.xyz", type: "malicious", x: canvas.width/1.5, y: canvas.height/2 },
    { id: 4, label: "IP: 192.168.1.1", type: "ip", x: canvas.width/2, y: canvas.height/1.5 }
  ];

  const edges = [[0,1], [0,2], [3,2], [0,4], [1,3]];

  function draw() {
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    
    // Draw edges
    ctx.strokeStyle = 'rgba(0, 240, 255, 0.2)';
    ctx.lineWidth = 2;
    edges.forEach(([a, b]) => {
      ctx.beginPath();
      ctx.moveTo(nodes[a].x, nodes[a].y);
      ctx.lineTo(nodes[b].x, nodes[b].y);
      ctx.stroke();
    });

    // Draw nodes
    nodes.forEach(n => {
      ctx.beginPath();
      ctx.arc(n.x, n.y, 10, 0, Math.PI * 2);
      ctx.fillStyle = n.type === 'malicious' ? '#ff4757' : '#ffa502';
      ctx.fill();
      ctx.strokeStyle = '#fff'; ctx.lineWidth = 2; ctx.stroke();

      ctx.fillStyle = '#fff';
      ctx.font = '12px Inter';
      ctx.fillText(n.label, n.x + 15, n.y + 4);
    });
  }
  draw();
}

// --- Existing Academy (Unchanged) ---
function renderAcademy() {
  app.innerHTML = `
    <h2 class="fw-bold mb-4">Cybersecurity Academy</h2>
    <div class="row g-4">
      <div class="col-md-8">
        <div class="glass-card mb-4 border-start border-4 border-info">
          <div class="d-flex justify-content-between"><h4>Module 1: Spotting Phishing</h4><span class="badge bg-info text-dark">Beginner</span></div>
          <p class="text-muted mt-3">Phishing relies on urgency and fear. Always check the sender's true email address. Hover over links to see where they actually lead before clicking.</p>
          <button class="btn btn-outline-cyan" onclick="alert('Marked complete!')"><i class="fa-solid fa-check me-2"></i>Mark as Completed (+10 pts)</button>
        </div>
      </div>
    </div>
  `;
}

// --- Existing Login/History (Unchanged) ---
async function renderHistory() {
  const res = await fetch('/api/scans/history');
  const history = await res.json();
  app.innerHTML = `
    <h2 class="fw-bold mb-4">Incident Timeline ${!user ? '<span class="badge bg-secondary fs-6 ms-2">Guest Session</span>' : ''}</h2>
    <div class="glass-card">
      ${history.length ? `
        <table class="table text-light table-borderless align-middle">
          <thead class="text-muted border-bottom border-secondary"><tr><th>Type</th><th>Scanned Content</th><th>Score</th><th>Level</th><th>Date</th></tr></thead>
          <tbody>${history.map(h => `
            <tr><td class="text-capitalize"><i class="fa-solid fa-${h.scan_type === 'url' ? 'link' : 'comment'} me-2 text-cyan"></i>${h.scan_type}</td><td class="text-muted text-truncate" style="max-width: 250px;">${h.content}</td><td><b>${h.risk_score}</b>/100</td><td><span class="badge badge-${h.risk_level}">${h.risk_level}</span></td><td class="text-muted">${new Date(h.created_at).toLocaleDateString()}</td></tr>
          `).join('')}</tbody>
        </table>
      ` : '<div class="text-center py-5 text-muted"><i class="fa-solid fa-folder-open fa-3x mb-3 opacity-50"></i><p>No records found.</p></div>'}
    </div>
  `;
}

function renderLogin() {
  app.innerHTML = `
    <div class="row justify-content-center mt-5"><div class="col-md-5 glass-card">
        <h3 class="text-center text-cyan mb-4">Secure Login</h3>
        <form id="form"><input type="email" name="email" class="form-control mb-3" placeholder="Email" required><input type="password" name="password" class="form-control mb-3" placeholder="Password" required><button class="btn btn-primary w-100">Authenticate</button></form>
        <p class="text-center mt-3 text-muted small">No account? <a href="#" class="text-cyan" onclick="renderRegister()">Register here</a></p>
    </div></div>
  `;
  document.getElementById('form').onsubmit = async (e) => {
    e.preventDefault();
    const res = await fetch('/api/auth/login', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(Object.fromEntries(new FormData(e.target))) });
    if (res.ok) { user = (await res.json()).user; renderNav(); navigate('dashboard'); } else alert('Invalid credentials');
  };
}

function renderRegister() {
  app.innerHTML = `
    <div class="row justify-content-center mt-5"><div class="col-md-5 glass-card">
        <h3 class="text-center text-cyan mb-4">Create Account</h3>
        <form id="form"><input type="text" name="username" class="form-control mb-3" placeholder="Username" required><input type="email" name="email" class="form-control mb-3" placeholder="Email" required><input type="password" name="password" class="form-control mb-3" placeholder="Password" required><button class="btn btn-primary w-100">Register</button></form>
    </div></div>
  `;
  document.getElementById('form').onsubmit = async (e) => {
    e.preventDefault();
    const res = await fetch('/api/auth/register', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(Object.fromEntries(new FormData(e.target))) });
    if (res.ok) { alert('Registered! Please login.'); navigate('login'); } else alert('Error registering');
  };
}

async function logout() {
  await fetch('/api/auth/logout', { method: 'POST' });
  user = null; renderNav(); navigate('dashboard');
}

init();