require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const session = require('express-session');
const MySQLStore = require('express-mysql-session')(session);
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');

const app = express();
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 200 });
app.use('/api/', limiter);

const pool = mysql.createPool({
  host: process.env.DB_HOST, user: process.env.DB_USER,
  password: process.env.DB_PASSWORD, database: process.env.DB_NAME
});

const sessionStore = new MySQLStore({}, pool);
app.use(session({
  key: 'trustlens.sid', secret: process.env.SESSION_SECRET,
  store: sessionStore, resave: false, saveUninitialized: true,
  cookie: { httpOnly: true, secure: false, sameSite: 'lax', maxAge: 1000 * 60 * 60 * 24 } // 24 hours
}));

// --- Middleware ---
const requireAuth = (req, res, next) => {
  if (!req.session.user) return res.status(401).json({ error: 'Please login to access this feature.' });
  next();
};
const requireAdmin = (req, res, next) => {
  if (!req.session.user || req.session.user.role !== 'admin') return res.status(403).json({ error: 'Admin access required.' });
  next();
};

// --- Advanced Risk Engine ---
function analyzeRisk(type, content) {
  let score = 0;
  let findings = [];
  const lower = content.toLowerCase();

  if (type === 'message' || type === 'job') {
    if (/(urgent|act now|limited time|immediately)/.test(lower)) { score += 25; findings.push('High-pressure urgency tactics detected.'); }
    if (/(password|otp|pin|ssn|credit card|bank)/.test(lower)) { score += 40; findings.push('Requests highly sensitive personal/financial information.'); }
    if (/(prize|winner|lottery|crypto|bitcoin|upfront fee|wire transfer)/.test(lower)) { score += 20; findings.push('Financial bait or upfront payment request.'); }
    if (/(click here|verify your account|suspended)/.test(lower)) { score += 15; findings.push('Common phishing phrasing detected.'); }
  }

  if (type === 'url') {
    if (!lower.startsWith('https://')) { score += 20; findings.push('Insecure connection (No HTTPS).'); }
    if (/(bit\.ly|tinyurl|t\.co)/.test(lower)) { score += 30; findings.push('URL shortener used to hide the true destination.'); }
    if (/(login|verify|secure|update|account)/.test(lower)) { score += 15; findings.push('Contains security-themed keywords used in phishing.'); }
    if (/\.(tk|ml|ga|cf|gq|zip)$/.test(lower)) { score += 25; findings.push('Suspicious top-level domain extension.'); }
  }

  score = Math.min(score, 100);
  const level = score >= 75 ? 'critical' : score >= 50 ? 'high' : score >= 25 ? 'medium' : 'low';
  if (findings.length === 0) findings.push('No known scam indicators detected. Remember: this is not a guarantee of absolute safety.');
  
  return { score, level, findings };
}

// --- APIs ---

// 1. Auth
app.post('/api/auth/register', async (req, res) => {
  const { username, email, password } = req.body;
  const hash = await bcrypt.hash(password, 12);
  try {
    const [result] = await pool.query('INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)', [username, email, hash]);
    await pool.query('INSERT INTO user_progress (user_id) VALUES (?)', [result.insertId]);
    res.status(201).json({ message: 'Account created' });
  } catch (e) { res.status(400).json({ error: 'Email or username already exists' }); }
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  const [rows] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
  if (!rows.length) return res.status(401).json({ error: 'Invalid credentials' });
  const valid = await bcrypt.compare(password, rows[0].password_hash);
  if (!valid) return res.status(401).json({ error: 'Invalid credentials' });
  req.session.user = { id: rows[0].id, username: rows[0].username, role: rows[0].role };
  res.json({ user: req.session.user });
});

app.get('/api/auth/me', (req, res) => res.json({ user: req.session.user || null }));
app.post('/api/auth/logout', (req, res) => { req.session.destroy(); res.clearCookie('trustlens.sid'); res.json({ success: true }); });

// 2. Scanner & History
app.post('/api/scans/analyze', async (req, res) => {
  const { type, content } = req.body;
  const { score, level, findings } = analyzeRisk(type, content);
  
  const scanRecord = {
    id: 'SCAN-' + Math.random().toString(36).substr(2, 9).toUpperCase(),
    scan_type: type, content, risk_score: score, risk_level: level, findings,
    created_at: new Date()
  };

  if (req.session.user) {
    const [dbResult] = await pool.query(
      'INSERT INTO scans (user_id, scan_type, content, risk_score, risk_level, findings) VALUES (?, ?, ?, ?, ?, ?)',
      [req.session.user.id, type, content, score, level, JSON.stringify(findings)]
    );
    scanRecord.id = dbResult.insertId;
  } else {
    if (!req.session.guestScans) req.session.guestScans = [];
    req.session.guestScans.unshift(scanRecord);
    if (req.session.guestScans.length > 10) req.session.guestScans.pop();
  }
  res.json(scanRecord);
});

app.get('/api/scans/history', (req, res) => {
  if (!req.session.user) return res.json(req.session.guestScans || []);
  pool.query('SELECT * FROM scans WHERE user_id = ? ORDER BY created_at DESC LIMIT 20', [req.session.user.id])
    .then(([rows]) => res.json(rows));
});

app.get('/api/user/stats', async (req, res) => {
  if (!req.session.user) return res.json({ totalScans: req.session.guestScans ? req.session.guestScans.length : 0, highRisk: req.session.guestScans ? req.session.guestScans.filter(s => s.risk_score > 50).length : 0, points: 0 });
  
  const [[{ totalScans }]] = await pool.query('SELECT COUNT(*) as totalScans FROM scans WHERE user_id = ?', [req.session.user.id]);
  const [[{ highRisk }]] = await pool.query("SELECT COUNT(*) as highRisk FROM scans WHERE user_id = ? AND risk_level IN ('high', 'critical')", [req.session.user.id]);
  const [[{ points }]] = await pool.query('SELECT points FROM user_progress WHERE user_id = ?', [req.session.user.id]);
  res.json({ totalScans, highRisk, points });
});

// 3. Admin
app.get('/api/admin/stats', requireAdmin, async (req, res) => {
  const [[{ users }]] = await pool.query('SELECT COUNT(*) as users FROM users');
  const [[{ scans }]] = await pool.query('SELECT COUNT(*) as scans FROM scans');
  const [[{ reports }]] = await pool.query("SELECT COUNT(*) as reports FROM community_reports WHERE status = 'pending'");
  res.json({ users, scans, reports });
});

app.listen(process.env.PORT, () => {
  console.log(`\n=========================================`);
  console.log(`🚀 TrustLens Enterprise is LIVE!`);
  console.log(`🌐 Open: http://localhost:${process.env.PORT}`);
  console.log(`=========================================\n`);
});


// --- NEW: Email Authenticity Analyzer ---
app.post('/api/analyze/email-headers', (req, res) => {
  const { headers } = req.body;
  let findings = [];
  let score = 0;
  const lower = headers.toLowerCase();

  // SPF Check
  if (lower.includes('spf=fail') || lower.includes('spf=softfail')) {
    score += 30;
    findings.push('SPF check failed. The sender does not have permission to send from this domain.');
  } else if (lower.includes('spf=pass')) {
    findings.push('SPF check passed. The sender IP is authorized by the domain.');
  }

  // DKIM Check
  if (lower.includes('dkim=fail')) {
    score += 30;
    findings.push('DKIM signature failed. The email may have been tampered with in transit.');
  } else if (lower.includes('dkim=pass')) {
    findings.push('DKIM check passed. The email signature is cryptographically valid.');
  }

  // DMARC Check
  if (lower.includes('dmarc=fail')) {
    score += 40;
    findings.push('DMARC policy failed. The email claims to be from a domain that rejects unauthorized mail.');
  }

  // Sender Mismatch (Reply-To differs from From)
  const fromMatch = headers.match(/From:.*?([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/i);
  const replyMatch = headers.match(/Reply-To:.*?([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/i);
  if (fromMatch && replyMatch && fromMatch[1] !== replyMatch[1]) {
    score += 20;
    findings.push(`Sender mismatch: From domain (${fromMatch[1]}) differs from Reply-To domain (${replyMatch[1]}).`);
  }

  score = Math.min(score, 100);
  const level = score >= 70 ? 'critical' : score >= 40 ? 'high' : 'low';
  
  if (findings.length === 0) findings.push('No major authentication failures detected in the provided headers.');

  res.json({ score, level, findings });
});