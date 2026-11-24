const express = require('express');
const { Pool } = require('pg');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
const util = require('util');
const helmet = require('helmet');
const { rateLimit } = require('express-rate-limit');
const scryptAsync = util.promisify(crypto.scrypt);

const app = express();
app.set('trust proxy', 1);

const APP_URL = (process.env.APP_URL || 'http://localhost:3000').replace(/\/$/, '');
const ADMINS = (process.env.ADMIN_EMAILS || '').split(',').map(s => s.trim().toLowerCase()).filter(Boolean);
const SECURE_COOKIE = APP_URL.startsWith('https://');

// Helper de registro de eventos de seguridad (Punto 12)
function logSecurityEvent(level, event, req, details = {}) {
  const ts = new Date().toISOString();
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || req.ip;
  const user = req.user ? `${req.user.id} (${req.user.email})` : 'anon';
  console[level === 'error' ? 'error' : 'warn'](
    `[SEGURIDAD][${ts}][${event}] IP=${ip} User=${user} Path=${req.method} ${req.originalUrl} | ${JSON.stringify(details)}`
  );
}

// 1. Redirección HTTPS y forzado de HSTS (Punto 18)
app.use((req, res, next) => {
  if (SECURE_COOKIE && req.headers['x-forwarded-proto'] && req.headers['x-forwarded-proto'] !== 'https') {
    return res.redirect(301, 'https://' + req.headers.host + req.originalUrl);
  }
  if (SECURE_COOKIE) {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
  }
  next();
});

// 2. Bloqueo tajante de archivos expuestos, configuraciones y respaldos (Punto 25)
app.use((req, res, next) => {
  const p = decodeURIComponent(req.path).toLowerCase();
  if (
    p.includes('.env') ||
    p.includes('.git') ||
    p.includes('.sql') ||
    p.includes('.bak') ||
    p.includes('.config') ||
    p.includes('docker') ||
    p.startsWith('/package')
  ) {
    logSecurityEvent('warn', 'ARCHIVO_SENSIBLE_BLOQUEADO', req, { path: req.path });
    return res.status(403).type('text/plain').send('Acceso denegado.');
  }
  next();
});

// 3. Política CORS restrictiva (Punto 20)
app.use((req, res, next) => {
  const origin = req.headers.origin;
  const allowedOrigins = [
    APP_URL,
    'http://localhost:3000',
    'http://localhost:8080'
  ].filter(Boolean);
  if (origin) {
    const isAllowed = allowedOrigins.includes(origin);
    if (isAllowed) {
      res.setHeader('Access-Control-Allow-Origin', origin);
      res.setHeader('Access-Control-Allow-Credentials', 'true');
      res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
      res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With');
    } else {
      logSecurityEvent('warn', 'CORS_RECHAZADO', req, { origin });
      return res.status(403).json({ error: 'Origen no autorizado por política CORS.' });
    }
  }
  if (req.method === 'OPTIONS') {
    return res.status(204).end();
  }
  next();
});

// Cabeceras de seguridad HTTP con Content Security Policy adaptada para SPA vanilla
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:"],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      baseUri: ["'self'"],
      frameAncestors: ["'none'"],
    }
  },
  crossOriginEmbedderPolicy: false,
}));

app.use(express.json({ limit: '1mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// Directorio de avatares subidos
const AVATARS_DIR = path.join(__dirname, 'public', 'uploads', 'avatars');
try { fs.mkdirSync(AVATARS_DIR, { recursive: true }); } catch (e) {}

// Limitador de tasa profesional con express-rate-limit
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Demasiados intentos. Por favor espera unos minutos.' }
});

const forgotLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Demasiadas solicitudes de recuperación. Inténtalo más tarde.' }
});

// Limitador de tasa global para endpoints de la API (Punto 19)
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 300,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Demasiadas peticiones a la API. Espera unos minutos.' }
});
app.use('/api/', apiLimiter);

// Pool de base de datos con configuración de resiliencia y timeouts
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000
});

pool.on('error', (err) => {
  console.error('Error imprevisto en cliente inactivo del pool PostgreSQL:', err);
});

// Secuencia de versión global para soporte de ETag / HTTP 304 en snapshot
let stateVersion = Date.now();
function touchState() { stateVersion = Date.now(); }

const COLLECTIONS = ['players', 'ratings', 'matches', 'signups', 'fantasy', 'statsby', 'votes', 'seasons', 'preds'];
// Colecciones donde cada jugador puede escribir su propio documento (id = su id de usuario)
const OWNED = new Set(['players', 'signups', 'fantasy', 'statsby', 'votes', 'preds']);

const mailer = process.env.SMTP_HOST ? nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: Number(process.env.SMTP_PORT || 587),
  secure: process.env.SMTP_SECURE === 'true',
  auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
}) : null;

async function sendMail(to, subject, text) {
  if (!mailer) { console.log('[correo sin SMTP configurado]', to, subject, text); return; }
  await mailer.sendMail({ from: process.env.SMTP_FROM, to, subject, text });
}

async function initDb() {
  await pool.query(`CREATE TABLE IF NOT EXISTS users (
    id text PRIMARY KEY,
    email text UNIQUE NOT NULL,
    pass_hash text NOT NULL,
    verified boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now())`);
  await pool.query(`CREATE TABLE IF NOT EXISTS tokens (
    token text PRIMARY KEY,
    user_id text NOT NULL,
    kind text NOT NULL,
    expires_at timestamptz NOT NULL)`);
  await pool.query(`CREATE TABLE IF NOT EXISTS sessions (
    token text PRIMARY KEY,
    user_id text NOT NULL,
    expires_at timestamptz NOT NULL)`);
  await pool.query(`CREATE TABLE IF NOT EXISTS docs (
    collection text NOT NULL,
    id text NOT NULL,
    data jsonb NOT NULL,
    PRIMARY KEY (collection, id))`);

  // Índices para optimizar autenticación y consultas
  await pool.query('CREATE INDEX IF NOT EXISTS idx_tokens_user_kind ON tokens (user_id, kind)');
  await pool.query('CREATE INDEX IF NOT EXISTS idx_tokens_expires ON tokens (expires_at)');
  await pool.query('CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions (user_id)');
  await pool.query('CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions (expires_at)');
}

async function cleanupExpiredSessionsAndTokens() {
  try {
    await pool.query('DELETE FROM sessions WHERE expires_at < now()');
    await pool.query('DELETE FROM tokens WHERE expires_at < now()');
  } catch (err) {
    console.error('Error en purga periódica de sesiones/tokens:', err);
  }
}
setInterval(cleanupExpiredSessionsAndTokens, 6 * 3600 * 1000).unref();

async function hashPass(pass) {
  const salt = crypto.randomBytes(16).toString('hex');
  const buf = await scryptAsync(pass, salt, 64);
  return salt + ':' + buf.toString('hex');
}
async function checkPass(pass, stored) {
  if (!stored || typeof stored !== 'string' || !stored.includes(':')) return false;
  const [salt, hash] = stored.split(':');
  if (!salt || !hash) return false;
  try {
    const test = await scryptAsync(pass, salt, 64);
    const hashBuf = Buffer.from(hash, 'hex');
    if (test.length !== hashBuf.length) return false;
    return crypto.timingSafeEqual(hashBuf, test);
  } catch (e) {
    return false;
  }
}
const token = () => crypto.randomBytes(32).toString('hex');
const normEmail = e => String(e || '').trim().toLowerCase();
const validEmail = e => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e);

function getSid(req) {
  const m = (req.headers.cookie || '').match(/(?:^|;\s*)sid=([a-f0-9]{64})/);
  return m ? m[1] : null;
}
function setSession(res, t) {
  res.setHeader('Set-Cookie', `sid=${t}; HttpOnly; SameSite=Lax; Path=/; Max-Age=2592000${SECURE_COOKIE ? '; Secure' : ''}`);
}

async function requireUser(req, res, next) {
  try {
    const sid = getSid(req);
    if (!sid) return res.status(401).json({ error: 'Inicia sesión.' });
    const r = await pool.query(
      `SELECT u.id, u.email FROM sessions s JOIN users u ON u.id = s.user_id
       WHERE s.token = $1 AND s.expires_at > now() AND u.verified`, [sid]);
    if (!r.rows[0]) return res.status(401).json({ error: 'Inicia sesión.' });
    req.user = r.rows[0];
    req.isAdmin = ADMINS.includes(req.user.email);
    next();
  } catch (e) { next(e); }
}

/* ---------- Documentos y plazo de votación ---------- */
async function getDoc(collection, id, client = pool) {
  const r = await client.query('SELECT data FROM docs WHERE collection = $1 AND id = $2', [collection, id]);
  return r.rows[0] ? r.rows[0].data : null;
}
const lineupOf = m => (m.teamA || []).concat(m.teamB || []);
// Partidos antiguos sin fecha de jugado: se cuenta desde la hora del partido (hora de Madrid, verano)
function closesAtMs(m) {
  if (m.playedAt) return m.playedAt + 24 * 3600 * 1000;
  return Date.parse(m.date + 'T' + (m.time || '20:30') + ':00+02:00') + 24 * 3600 * 1000;
}

// Evaluación en memoria del estado de cierre de votaciones (0 consultas SQL adicionales)
function checkVotesClosedInMemory(m, votesByPlayer) {
  if (!m || m.status !== 'played' || m.scoreA == null || m.scoreB == null) return false;
  if (Date.now() >= closesAtMs(m)) return true;
  const ids = lineupOf(m);
  if (ids.length < 2) return false;
  return ids.every(a => ids.every(b => a === b || (
    votesByPlayer[a] && votesByPlayer[a].matches && votesByPlayer[a].matches[m.id] && votesByPlayer[a].matches[m.id][b] != null
  )));
}

async function votesClosed(m, client = pool) {
  if (!m || m.status !== 'played' || m.scoreA == null || m.scoreB == null) return false;
  if (Date.now() >= closesAtMs(m)) return true;
  const ids = lineupOf(m);
  if (ids.length < 2) return false;
  const r = await client.query("SELECT id, data FROM docs WHERE collection = 'votes' AND id = ANY($1)", [ids]);
  const byId = {};
  r.rows.forEach(x => { byId[x.id] = x.data; });
  return ids.every(a => ids.every(b => a === b || (byId[a] && byId[a].matches && byId[a].matches[m.id] && byId[a].matches[m.id][b] != null)));
}

// Valida un cambio de notas: solo partidos abiertos a votación, notas de 1 a 10 de 0,5 en 0,5, y solo entre jugadores del partido
async function checkVotes(voterId, data, client = pool) {
  const existing = (await getDoc('votes', voterId, client)) || {};
  const oldM = existing.matches || {}, newM = data.matches || {};
  const mids = new Set(Object.keys(oldM).concat(Object.keys(newM)));
  for (const mid of mids) {
    if (JSON.stringify(oldM[mid] || {}) === JSON.stringify(newM[mid] || {})) continue;
    const m = await getDoc('matches', mid, client);
    if (!m) return 'Ese partido ya no existe.';
    if (m.status !== 'played' || m.scoreA == null || m.scoreB == null) {
      return 'Las votaciones no están abiertas hasta que el administrador publique el resultado oficial.';
    }
    if (await votesClosed(m, client)) return 'La votación de ese partido ya está cerrada.';
    const ids = lineupOf(m);
    if (ids.indexOf(voterId) < 0) return 'Solo puedes puntuar en partidos en los que juegas.';
    for (const t of Object.keys(newM[mid] || {})) {
      const v = newM[mid][t];
      if (ids.indexOf(t) < 0 || t === voterId) return 'Nota no válida.';
      if (typeof v !== 'number' || v < 1 || v > 10 || (v * 2) % 1 !== 0) return 'Las notas van de 1 a 10, de 0,5 en 0,5.';
    }
  }
  return null;
}

// Valida goles y asistencias con bloqueo transaccional para evitar condiciones de carrera (TOCTOU)
async function checkStats(playerId, data, client = pool) {
  const existing = (await getDoc('statsby', playerId, client)) || {};
  const oldM = existing.matches || {}, newM = data.matches || {};
  const mids = new Set(Object.keys(oldM).concat(Object.keys(newM)));
  for (const mid of mids) {
    if (JSON.stringify(oldM[mid] || {}) === JSON.stringify(newM[mid] || {})) continue;
    // Bloqueo consultivo a nivel de transacción para serializar la validación de estadísticas por partido
    if (client && client.query) {
      await client.query('SELECT pg_advisory_xact_lock(hashtext($1))', ['match_stats:' + mid]);
    }
    const m = await getDoc('matches', mid, client);
    if (!m) return 'Ese partido ya no existe.';
    if (m.status !== 'played' || m.scoreA == null || m.scoreB == null) {
      return 'No se pueden anotar goles ni asistencias hasta que el administrador publique el resultado oficial.';
    }
    const isA = (m.teamA || []).indexOf(playerId) > -1;
    const isB = (m.teamB || []).indexOf(playerId) > -1;
    if (!isA && !isB) return 'Solo los jugadores del partido pueden anotar estadísticas.';

    const side = isA ? 'A' : 'B';
    const teamIds = isA ? (m.teamA || []) : (m.teamB || []);
    const maxG = side === 'A' ? Number(m.scoreA) : Number(m.scoreB);

    const stat = newM[mid] || {};
    const g = Number(stat.g || 0);
    const a = Number(stat.a || 0);
    if (!Number.isInteger(g) || g < 0 || !Number.isInteger(a) || a < 0) {
      return 'Goles y asistencias deben ser números enteros no negativos.';
    }

    // Consultar statsby de los demás compañeros de equipo en este partido
    const otherIds = teamIds.filter(id => id !== playerId);
    let otherG = 0, otherA = 0;
    if (otherIds.length) {
      const r = await client.query("SELECT id, data FROM docs WHERE collection = 'statsby' AND id = ANY($1)", [otherIds]);
      r.rows.forEach(row => {
        const sm = (row.data && row.data.matches && row.data.matches[mid]) || {};
        otherG += Number(sm.g || 0);
        otherA += Number(sm.a || 0);
      });
    }

    const totalG = otherG + g;
    const totalA = otherA + a;

    if (totalG > maxG) {
      return `Los goles del equipo (${totalG}) superan el resultado oficial (${maxG}).`;
    }
    if (totalA > totalG) {
      return `Las asistencias del equipo (${totalA}) no pueden superar los goles marcados (${totalG}).`;
    }
  }
  return null;
}

// Valida plantilla de Fantasy: máximo 5 jugadores, presupuesto oficial de 40M y pertenencia del capitán
async function checkFantasy(playerId, data, client = pool) {
  const squad = data.squad || [];
  if (!Array.isArray(squad)) return 'La plantilla debe ser una lista de jugadores.';
  if (squad.length > 5) return 'La plantilla no puede tener más de 5 jugadores.';
  if (squad.length === 0) return null; // Plantilla vacía permitida

  if (new Set(squad).size !== squad.length) {
    return 'No puedes seleccionar al mismo jugador varias veces en la plantilla.';
  }

  // Comprobar que los jugadores seleccionados existen en la colección players
  const r = await client.query("SELECT id, data FROM docs WHERE collection = 'players' AND id = ANY($1)", [squad]);
  if (r.rows.length !== squad.length) {
    return 'Uno o más jugadores de la plantilla no existen.';
  }

  // Obtener valoraciones oficiales para calcular el precio
  const ratRes = await client.query("SELECT id, data FROM docs WHERE collection = 'ratings' AND id = ANY($1)", [squad]);
  const ratingsMap = {};
  ratRes.rows.forEach(row => {
    if (row.data && row.data.rating != null) ratingsMap[row.id] = Number(row.data.rating);
  });

  let totalCost = 0;
  for (const row of r.rows) {
    const pid = row.id;
    const p = row.data || {};
    const rating = ratingsMap[pid] != null ? ratingsMap[pid] : Number(p.rating || 75);
    const price = Math.max(2, Math.round((2 + (rating - 50) * 0.2) * 10) / 10);
    totalCost += price;
  }
  totalCost = Math.round(totalCost * 10) / 10;

  if (totalCost > 40.001) {
    return `Presupuesto insuficiente: el coste de la plantilla (${totalCost} M€) supera los 40 M€.`;
  }

  if (data.captain && !squad.includes(data.captain)) {
    return 'El capitán debe formar parte de los jugadores de tu plantilla.';
  }
  return null;
}

// Valida pronósticos: opciones válidas (A, D, B) y partidos abiertos antes de la hora de juego
async function checkPreds(playerId, data, client = pool) {
  const matches = data.matches || {};
  if (typeof matches !== 'object' || Array.isArray(matches)) {
    return 'Formato de pronósticos no válido.';
  }
  for (const [mid, pick] of Object.entries(matches)) {
    if (!['A', 'D', 'B'].includes(pick)) {
      return 'Opción de pronóstico no válida (debe ser A, D o B).';
    }
    const m = await getDoc('matches', mid, client);
    if (!m) return 'El partido pronosticado ya no existe.';
    if (m.status !== 'open') {
      return 'No se pueden enviar pronósticos de partidos cerrados o jugados.';
    }
    const kickoff = Date.parse(m.date + 'T' + (m.time || '20:30') + ':00+02:00');
    if (!isNaN(kickoff) && Date.now() >= kickoff) {
      return 'El plazo de pronósticos para este partido ya ha finalizado.';
    }
  }
  return null;
}

/* ---------- Registro, confirmación y sesión ---------- */
app.post('/api/register', authLimiter, async (req, res, next) => {
  try {
    const email = normEmail(req.body.email), pass = String(req.body.password || '');
    if (!validEmail(email)) return res.status(400).json({ error: 'El email no es válido.' });
    if (pass.length < 8) return res.status(400).json({ error: 'La contraseña debe tener al menos 8 caracteres.' });
    const msg = 'Te hemos enviado un correo para confirmar tu cuenta. Ábrelo y pulsa el enlace.';
    const exists = await pool.query('SELECT id, verified FROM users WHERE email = $1', [email]);
    if (exists.rows[0]) {
      if (exists.rows[0].verified) {
        return res.status(400).json({ error: 'Si ya tienes cuenta con este email, inicia sesión o pulsa en recuperar contraseña.' });
      }
      // Cuenta existente no confirmada: renovamos token y reenviamos el correo
      const t = token();
      await pool.query("DELETE FROM tokens WHERE user_id = $1 AND kind = 'verify'", [exists.rows[0].id]);
      await pool.query("INSERT INTO tokens (token, user_id, kind, expires_at) VALUES ($1, $2, 'verify', now() + interval '48 hours')", [t, exists.rows[0].id]);
      await sendMail(email, 'Confirma tu cuenta de Barrio de Fantasía',
        `Pulsa este enlace para confirmar tu cuenta (caduca en 48 horas):\n${APP_URL}/api/verify?token=${t}`);
      return res.json({ ok: true, msg });
    }
    const id = crypto.randomUUID();
    const hash = await hashPass(pass);
    await pool.query('INSERT INTO users (id, email, pass_hash) VALUES ($1, $2, $3)', [id, email, hash]);
    const t = token();
    await pool.query("INSERT INTO tokens (token, user_id, kind, expires_at) VALUES ($1, $2, 'verify', now() + interval '48 hours')", [t, id]);
    await sendMail(email, 'Confirma tu cuenta de Barrio de Fantasía',
      `Pulsa este enlace para confirmar tu cuenta (caduca en 48 horas):\n${APP_URL}/api/verify?token=${t}`);
    res.json({ ok: true, msg });
  } catch (e) { next(e); }
});

app.get('/api/verify', async (req, res, next) => {
  const client = await pool.connect();
  try {
    const t = String(req.query.token || '');
    await client.query('BEGIN');
    const r = await client.query("SELECT user_id FROM tokens WHERE token = $1 AND kind = 'verify' AND expires_at > now() FOR UPDATE", [t]);
    if (!r.rows[0]) {
      await client.query('ROLLBACK');
      return res.status(400).send('Este enlace no es válido o ha caducado.');
    }
    const uid = r.rows[0].user_id;
    await client.query('UPDATE users SET verified = true WHERE id = $1', [uid]);
    await client.query('DELETE FROM tokens WHERE token = $1', [t]);
    // Inicio de sesión automático al verificar enlace
    const sid = token();
    await client.query("INSERT INTO sessions (token, user_id, expires_at) VALUES ($1, $2, now() + interval '30 days')", [sid, uid]);
    await client.query('COMMIT');
    setSession(res, sid);
    res.redirect('/?verificado=1');
  } catch (e) {
    await client.query('ROLLBACK').catch(() => {});
    next(e);
  } finally {
    client.release();
  }
});

/* ---------- Recuperar contraseña ---------- */
app.post('/api/forgot', forgotLimiter, async (req, res, next) => {
  try {
    const email = normEmail(req.body.email);
    const msg = 'Si el email existe, te hemos enviado un enlace para cambiar la contraseña.';
    const r = await pool.query('SELECT id FROM users WHERE email = $1 AND verified', [email]);
    if (r.rows[0]) {
      const t = token();
      await pool.query("DELETE FROM tokens WHERE user_id = $1 AND kind = 'reset'", [r.rows[0].id]);
      await pool.query("INSERT INTO tokens (token, user_id, kind, expires_at) VALUES ($1, $2, 'reset', now() + interval '1 hour')", [t, r.rows[0].id]);
      await sendMail(email, 'Cambiar la contraseña de Barrio de Fantasía',
        `Pulsa este enlace para elegir una contraseña nueva (caduca en 1 hora):\n${APP_URL}/?reset=${t}`);
    }
    res.json({ ok: true, msg });
  } catch (e) { next(e); }
});

app.post('/api/reset', forgotLimiter, async (req, res, next) => {
  const client = await pool.connect();
  try {
    const t = String(req.body.token || ''), pass = String(req.body.password || '');
    if (pass.length < 8) return res.status(400).json({ error: 'La contraseña debe tener al menos 8 caracteres.' });
    await client.query('BEGIN');
    const r = await client.query("SELECT user_id FROM tokens WHERE token = $1 AND kind = 'reset' AND expires_at > now() FOR UPDATE", [t]);
    if (!r.rows[0]) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'Este enlace no es válido o ha caducado. Pide otro.' });
    }
    const uid = r.rows[0].user_id;
    const newHash = await hashPass(pass);
    await client.query('UPDATE users SET pass_hash = $1 WHERE id = $2', [newHash, uid]);
    await client.query("DELETE FROM tokens WHERE user_id = $1 AND kind = 'reset'", [uid]);
    await client.query('DELETE FROM sessions WHERE user_id = $1', [uid]);
    await client.query('COMMIT');
    res.json({ ok: true, msg: 'Contraseña cambiada. Ya puedes entrar con la nueva.' });
  } catch (e) {
    await client.query('ROLLBACK').catch(() => {});
    next(e);
  } finally {
    client.release();
  }
});

app.post('/api/login', authLimiter, async (req, res, next) => {
  try {
    const email = normEmail(req.body.email), pass = String(req.body.password || '');
    const r = await pool.query('SELECT id, pass_hash, verified FROM users WHERE email = $1', [email]);
    const u = r.rows[0];
    if (!u || !(await checkPass(pass, u.pass_hash))) {
      logSecurityEvent('warn', 'LOGIN_FALLIDO', req, { email });
      return res.status(401).json({ error: 'Email o contraseña incorrectos.' });
    }
    if (!u.verified) {
      logSecurityEvent('warn', 'LOGIN_NO_VERIFICADO', req, { email });
      return res.status(403).json({ error: 'Confirma tu email antes de entrar. Revisa tu correo.' });
    }
    const t = token();
    await pool.query("INSERT INTO sessions (token, user_id, expires_at) VALUES ($1, $2, now() + interval '30 days')", [t, u.id]);
    setSession(res, t);
    res.json({ ok: true });
  } catch (e) { next(e); }
});

app.post('/api/logout', async (req, res, next) => {
  try {
    const sid = getSid(req);
    if (sid) await pool.query('DELETE FROM sessions WHERE token = $1', [sid]);
    res.setHeader('Set-Cookie', 'sid=; Path=/; Max-Age=0');
    res.json({ ok: true });
  } catch (e) { next(e); }
});

/* ---------- Healthcheck y Observabilidad ---------- */
app.get('/api/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.status(200).json({ status: 'ok', uptime: Math.floor(process.uptime()), v: stateVersion });
  } catch (err) {
    res.status(503).json({ status: 'error', error: 'Base de datos no accesible' });
  }
});

/* ---------- Datos ---------- */
app.get('/api/me', requireUser, async (req, res, next) => {
  try {
    const p = await pool.query("SELECT data FROM docs WHERE collection = 'players' AND id = $1", [req.user.id]);
    res.json({ id: req.user.id, email: req.user.email, name: (p.rows[0] && p.rows[0].data.name) || '', isAdmin: req.isAdmin });
  } catch (e) { next(e); }
});

// Snapshot completo con soporte de ETag / HTTP 304 Not Modified y 0 consultas N+1
app.get('/api/snapshot', requireUser, async (req, res, next) => {
  try {
    const clientEtag = req.headers['if-none-match'];
    const currentEtag = `W/"${stateVersion}-${req.isAdmin ? 'adm' : req.user.id}"`;
    if (clientEtag === currentEtag) {
      return res.status(304).end();
    }

    const r = await pool.query('SELECT collection, id, data FROM docs');
    const collections = {};
    COLLECTIONS.forEach(c => { collections[c] = {}; });
    r.rows.forEach(row => { if (collections[row.collection]) collections[row.collection][row.id] = row.data; });

    // Privacidad de votaciones: Si el usuario no es admin, ocultar notas de partidos cuya votación siga abierta
    if (!req.isAdmin && collections.votes && collections.matches) {
      const matchesList = Object.values(collections.matches);
      const openMatchIds = new Set();
      for (const m of matchesList) {
        // Validación en memoria sin consultas N+1
        if (!checkVotesClosedInMemory(m, collections.votes || {})) {
          openMatchIds.add(m.id);
        }
      }

      if (openMatchIds.size > 0) {
        const sanitizedVotes = {};
        for (const [voterId, voteDoc] of Object.entries(collections.votes)) {
          if (voterId === req.user.id) {
            sanitizedVotes[voterId] = voteDoc;
          } else {
            const filteredMatches = {};
            const docMatches = (voteDoc && voteDoc.matches) || {};
            for (const [mId, mVotes] of Object.entries(docMatches)) {
              if (!openMatchIds.has(mId)) {
                filteredMatches[mId] = mVotes;
              }
            }
            sanitizedVotes[voterId] = { ...voteDoc, matches: filteredMatches };
          }
        }
        collections.votes = sanitizedVotes;
      }
    }

    res.setHeader('ETag', currentEtag);
    res.setHeader('Cache-Control', 'private, no-cache');
    const name = (collections.players[req.user.id] || {}).name || '';
    res.json({ collections, me: { id: req.user.id, email: req.user.email, name, isAdmin: req.isAdmin } });
  } catch (e) { next(e); }
});

/* ---------- Endpoints dedicados para gestión atómica de partidos ---------- */
// Asignación de posición táctica por el propio jugador
app.post('/api/matches/:id/role', requireUser, async (req, res, next) => {
  const client = await pool.connect();
  try {
    const { id } = req.params;
    const targetPid = req.body.pid || req.user.id;
    const role = req.body.role;
    if (!req.isAdmin && targetPid !== req.user.id) {
      return res.status(403).json({ error: 'Solo puedes cambiar tu propia posición.' });
    }
    if (!['POR', 'DEF', 'MED', 'DEL'].includes(role)) {
      return res.status(400).json({ error: 'Posición no válida.' });
    }
    await client.query('BEGIN');
    const r = await client.query("SELECT data FROM docs WHERE collection = 'matches' AND id = $1 FOR UPDATE", [id]);
    if (!r.rows[0]) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Partido no encontrado.' });
    }
    const m = r.rows[0].data;
    if (m.status !== 'open') {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'El partido no está abierto.' });
    }
    const inLineup = (m.teamA || []).includes(targetPid) || (m.teamB || []).includes(targetPid);
    if (!inLineup) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'El jugador no forma parte de ningún equipo.' });
    }
    m.roles = m.roles || {};
    m.roles[targetPid] = role;
    await client.query("UPDATE docs SET data = $1 WHERE collection = 'matches' AND id = $2", [JSON.stringify(m), id]);
    await client.query('COMMIT');
    touchState();
    res.json({ ok: true, roles: m.roles });
  } catch (e) {
    await client.query('ROLLBACK').catch(() => {});
    next(e);
  } finally {
    client.release();
  }
});

// Inscripción y desconvocatoria con sincronización atómica de lista de espera y equipos
app.post('/api/matches/:id/toggle-sign', requireUser, async (req, res, next) => {
  const client = await pool.connect();
  try {
    const { id } = req.params;
    const targetPid = req.body.pid || req.user.id;
    if (!req.isAdmin && targetPid !== req.user.id) {
      return res.status(403).json({ error: 'No tienes permiso.' });
    }
    await client.query('BEGIN');
    const mr = await client.query("SELECT data FROM docs WHERE collection = 'matches' AND id = $1 FOR UPDATE", [id]);
    if (!mr.rows[0]) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Partido no encontrado.' });
    }
    const m = mr.rows[0].data;
    if (m.status !== 'open') {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'El partido no está abierto.' });
    }

    const sr = await client.query("SELECT data FROM docs WHERE collection = 'signups' AND id = $1 FOR UPDATE", [targetPid]);
    const sDoc = (sr.rows[0] && sr.rows[0].data) || {};
    const ms = Object.assign({}, sDoc.matches || {});
    const isSigningUp = !ms[id];

    if (isSigningUp) {
      ms[id] = Date.now();
    } else {
      delete ms[id];
    }
    sDoc.matches = ms;
    await client.query(
      `INSERT INTO docs (collection, id, data) VALUES ('signups', $1, $2)
       ON CONFLICT (collection, id) DO UPDATE SET data = EXCLUDED.data`,
      [targetPid, JSON.stringify(sDoc)]
    );

    // Si se retira y los equipos ya estaban asignados, purgar de alineación y promocionar al primero en espera
    const hasTeams = (m.teamA && m.teamA.length > 0) || (m.teamB && m.teamB.length > 0);
    if (!isSigningUp && hasTeams) {
      const inA = (m.teamA || []).indexOf(targetPid);
      const inB = (m.teamB || []).indexOf(targetPid);
      if (inA > -1 || inB > -1) {
        if (inA > -1) m.teamA.splice(inA, 1);
        if (inB > -1) m.teamB.splice(inB, 1);
        if (m.roles) delete m.roles[targetPid];

        // Buscar lista de espera
        const allSignupsRes = await client.query("SELECT id, data FROM docs WHERE collection = 'signups'");
        const signedMap = [];
        allSignupsRes.rows.forEach(row => {
          const sm = (row.data && row.data.matches && row.data.matches[id]);
          if (sm) signedMap.push({ id: row.id, ts: Number(sm) });
        });
        signedMap.sort((a, b) => a.ts - b.ts);
        const currentIn = (m.teamA || []).concat(m.teamB || []);
        const waitlist = signedMap.map(x => x.id).filter(pid => !currentIn.includes(pid));
        if (waitlist.length > 0) {
          const promoted = waitlist[0];
          if ((m.teamA || []).length <= (m.teamB || []).length) {
            m.teamA = (m.teamA || []).concat(promoted);
          } else {
            m.teamB = (m.teamB || []).concat(promoted);
          }
        }
        await client.query("UPDATE docs SET data = $1 WHERE collection = 'matches' AND id = $2", [JSON.stringify(m), id]);
      }
    }

    await client.query('COMMIT');
    touchState();
    res.json({ ok: true, signed: isSigningUp });
  } catch (e) {
    await client.query('ROLLBACK').catch(() => {});
    next(e);
  } finally {
    client.release();
  }
});

/* ---------- Subida y persistencia desacoplada de Avatares ---------- */
app.post('/api/players/:id/avatar', requireUser, async (req, res, next) => {
  try {
    const { id } = req.params;
    const sanitizedId = path.basename(id).replace(/[^a-zA-Z0-9_-]/g, '');
    if (!sanitizedId) {
      return res.status(400).json({ error: 'Identificador no válido.' });
    }
    if (!req.isAdmin && id !== req.user.id) {
      return res.status(403).json({ error: 'No tienes permiso para modificar este avatar.' });
    }
    const { photo } = req.body;
    if (typeof photo !== 'string') {
      return res.status(400).json({ error: 'Imagen no proporcionada.' });
    }

    if (photo.startsWith('data:image/')) {
      const parts = photo.split(',');
      if (parts.length < 2) return res.status(400).json({ error: 'Formato no válido.' });
      const buffer = Buffer.from(parts[1], 'base64');
      if (buffer.length === 0 || buffer.length > 512 * 1024) {
        return res.status(400).json({ error: 'La imagen excede el límite máximo permitido de 500 KB.' });
      }

      // Verificación estricta de Magic Bytes: JPEG (FF D8 FF) o PNG (89 50 4E 47)
      const isJpeg = buffer.length > 3 && buffer[0] === 0xFF && buffer[1] === 0xD8 && buffer[2] === 0xFF;
      const isPng = buffer.length > 8 && buffer[0] === 0x89 && buffer[1] === 0x50 && buffer[2] === 0x4E && buffer[3] === 0x47;
      if (!isJpeg && !isPng) {
        return res.status(400).json({ error: 'El archivo debe ser una imagen JPEG o PNG válida.' });
      }

      const ext = isPng ? 'png' : 'jpg';
      const altExt = isPng ? 'jpg' : 'png';
      const filename = `${sanitizedId}.${ext}`;
      const filePath = path.join(AVATARS_DIR, filename);

      // Limpiar archivo antiguo con la otra extensión si existía
      const altPath = path.join(AVATARS_DIR, `${sanitizedId}.${altExt}`);
      if (fs.existsSync(altPath)) { try { fs.unlinkSync(altPath); } catch (e) {} }

      await fs.promises.writeFile(filePath, buffer);
      const publicUrl = `/uploads/avatars/${filename}?v=${Date.now()}`;

      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        const r = await client.query("SELECT data FROM docs WHERE collection = 'players' AND id = $1 FOR UPDATE", [id]);
        const pDoc = (r.rows[0] && r.rows[0].data) || {};
        pDoc.photo = publicUrl;
        await client.query(
          `INSERT INTO docs (collection, id, data) VALUES ('players', $1, $2)
           ON CONFLICT (collection, id) DO UPDATE SET data = EXCLUDED.data`,
          [id, JSON.stringify(pDoc)]
        );
        await client.query('COMMIT');
        touchState();
        return res.json({ ok: true, photoUrl: publicUrl });
      } catch (e) {
        await client.query('ROLLBACK').catch(() => {});
        throw e;
      } finally {
        client.release();
      }
    } else if (photo === '' || photo === 'remove') {
      ['jpg', 'jpeg', 'png'].forEach(ext => {
        const p = path.join(AVATARS_DIR, `${sanitizedId}.${ext}`);
        if (fs.existsSync(p)) try { fs.unlinkSync(p); } catch (e) {}
      });
      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        const r = await client.query("SELECT data FROM docs WHERE collection = 'players' AND id = $1 FOR UPDATE", [id]);
        if (r.rows[0]) {
          const pDoc = r.rows[0].data;
          delete pDoc.photo;
          await client.query("UPDATE docs SET data = $1 WHERE collection = 'players' AND id = $2", [JSON.stringify(pDoc), id]);
        }
        await client.query('COMMIT');
        touchState();
        return res.json({ ok: true, photoUrl: null });
      } catch (e) {
        await client.query('ROLLBACK').catch(() => {});
        throw e;
      } finally {
        client.release();
      }
    }
    res.status(400).json({ error: 'Operación no reconocida.' });
  } catch (e) { next(e); }
});

function canWrite(req, collection, id) {
  if (req.isAdmin) return true;
  return OWNED.has(collection) && id === req.user.id;
}

app.put('/api/docs/:collection/:id', requireUser, async (req, res, next) => {
  const client = await pool.connect();
  try {
    const { collection, id } = req.params;
    if (!COLLECTIONS.includes(collection)) return res.status(400).json({ error: 'Colección no válida.' });
    if (!canWrite(req, collection, id)) {
      logSecurityEvent('warn', 'IDOR_MODIFICACION_RECHAZADA', req, { collection, id });
      return res.status(403).json({ error: 'No tienes permiso para guardar esto.' });
    }
    const data = req.body.data;
    if (!data || typeof data !== 'object' || Array.isArray(data)) return res.status(400).json({ error: 'Datos no válidos.' });

    await client.query('BEGIN');

    if (collection === 'statsby') {
      const err = await checkStats(id, data, client);
      if (err) {
        await client.query('ROLLBACK');
        return res.status(400).json({ error: err });
      }
    }
    if (collection === 'votes' && !req.isAdmin) {
      const err = await checkVotes(id, data, client);
      if (err) {
        await client.query('ROLLBACK');
        return res.status(403).json({ error: err });
      }
    }
    if (collection === 'fantasy') {
      const err = await checkFantasy(id, data, client);
      if (err) {
        await client.query('ROLLBACK');
        return res.status(400).json({ error: err });
      }
    }
    if (collection === 'preds') {
      const err = await checkPreds(id, data, client);
      if (err) {
        await client.query('ROLLBACK');
        return res.status(400).json({ error: err });
      }
    }
    if (collection === 'matches' && data && data.status === 'played' && data.scoreA != null && data.scoreB != null) {
      const teamA = data.teamA || [], teamB = data.teamB || [];
      const checkTeam = async (tIds, maxScore, label) => {
        if (!tIds.length) return null;
        const r = await client.query("SELECT data FROM docs WHERE collection = 'statsby' AND id = ANY($1)", [tIds]);
        let sG = 0;
        r.rows.forEach(row => {
          const sm = (row.data && row.data.matches && row.data.matches[id]) || {};
          sG += Number(sm.g || 0);
        });
        if (sG > maxScore) {
          return `El equipo ${label} ya tiene ${sG} goles anotados por sus jugadores. No se puede fijar un resultado menor (${maxScore}).`;
        }
        return null;
      };
      const errA = await checkTeam(teamA, Number(data.scoreA), 'Claros');
      if (errA) {
        await client.query('ROLLBACK');
        return res.status(400).json({ error: errA });
      }
      const errB = await checkTeam(teamB, Number(data.scoreB), 'Oscuros');
      if (errB) {
        await client.query('ROLLBACK');
        return res.status(400).json({ error: errB });
      }
    }
    await client.query(
      `INSERT INTO docs (collection, id, data) VALUES ($1, $2, $3)
       ON CONFLICT (collection, id) DO UPDATE SET data = EXCLUDED.data`,
      [collection, id, JSON.stringify(data)]);
    await client.query('COMMIT');
    touchState();
    res.json({ ok: true });
  } catch (e) {
    await client.query('ROLLBACK').catch(() => {});
    next(e);
  } finally {
    client.release();
  }
});

app.delete('/api/docs/:collection/:id', requireUser, async (req, res, next) => {
  try {
    const { collection, id } = req.params;
    if (!COLLECTIONS.includes(collection)) return res.status(400).json({ error: 'Colección no válida.' });
    if (!canWrite(req, collection, id)) {
      logSecurityEvent('warn', 'IDOR_BORRADO_RECHAZADO', req, { collection, id });
      return res.status(403).json({ error: 'No tienes permiso para borrar esto.' });
    }

    // Prohibir el borrado arbitrario de estadísticas y votaciones para usuarios no administradores
    if (!req.isAdmin && ['votes', 'statsby'].includes(collection)) {
      logSecurityEvent('warn', 'INTENTO_BORRADO_HISTORICO', req, { collection, id });
      return res.status(403).json({ error: 'No está permitido eliminar el registro histórico de votos o estadísticas.' });
    }

    await pool.query('DELETE FROM docs WHERE collection = $1 AND id = $2', [collection, id]);
    touchState();
    res.json({ ok: true });
  } catch (e) { next(e); }
});

app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: 'Error del servidor. Inténtalo de nuevo.' });
});

let server = null;
const PORT = process.env.PORT || 3000;
initDb()
  .then(() => {
    server = app.listen(PORT, () => console.log(`Barrio de Fantasía escuchando en el puerto ${PORT}`));
  })
  .catch(err => {
    console.error('No se pudo iniciar la base de datos', err);
    process.exit(1);
  });

function gracefulShutdown(signal) {
  console.log(`Recibida señal ${signal}. Cerrando servidor HTTP...`);
  if (server) {
    server.close(async () => {
      console.log('Servidor HTTP cerrado. Cerrando pool de Postgres...');
      try {
        await pool.end();
        console.log('Pool de Postgres cerrado con éxito.');
        process.exit(0);
      } catch (err) {
        console.error('Error cerrando pool:', err);
        process.exit(1);
      }
    });
    setTimeout(() => {
      console.error('Forzando salida tras timeout de 10 segundos.');
      process.exit(1);
    }, 10000).unref();
  } else {
    process.exit(0);
  }
}

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));
