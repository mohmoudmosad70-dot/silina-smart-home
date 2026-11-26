const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const cors = require('cors');
const crypto = require('crypto');
const path = require('path');
const { createSecurityLayer } = require('./auth-security');

try {
  if (typeof process.loadEnvFile === 'function') {
    process.loadEnvFile();
  }
} catch (_) {}

const app = express();
const PORT = Number.parseInt(process.env.PORT, 10) || 3000;
const isProduction = process.env.NODE_ENV === 'production';
const rawJwtSecret = (process.env.JWT_SECRET || '').trim();

if (isProduction && rawJwtSecret.length < 32) {
  console.error('[FATAL] In production (NODE_ENV=production), JWT_SECRET must be set and at least 32 characters long.');
  process.exit(1);
}

const JWT_SECRET = rawJwtSecret || crypto.randomBytes(48).toString('hex');

if (!rawJwtSecret) {
  console.warn('[WARN] JWT_SECRET is not set in environment; generated a temporary secret for this runtime.');
}

if (process.env.TRUST_PROXY === '1') {
  app.set('trust proxy', 1);
}

const dbPath = process.env.DB_PATH || path.join(__dirname, 'silina.db');
const db = new sqlite3.Database(dbPath);

function dbRun(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function (err) {
      if (err) reject(err);
      else resolve(this);
    });
  });
}

function dbGet(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) reject(err);
      else resolve(row);
    });
  });
}

function dbAll(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
      if (err) reject(err);
      else resolve(rows);
    });
  });
}

const security = createSecurityLayer({
  dbRun,
  dbGet,
  dbAll,
  jwtSecret: JWT_SECRET
});

const publicDir = path.join(__dirname, 'public');

const allowedOrigins = (process.env.CORS_ORIGINS || '')
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean);

app.disable('x-powered-by');
app.use(security.helmetMiddleware);
app.use(
  cors(
    allowedOrigins.length
      ? {
          origin: (origin, cb) => {
            if (!origin || allowedOrigins.includes(origin)) cb(null, true);
            else cb(new Error('Origin not allowed by CORS'));
          }
        }
      : undefined
  )
);
app.use(express.json({ limit: '50kb' }));
app.use(security.jsonErrorHandler);
app.use(security.blockSensitivePaths);

app.get(['/admin-login', '/admin'], (req, res) => {
  res.sendFile(path.join(publicDir, 'index.html'));
});

app.use(
  express.static(publicDir, {
    maxAge: isProduction ? '1h' : 0
  })
);

app.use('/api/', security.apiLimiter);

const adminOnly = security.requireRole('admin');

const DEVICE_COLUMNS = [
  'living_light',
  'bedroom_light',
  'ac_power',
  'tv_power',
  'fan_power',
  'curtains_open',
  'front_door_open',
  'coffee_maker',
  'smart_speaker',
  'fireplace_on',
  'desk_lamp',
  'security_cam',
  'robot_vac',
  'air_purifier'
];
const DEVICE_SET = new Set(DEVICE_COLUMNS);
const YT_ID_REGEX = /^[a-zA-Z0-9_-]{11}$/;

const STATE_SELECT_SQL = `SELECT id, sky_mode, boy_x, boy_z, boy_yaw, is_sleeping, tv_video_id, ${DEVICE_COLUMNS.join(', ')}, hidden_devices, updated_at FROM device_state WHERE id = 1`;

function parseHiddenDevices(raw) {
  if (!raw) return [];
  try {
    const parsed = typeof raw === 'string' ? JSON.parse(raw) : raw;
    if (!Array.isArray(parsed)) return [];
    return Array.from(new Set(parsed.filter((item) => typeof item === 'string' && DEVICE_SET.has(item))));
  } catch (_) {
    return [];
  }
}

function formatStateRow(row) {
  if (!row) return null;
  return Object.assign({}, row, {
    hidden_devices: parseHiddenDevices(row.hidden_devices),
    is_sleeping: Number(row.is_sleeping || 0),
    tv_video_id: YT_ID_REGEX.test(row.tv_video_id || '') ? row.tv_video_id : 'dQw4w9WgXcQ'
  });
}

function writeLog(username, action, details, ip) {
  dbRun(
    `INSERT INTO activity_logs (username, action, details, ip_address) VALUES (?, ?, ?, ?)`,
    [username, action, details || '', ip || '']
  )
    .then(() =>
      dbRun(
        `DELETE FROM activity_logs WHERE id NOT IN (SELECT id FROM activity_logs ORDER BY id DESC LIMIT 5000)`
      )
    )
    .catch((err) => {
      console.error('Failed to write activity log:', err.message);
    });
}

async function seedInitialUsers() {
  const existingAdmin = await dbGet(`SELECT id FROM users WHERE role = 'admin' LIMIT 1`);
  if (!existingAdmin) {
    const adminUser = (process.env.ADMIN_USERNAME || 'admin').trim();
    const adminPass = process.env.ADMIN_PASSWORD || '123456';
    const hash = bcrypt.hashSync(adminPass, 12);
    await dbRun(
      `INSERT OR IGNORE INTO users (username, password_hash, role, can_move, can_control_devices, can_watch_tv, can_sleep, can_use_robot) VALUES (?, ?, 'admin', 1, 1, 1, 1, 1)`,
      [adminUser, hash]
    );
    if (!process.env.ADMIN_PASSWORD) {
      console.warn('[WARN] Using default admin credentials (admin / 123456). Set ADMIN_PASSWORD in environment.');
    }
  }

  const guestPass = process.env.GUEST_PASSWORD || 'guest123';
  const guestHash = bcrypt.hashSync(guestPass, 10);
  await dbRun(
    `INSERT OR IGNORE INTO users (username, password_hash, role, can_move, can_control_devices, can_watch_tv, can_sleep, can_use_robot) VALUES ('guest', ?, 'guest', 1, 1, 1, 1, 1)`,
    [guestHash]
  );

  const visitorPass = process.env.VISITOR_PASSWORD || 'visitor123';
  const visitorHash = bcrypt.hashSync(visitorPass, 10);
  await dbRun(
    `INSERT OR IGNORE INTO users (username, password_hash, role, can_move, can_control_devices, can_watch_tv, can_sleep, can_use_robot) VALUES ('visitor', ?, 'visitor', 0, 0, 0, 0, 0)`,
    [visitorHash]
  );
}

async function initDb() {
  await dbRun(`PRAGMA journal_mode = WAL`).catch(() => {});
  await dbRun(`PRAGMA foreign_keys = ON`).catch(() => {});

  await dbRun(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT DEFAULT 'admin',
    token_version INTEGER DEFAULT 1,
    failed_attempts INTEGER DEFAULT 0,
    locked_until INTEGER DEFAULT 0,
    can_move INTEGER DEFAULT 1,
    can_control_devices INTEGER DEFAULT 1,
    can_watch_tv INTEGER DEFAULT 1,
    can_sleep INTEGER DEFAULT 1,
    can_use_robot INTEGER DEFAULT 1,
    last_seen_at TEXT,
    last_activity TEXT DEFAULT 'متصل',
    last_ip TEXT,
    last_ua TEXT
  )`);

  const userExtraCols = [
    `ALTER TABLE users ADD COLUMN token_version INTEGER DEFAULT 1`,
    `ALTER TABLE users ADD COLUMN failed_attempts INTEGER DEFAULT 0`,
    `ALTER TABLE users ADD COLUMN locked_until INTEGER DEFAULT 0`,
    `ALTER TABLE users ADD COLUMN can_move INTEGER DEFAULT 1`,
    `ALTER TABLE users ADD COLUMN can_control_devices INTEGER DEFAULT 1`,
    `ALTER TABLE users ADD COLUMN can_watch_tv INTEGER DEFAULT 1`,
    `ALTER TABLE users ADD COLUMN can_sleep INTEGER DEFAULT 1`,
    `ALTER TABLE users ADD COLUMN can_use_robot INTEGER DEFAULT 1`,
    `ALTER TABLE users ADD COLUMN last_seen_at TEXT`,
    `ALTER TABLE users ADD COLUMN last_activity TEXT DEFAULT 'متصل'`,
    `ALTER TABLE users ADD COLUMN last_ip TEXT`,
    `ALTER TABLE users ADD COLUMN last_ua TEXT`
  ];
  for (const sql of userExtraCols) {
    await dbRun(sql).catch(() => {});
  }

  await dbRun(`CREATE TABLE IF NOT EXISTS device_state (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    sky_mode TEXT DEFAULT 'sunset',
    boy_x REAL DEFAULT 0.6,
    boy_z REAL DEFAULT 0.4,
    boy_yaw REAL DEFAULT 0,
    is_sleeping INTEGER DEFAULT 0,
    tv_video_id TEXT DEFAULT 'dQw4w9WgXcQ',
    living_light INTEGER DEFAULT 1,
    bedroom_light INTEGER DEFAULT 0,
    ac_power INTEGER DEFAULT 1,
    tv_power INTEGER DEFAULT 0,
    fan_power INTEGER DEFAULT 0,
    curtains_open INTEGER DEFAULT 1,
    front_door_open INTEGER DEFAULT 0,
    coffee_maker INTEGER DEFAULT 0,
    smart_speaker INTEGER DEFAULT 1,
    fireplace_on INTEGER DEFAULT 0,
    desk_lamp INTEGER DEFAULT 1,
    security_cam INTEGER DEFAULT 1,
    robot_vac INTEGER DEFAULT 0,
    air_purifier INTEGER DEFAULT 1,
    hidden_devices TEXT DEFAULT '[]',
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  const extraCols = [
    `ALTER TABLE device_state ADD COLUMN sky_mode TEXT DEFAULT 'sunset'`,
    `ALTER TABLE device_state ADD COLUMN boy_x REAL DEFAULT 0.6`,
    `ALTER TABLE device_state ADD COLUMN boy_z REAL DEFAULT 0.4`,
    `ALTER TABLE device_state ADD COLUMN boy_yaw REAL DEFAULT 0`,
    `ALTER TABLE device_state ADD COLUMN is_sleeping INTEGER DEFAULT 0`,
    `ALTER TABLE device_state ADD COLUMN tv_video_id TEXT DEFAULT 'dQw4w9WgXcQ'`,
    `ALTER TABLE device_state ADD COLUMN living_light INTEGER DEFAULT 1`,
    `ALTER TABLE device_state ADD COLUMN bedroom_light INTEGER DEFAULT 0`,
    `ALTER TABLE device_state ADD COLUMN ac_power INTEGER DEFAULT 1`,
    `ALTER TABLE device_state ADD COLUMN tv_power INTEGER DEFAULT 0`,
    `ALTER TABLE device_state ADD COLUMN fan_power INTEGER DEFAULT 0`,
    `ALTER TABLE device_state ADD COLUMN curtains_open INTEGER DEFAULT 1`,
    `ALTER TABLE device_state ADD COLUMN front_door_open INTEGER DEFAULT 0`,
    `ALTER TABLE device_state ADD COLUMN coffee_maker INTEGER DEFAULT 0`,
    `ALTER TABLE device_state ADD COLUMN smart_speaker INTEGER DEFAULT 1`,
    `ALTER TABLE device_state ADD COLUMN fireplace_on INTEGER DEFAULT 0`,
    `ALTER TABLE device_state ADD COLUMN desk_lamp INTEGER DEFAULT 1`,
    `ALTER TABLE device_state ADD COLUMN security_cam INTEGER DEFAULT 1`,
    `ALTER TABLE device_state ADD COLUMN robot_vac INTEGER DEFAULT 0`,
    `ALTER TABLE device_state ADD COLUMN air_purifier INTEGER DEFAULT 1`,
    `ALTER TABLE device_state ADD COLUMN hidden_devices TEXT DEFAULT '[]'`
  ];
  for (const sql of extraCols) {
    await dbRun(sql).catch(() => {});
  }

  await dbRun(`CREATE TABLE IF NOT EXISTS activity_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    action TEXT NOT NULL,
    details TEXT,
    ip_address TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  await dbRun(`CREATE TABLE IF NOT EXISTS admin_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_username TEXT NOT NULL,
    target_username TEXT,
    title TEXT NOT NULL,
    body TEXT NOT NULL,
    level TEXT DEFAULT 'info',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  await dbRun(`CREATE INDEX IF NOT EXISTS idx_users_role ON users(role)`).catch(() => {});
  await dbRun(`CREATE INDEX IF NOT EXISTS idx_logs_id_desc ON activity_logs(id DESC)`).catch(() => {});
  await dbRun(`CREATE INDEX IF NOT EXISTS idx_logs_created_at ON activity_logs(created_at)`).catch(() => {});
  await dbRun(`CREATE INDEX IF NOT EXISTS idx_logs_action ON activity_logs(action)`).catch(() => {});
  await dbRun(`CREATE INDEX IF NOT EXISTS idx_logs_username ON activity_logs(username)`).catch(() => {});
  await dbRun(`CREATE INDEX IF NOT EXISTS idx_messages_id_desc ON admin_messages(id DESC)`).catch(() => {});
  await dbRun(`CREATE INDEX IF NOT EXISTS idx_messages_target ON admin_messages(target_username)`).catch(() => {});

  await seedInitialUsers();
  await dbRun(`INSERT OR IGNORE INTO device_state (id) VALUES (1)`);
}

function getEffectiveCapabilities(userRow) {
  if (!userRow) {
    return {
      can_move: false,
      can_control_devices: false,
      can_watch_tv: false,
      can_sleep: false,
      can_use_robot: false
    };
  }
  if (userRow.role === 'admin') {
    return {
      can_move: true,
      can_control_devices: true,
      can_watch_tv: true,
      can_sleep: true,
      can_use_robot: true
    };
  }
  return {
    can_move: Boolean(userRow.can_move),
    can_control_devices: Boolean(userRow.can_control_devices),
    can_watch_tv: Boolean(userRow.can_watch_tv),
    can_sleep: Boolean(userRow.can_sleep),
    can_use_robot: Boolean(userRow.can_use_robot)
  };
}

app.get('/api/health', async (req, res) => {
  try {
    await dbGet(`SELECT 1`);
    res.json({
      status: 'ok',
      db: 'connected',
      uptimeSec: Math.floor(process.uptime()),
      timestamp: new Date().toISOString()
    });
  } catch (_) {
    res.status(503).json({
      status: 'degraded',
      db: 'error',
      timestamp: new Date().toISOString()
    });
  }
});

app.get('/api/auth/captcha', security.authLimiter, (req, res) =>
  security.issueCaptcha(req, res)
);

app.get('/api/auth/me', security.authRequired, async (req, res) => {
  try {
    const row = await dbGet(
      `SELECT id, username, role, can_move, can_control_devices, can_watch_tv, can_sleep, can_use_robot FROM users WHERE id = ?`,
      [req.user.id]
    );
    const caps = getEffectiveCapabilities(row);
    res.json({
      id: req.user.id,
      username: req.user.username,
      role: req.user.role,
      capabilities: caps
    });
  } catch (_) {
    res.json({
      id: req.user.id,
      username: req.user.username,
      role: req.user.role,
      capabilities: getEffectiveCapabilities(null)
    });
  }
});

app.post('/api/presence/heartbeat', security.authRequired, async (req, res) => {
  const actRaw = req.body && typeof req.body.activity === 'string' ? req.body.activity.trim() : 'متصل';
  const activity = actRaw.slice(0, 60) || 'متصل';
  const ua = String(req.headers['user-agent'] || '').slice(0, 120);
  const nowIso = new Date().toISOString();

  try {
    await dbRun(
      `UPDATE users SET last_seen_at = ?, last_activity = ?, last_ip = ?, last_ua = ? WHERE id = ?`,
      [nowIso, activity, req.ip || '', ua, req.user.id]
    );
    res.json({ ok: true, lastSeenAt: nowIso });
  } catch (_) {
    res.status(500).json({ error: 'تعذر تحديث نبض الحضور' });
  }
});

app.post('/api/auth/login', security.authLimiter, (req, res) =>
  security.handleStandardLogin(req, res, writeLog)
);

app.post('/api/auth/admin-login', security.authLimiter, (req, res) =>
  security.handleAdminLogin(req, res, writeLog)
);

app.post('/api/auth/change-password', security.authRequired, security.changePassLimiter, (req, res) =>
  security.handleChangePassword(req, res, writeLog)
);

app.post('/api/auth/revoke-sessions', security.authRequired, (req, res) =>
  security.handleRevokeSessions(req, res, writeLog)
);

app.get('/api/admin/users', security.authRequired, adminOnly, async (req, res) => {
  try {
    const rows = await dbAll(
      `SELECT id, username, role, failed_attempts, locked_until, token_version,
              can_move, can_control_devices, can_watch_tv, can_sleep, can_use_robot,
              last_seen_at, last_activity, last_ip, last_ua
       FROM users ORDER BY id ASC`
    );
    const now = Date.now();
    const onlineThresholdMs = 75 * 1000;

    res.json(
      rows.map((r) => {
        const lastSeenMs = r.last_seen_at ? Date.parse(r.last_seen_at) : 0;
        const isOnline = Boolean(lastSeenMs && now - lastSeenMs <= onlineThresholdMs);
        return {
          id: r.id,
          username: r.username,
          role: r.role,
          failedAttempts: Number(r.failed_attempts || 0),
          isLocked: Boolean(r.locked_until && Number(r.locked_until) > now),
          lockedUntil: Number(r.locked_until || 0),
          isOnline,
          lastSeenAt: r.last_seen_at || null,
          lastActivity: r.last_activity || 'غير نشط',
          lastIp: r.last_ip || '',
          lastUa: r.last_ua || '',
          capabilities: getEffectiveCapabilities(r)
        };
      })
    );
  } catch (_) {
    res.status(500).json({ error: 'تعذر جلب قائمة المستخدمين' });
  }
});

app.patch('/api/admin/users/:id/capabilities', security.authRequired, adminOnly, async (req, res) => {
  const userId = Number.parseInt(req.params.id, 10);
  if (!Number.isInteger(userId) || userId <= 0) {
    return res.status(400).json({ error: 'معرف المستخدم غير صالح' });
  }

  const body = req.body;
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return res.status(400).json({ error: 'صيغة الخصائص غير صحيحة' });
  }

  const capKeys = ['can_move', 'can_control_devices', 'can_watch_tv', 'can_sleep', 'can_use_robot'];
  const sets = [];
  const params = [];

  for (const k of capKeys) {
    if (body[k] !== undefined) {
      sets.push(`${k} = ?`);
      params.push(body[k] ? 1 : 0);
    }
  }

  if (!sets.length) {
    return res.status(400).json({ error: 'لا توجد خصائص لتحديثها' });
  }

  try {
    const target = await dbGet(`SELECT id, username, role FROM users WHERE id = ?`, [userId]);
    if (!target) {
      return res.status(404).json({ error: 'المستخدم غير موجود' });
    }
    params.push(userId);
    await dbRun(`UPDATE users SET ${sets.join(', ')} WHERE id = ?`, params);
    writeLog(req.user.username, 'CAPABILITIES_UPDATED', `تحديث خصائص ${target.username}: ${JSON.stringify(body)}`, req.ip);
    res.json({ ok: true });
  } catch (_) {
    res.status(500).json({ error: 'تعذر تحديث خصائص المستخدم' });
  }
});

app.post('/api/admin/users/:id/force-logout', security.authRequired, adminOnly, async (req, res) => {
  const userId = Number.parseInt(req.params.id, 10);
  if (!Number.isInteger(userId) || userId <= 0) {
    return res.status(400).json({ error: 'معرف المستخدم غير صالح' });
  }
  try {
    const target = await dbGet(`SELECT id, username FROM users WHERE id = ?`, [userId]);
    if (!target) return res.status(404).json({ error: 'المستخدم غير موجود' });
    await dbRun(`UPDATE users SET token_version = COALESCE(token_version, 1) + 1, last_activity = 'تم إنهاء الجلسة' WHERE id = ?`, [userId]);
    writeLog(req.user.username, 'FORCE_LOGOUT', `إسقاط جلسات ${target.username}`, req.ip);
    res.json({ ok: true, message: `تم إنهاء جلسات ${target.username}` });
  } catch (_) {
    res.status(500).json({ error: 'تعذر إنهاء الجلسات' });
  }
});

app.post('/api/admin/users', security.authRequired, adminOnly, (req, res) =>
  security.handleCreateUser(req, res, writeLog)
);

app.post('/api/admin/users/:id/unlock', security.authRequired, adminOnly, (req, res) =>
  security.handleUnlockUser(req, res, writeLog)
);

app.patch('/api/admin/users/:id/role', security.authRequired, adminOnly, (req, res) =>
  security.handleUpdateUserRole(req, res, writeLog)
);

app.get('/api/messages', security.authRequired, async (req, res) => {
  try {
    const rows =
      req.user.role === 'admin'
        ? await dbAll(
            `SELECT id, sender_username, target_username, title, body, level, created_at
             FROM admin_messages ORDER BY id DESC LIMIT 50`
          )
        : await dbAll(
            `SELECT id, sender_username, target_username, title, body, level, created_at
             FROM admin_messages
             WHERE target_username IS NULL OR target_username = ?
             ORDER BY id DESC LIMIT 50`,
            [req.user.username]
          );
    res.json(rows);
  } catch (_) {
    res.status(500).json({ error: 'تعذر جلب الرسائل' });
  }
});

app.post('/api/admin/messages', security.authRequired, adminOnly, async (req, res) => {
  const bodyObj = req.body;
  if (!bodyObj || typeof bodyObj !== 'object' || Array.isArray(bodyObj)) {
    return res.status(400).json({ error: 'صيغة الرسالة غير صحيحة' });
  }

  const title = typeof bodyObj.title === 'string' ? bodyObj.title.trim() : '';
  const messageBody = typeof bodyObj.body === 'string' ? bodyObj.body.trim() : '';
  const rawTarget = typeof bodyObj.targetUsername === 'string' ? bodyObj.targetUsername.trim() : '';
  const level = ['info', 'warn', 'alert'].includes(bodyObj.level) ? bodyObj.level : 'info';

  if (!title || title.length > 100) {
    return res.status(400).json({ error: 'عنوان الرسالة مطلوب وبحد أقصى 100 حرف' });
  }
  if (!messageBody || messageBody.length > 600) {
    return res.status(400).json({ error: 'نص الرسالة مطلوب وبحد أقصى 600 حرف' });
  }

  let targetUsername = null;
  if (rawTarget && rawTarget.toLowerCase() !== 'all') {
    const exists = await dbGet(`SELECT username FROM users WHERE username = ?`, [rawTarget]);
    if (!exists) {
      return res.status(404).json({ error: 'المستخدم المستهدف غير موجود' });
    }
    targetUsername = exists.username;
  }

  try {
    const inserted = await dbRun(
      `INSERT INTO admin_messages (sender_username, target_username, title, body, level)
       VALUES (?, ?, ?, ?, ?)`,
      [req.user.username, targetUsername, title, messageBody, level]
    );

    await dbRun(
      `DELETE FROM admin_messages WHERE id NOT IN (SELECT id FROM admin_messages ORDER BY id DESC LIMIT 200)`
    );

    writeLog(
      req.user.username,
      'ADMIN_MESSAGE_SENT',
      `إلى: ${targetUsername || 'الجميع'} | ${title}`,
      req.ip
    );

    const created = await dbGet(
      `SELECT id, sender_username, target_username, title, body, level, created_at
       FROM admin_messages WHERE id = ?`,
      [inserted.lastID]
    );

    res.status(201).json(created);
  } catch (_) {
    res.status(500).json({ error: 'تعذر إرسال الرسالة' });
  }
});

app.delete('/api/admin/messages/:id', security.authRequired, adminOnly, async (req, res) => {
  const msgId = Number.parseInt(req.params.id, 10);
  if (!Number.isInteger(msgId) || msgId <= 0) {
    return res.status(400).json({ error: 'معرف الرسالة غير صالح' });
  }

  try {
    const existing = await dbGet(`SELECT id, title FROM admin_messages WHERE id = ?`, [msgId]);
    if (!existing) {
      return res.status(404).json({ error: 'الرسالة غير موجودة' });
    }
    await dbRun(`DELETE FROM admin_messages WHERE id = ?`, [msgId]);
    writeLog(req.user.username, 'ADMIN_MESSAGE_DELETED', `حذف الرسالة: ${existing.title}`, req.ip);
    res.json({ ok: true });
  } catch (_) {
    res.status(500).json({ error: 'تعذر حذف الرسالة' });
  }
});

app.get('/api/state', security.authRequired, async (req, res) => {
  try {
    const row = await dbGet(STATE_SELECT_SQL);
    res.json(formatStateRow(row));
  } catch (_) {
    res.status(500).json({ error: 'تعذر قراءة الحالة' });
  }
});

app.post('/api/state', security.authRequired, async (req, res) => {
  if (req.user.role === 'visitor') {
    return res.status(403).json({ error: 'وضع الزائر للعرض فقط — سجّل دخولك بحساب مستخدم للتحكم' });
  }

  const body = req.body;
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return res.status(400).json({ error: 'صيغة بيانات التحديث غير صحيحة' });
  }

  const userRow = await dbGet(
    `SELECT role, can_move, can_control_devices, can_watch_tv, can_sleep, can_use_robot FROM users WHERE id = ?`,
    [req.user.id]
  );
  const caps = getEffectiveCapabilities(userRow);

  const sets = [];
  const params = [];

  if (body.sky_mode !== undefined) {
    if (!caps.can_control_devices) {
      return res.status(403).json({ error: 'ليس لديك صلاحية تغيير الإضاءة والجو' });
    }
    if (!['day', 'sunset', 'night'].includes(body.sky_mode)) {
      return res.status(400).json({ error: 'وضع الإضاءة غير صالح' });
    }
    sets.push(`sky_mode = ?`);
    params.push(body.sky_mode);
  }

  const coordMap = {
    boy_x: { min: -7.2, max: 7.2 },
    boy_z: { min: -6.2, max: 6.2 },
    boy_yaw: { min: -Math.PI * 2, max: Math.PI * 2 }
  };

  for (const [key, bounds] of Object.entries(coordMap)) {
    if (body[key] !== undefined) {
      if (!caps.can_move) {
        return res.status(403).json({ error: 'الأدمن قيّد خاصية تحريك الشخصية لحسابك' });
      }
      const val = Number(body[key]);
      if (!Number.isFinite(val) || val < bounds.min || val > bounds.max) {
        return res.status(400).json({ error: `قيمة ${key} غير صالحة` });
      }
      sets.push(`${key} = ?`);
      params.push(Number(val.toFixed(3)));
    }
  }

  if (body.is_sleeping !== undefined) {
    if (!caps.can_sleep) {
      return res.status(403).json({ error: 'الأدمن قيّد خاصية النوم والاستيقاظ لحسابك' });
    }
    sets.push(`is_sleeping = ?`);
    params.push(body.is_sleeping ? 1 : 0);
  }

  if (body.tv_video_id !== undefined) {
    if (!caps.can_watch_tv) {
      return res.status(403).json({ error: 'الأدمن قيّد خاصية تغيير فيديو التلفزيون لحسابك' });
    }
    const vid = typeof body.tv_video_id === 'string' ? body.tv_video_id.trim() : '';
    if (!YT_ID_REGEX.test(vid)) {
      return res.status(400).json({ error: 'معرّف فيديو يوتيوب غير صالح' });
    }
    sets.push(`tv_video_id = ?`);
    params.push(vid);
  }

  for (const col of DEVICE_COLUMNS) {
    if (body[col] !== undefined) {
      if (col === 'tv_power') {
        if (!caps.can_watch_tv && !caps.can_control_devices) {
          return res.status(403).json({ error: 'ليس لديك صلاحية تشغيل التلفزيون' });
        }
      } else if (!caps.can_control_devices) {
        return res.status(403).json({ error: 'الأدمن قيّد خاصية التحكم بالأجهزة لحسابك' });
      }
      if (typeof body[col] !== 'boolean' && body[col] !== 0 && body[col] !== 1) {
        return res.status(400).json({ error: `قيمة الجهاز ${col} غير صالحة` });
      }
      sets.push(`${col} = ?`);
      params.push(body[col] ? 1 : 0);
    }
  }

  if (body.hidden_devices !== undefined) {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'إزالة أو إظهار الأجهزة متاح للمشرف فقط' });
    }
    if (!Array.isArray(body.hidden_devices)) {
      return res.status(400).json({ error: 'قائمة الأجهزة المخفية يجب أن تكون مصفوفة' });
    }
    const sanitizedHidden = Array.from(
      new Set(
        body.hidden_devices.filter((item) => typeof item === 'string' && DEVICE_SET.has(item))
      )
    );
    sets.push(`hidden_devices = ?`);
    params.push(JSON.stringify(sanitizedHidden));
  }

  if (!sets.length) {
    return res.status(400).json({ error: 'لا يوجد تحديث للتنفيذ' });
  }

  try {
    sets.push(`updated_at = CURRENT_TIMESTAMP`);
    await dbRun(`UPDATE device_state SET ${sets.join(', ')} WHERE id = 1`, params);
    const isOnlyMove = Object.keys(body).every((k) => ['boy_x', 'boy_z', 'boy_yaw'].includes(k));
    if (!isOnlyMove) {
      writeLog(req.user.username, 'STATE_CHANGE', JSON.stringify(body), req.ip);
    }

    const updated = await dbGet(STATE_SELECT_SQL);
    res.json(formatStateRow(updated));
  } catch (_) {
    res.status(500).json({ error: 'فشل حفظ الحالة في قاعدة البيانات' });
  }
});

app.get('/api/logs', security.authRequired, adminOnly, async (req, res) => {
  const rawLimit = Number.parseInt(req.query.limit, 10);
  const limit = Number.isNaN(rawLimit) ? 50 : Math.min(Math.max(rawLimit, 1), 200);

  try {
    const rows = await dbAll(
      `SELECT id, username, action, details, ip_address, created_at FROM activity_logs ORDER BY id DESC LIMIT ?`,
      [limit]
    );
    res.json(rows);
  } catch (_) {
    res.status(500).json({ error: 'تعذر جلب السجل' });
  }
});

app.delete('/api/logs', security.authRequired, adminOnly, async (req, res) => {
  try {
    await dbRun(`DELETE FROM activity_logs`);
    writeLog(req.user.username, 'LOGS_CLEARED', 'تم مسح سجل النشاط', req.ip);
    res.json({ ok: true });
  } catch (_) {
    res.status(500).json({ error: 'تعذر مسح السجل' });
  }
});

app.use('/api', (req, res) => {
  res.status(404).json({ error: 'المسار المطلوب غير موجود' });
});

app.use((err, req, res, next) => {
  console.error('Unhandled server error:', err && err.message ? err.message : err);
  res.status(500).json({ error: 'حدث خطأ داخلي في الخادم' });
});

let serverInstance = null;
let isShuttingDown = false;

initDb()
  .then(() => {
    serverInstance = app.listen(PORT, () => {
      console.log(`Silina server running on http://localhost:${PORT}`);
    });
  })
  .catch((err) => {
    console.error('Database initialization failed:', err.message);
    process.exit(1);
  });

function shutdown(signal) {
  if (isShuttingDown) return;
  isShuttingDown = true;
  console.log(`Received ${signal}, shutting down gracefully...`);

  const forceExitTimer = setTimeout(() => {
    console.error('Forced exit after shutdown timeout.');
    process.exit(1);
  }, 8000);
  forceExitTimer.unref();

  const closeDatabase = () => {
    db.close((err) => {
      if (err) {
        console.error('Error closing SQLite database:', err.message);
        process.exit(1);
      }
      process.exit(0);
    });
  };

  if (serverInstance) {
    serverInstance.close((err) => {
      if (err) console.error('Error closing HTTP server:', err.message);
      closeDatabase();
    });
  } else {
    closeDatabase();
  }
}

process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));