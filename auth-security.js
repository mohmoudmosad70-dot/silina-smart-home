const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');

const ALLOWED_ROLES = new Set(['admin', 'guest', 'visitor']);
const ASSIGNABLE_ROLES = new Set(['guest', 'visitor']);
const USERNAME_REGEX = /^[a-zA-Z0-9_.-]{3,32}$/;

// Dummy hash لموازنة زمن الاستجابة وتقليل احتمالية Timing Attacks
const DUMMY_BCRYPT_HASH = bcrypt.hashSync('SilinaDummyPassword!2026', 10);

function createSecurityLayer({ dbRun, dbGet, dbAll, jwtSecret }) {
  const secret = jwtSecret || crypto.randomBytes(48).toString('hex');
  const usedCaptchas = new Map();

  function cleanupUsedCaptchas(now) {
    for (const [jti, exp] of usedCaptchas.entries()) {
      if (exp <= now) usedCaptchas.delete(jti);
    }
  }

  const helmetMiddleware = helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "'unsafe-inline'", 'https://cdn.jsdelivr.net'],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", 'data:', 'blob:', 'https://i.ytimg.com'],
        connectSrc: ["'self'"],
        frameSrc: ["'self'", 'https://www.youtube.com', 'https://www.youtube-nocookie.com'],
        objectSrc: ["'none'"],
        baseUri: ["'self'"],
        formAction: ["'self'"],
        frameAncestors: ["'none'"]
      }
    },
    crossOriginEmbedderPolicy: false,
    crossOriginResourcePolicy: { policy: 'same-origin' },
    referrerPolicy: { policy: 'no-referrer' }
  });

  const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 35,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'محاولات دخول كثيرة، جرّب بعد شوية' }
  });

  const changePassLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 15,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'محاولات تغيير كلمة المرور كثيرة، انتظر قليلاً' }
  });

  const apiLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 120,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'تم تجاوز الحد المسموح من الطلبات، انتظر قليلاً' }
  });

  function jsonErrorHandler(err, req, res, next) {
    if (err instanceof SyntaxError && err.status === 400 && 'body' in err) {
      return res.status(400).json({ error: 'صيغة JSON في الطلب غير صحيحة' });
    }
    return next(err);
  }

  function blockSensitivePaths(req, res, next) {
    let cleanPath = '';
    try {
      cleanPath = decodeURIComponent(req.path || '').toLowerCase();
    } catch (_) {
      return res.status(400).json({ error: 'مسار غير صالح' });
    }

    if (
      cleanPath.includes('/.') ||
      cleanPath.endsWith('.env') ||
      cleanPath.endsWith('.db') ||
      cleanPath.endsWith('.db-wal') ||
      cleanPath.endsWith('.db-shm') ||
      cleanPath.endsWith('.sqlite') ||
      cleanPath.endsWith('.sqlite3') ||
      cleanPath.endsWith('.log') ||
      cleanPath.endsWith('.js') ||
      cleanPath.endsWith('.json')
    ) {
      return res.status(403).json({ error: 'الوصول إلى هذا المسار غير مسموح' });
    }
    return next();
  }

  function authRequired(req, res, next) {
    const header = typeof req.headers.authorization === 'string' ? req.headers.authorization : '';
    const token = header.startsWith('Bearer ') ? header.slice(7).trim() : null;
    if (!token || token.length > 2048) {
      return res.status(401).json({ error: 'مطلوب تسجيل الدخول أولاً' });
    }

    jwt.verify(token, secret, { algorithms: ['HS256'], issuer: 'silina-smart-home' }, async (err, payload) => {
      if (err || !payload || !payload.id) {
        return res.status(403).json({ error: 'الجلسة غير صالحة أو منتهية' });
      }

      try {
        const user = await dbGet(
          `SELECT id, username, role, token_version, locked_until FROM users WHERE id = ?`,
          [payload.id]
        );
        if (!user || !ALLOWED_ROLES.has(user.role)) {
          return res.status(403).json({ error: 'الحساب غير موجود أو غير صالح' });
        }

        if (user.locked_until && Number(user.locked_until) > Date.now()) {
          return res.status(423).json({ error: 'الحساب مقفل مؤقتاً للحماية' });
        }

        const currentVer = Number(user.token_version || 1);
        const tokenVer = Number(payload.tv || 1);
        if (tokenVer !== currentVer) {
          return res.status(401).json({ error: 'تم إبطال هذه الجلسة، يرجى تسجيل الدخول مجدداً' });
        }

        req.user = { id: user.id, username: user.username, role: user.role };
        return next();
      } catch (_) {
        return res.status(500).json({ error: 'خطأ في التحقق من الجلسة' });
      }
    });
  }

  function requireRole(...allowedRoles) {
    return (req, res, next) => {
      if (!req.user || !allowedRoles.includes(req.user.role)) {
        return res.status(403).json({ error: 'ليس لديك صلاحية تنفيذ هذا الإجراء' });
      }
      return next();
    };
  }

  function issueCaptcha(req, res) {
    const now = Date.now();
    cleanupUsedCaptchas(now);
    if (usedCaptchas.size > 5000) {
      usedCaptchas.clear();
    }

    const a = crypto.randomInt(2, 12);
    const b = crypto.randomInt(1, 10);
    const op = crypto.randomInt(0, 2) === 0 ? '+' : '-';
    const first = op === '-' && a < b ? b : a;
    const second = op === '-' && a < b ? a : b;
    const answer = op === '+' ? first + second : first - second;
    const jti = crypto.randomBytes(16).toString('hex');

    const captchaId = jwt.sign(
      { purpose: 'captcha', ans: String(answer), jti },
      secret,
      { algorithm: 'HS256', expiresIn: '5m', issuer: 'silina-smart-home' }
    );

    return res.json({
      captchaId,
      question: `${first} ${op} ${second} = ?`,
      expiresInSec: 300
    });
  }

  function consumeAndVerifyCaptcha(captchaId, captchaAnswer) {
    if (typeof captchaId !== 'string' || !captchaId.trim() || captchaId.length > 1024) {
      return false;
    }
    const rawAns =
      typeof captchaAnswer === 'number' && Number.isFinite(captchaAnswer)
        ? String(Math.trunc(captchaAnswer))
        : (typeof captchaAnswer === 'string' ? captchaAnswer.trim() : '');

    if (!rawAns || rawAns.length > 12) return false;

    const now = Date.now();
    cleanupUsedCaptchas(now);

    try {
      const payload = jwt.verify(captchaId.trim(), secret, {
        algorithms: ['HS256'],
        issuer: 'silina-smart-home'
      });
      if (
        !payload ||
        payload.purpose !== 'captcha' ||
        typeof payload.ans !== 'string' ||
        typeof payload.jti !== 'string'
      ) {
        return false;
      }

      if (usedCaptchas.has(payload.jti)) {
        return false;
      }

      const expMs = payload.exp ? Number(payload.exp) * 1000 : now + 5 * 60 * 1000;
      usedCaptchas.set(payload.jti, expMs);

      const left = Buffer.from(rawAns, 'utf8');
      const right = Buffer.from(payload.ans, 'utf8');
      if (left.length !== right.length) return false;
      return crypto.timingSafeEqual(left, right);
    } catch (_) {
      return false;
    }
  }

  async function recordFailedAttempt(userId, username, now, writeLog, isAdminPortal) {
    const lockUntilTs = now + 10 * 60 * 1000;

    await dbRun(
      `UPDATE users
       SET failed_attempts = COALESCE(failed_attempts, 0) + 1
       WHERE id = ?`,
      [userId]
    );

    const lockResult = await dbRun(
      `UPDATE users
       SET failed_attempts = 0, locked_until = ?
       WHERE id = ? AND COALESCE(failed_attempts, 0) >= 5`,
      [lockUntilTs, userId]
    );

    const lockedNow = Boolean(lockResult && Number(lockResult.changes || 0) > 0);
    const freshRow = lockedNow
      ? { failed_attempts: 0 }
      : await dbGet(`SELECT failed_attempts FROM users WHERE id = ?`, [userId]);

    const currentFails = lockedNow ? 5 : Number((freshRow && freshRow.failed_attempts) || 1);

    if (writeLog) {
      const action = isAdminPortal
        ? (lockedNow ? 'ADMIN_LOCKED' : 'ADMIN_LOGIN_FAILED')
        : (lockedNow ? 'ACCOUNT_LOCKED' : 'LOGIN_FAILED');
      const details = lockedNow
        ? 'تم قفل الحساب 10 دقائق بعد 5 محاولات خاطئة'
        : `محاولة دخول فاشلة (${currentFails}/5)`;
      writeLog(username, action, details);
    }

    return lockedNow
      ? 'تم قفل الحساب لمدة 10 دقائق بسبب تكرار المحاولات الخاطئة'
      : `كلمة المرور غير صحيحة (المحاولة ${currentFails} من 5)`;
  }

  function formatCapabilities(user) {
    if (user.role === 'admin') {
      return {
        can_move: true,
        can_control_devices: true,
        can_watch_tv: true,
        can_sleep: true,
        can_use_robot: true
      };
    }
    return {
      can_move: Boolean(user.can_move),
      can_control_devices: Boolean(user.can_control_devices),
      can_watch_tv: Boolean(user.can_watch_tv),
      can_sleep: Boolean(user.can_sleep),
      can_use_robot: Boolean(user.can_use_robot)
    };
  }

  async function processLogin(req, res, writeLog, { isAdminPortal }) {
    const body = req.body;
    if (!body || typeof body !== 'object' || Array.isArray(body)) {
      return res.status(400).json({ error: 'صيغة طلب تسجيل الدخول غير صحيحة' });
    }

    const username = typeof body.username === 'string' ? body.username.trim() : '';
    const password = typeof body.password === 'string' ? body.password : '';

    if (!username || !password || username.length > 50 || password.length > 128) {
      return res.status(400).json({ error: isAdminPortal ? 'بيانات دخول الأدمن غير صحيحة' : 'بيانات الدخول غير صحيحة' });
    }

    if (!consumeAndVerifyCaptcha(body.captchaId, body.captchaAnswer)) {
      if (writeLog) {
        writeLog(
          username || 'unknown',
          isAdminPortal ? 'ADMIN_CAPTCHA_FAILED' : 'CAPTCHA_FAILED',
          'رمز التحقق غير صحيح أو مستخدم سابقاً',
          req.ip
        );
      }
      return res.status(400).json({ error: 'رمز التحقق غير صحيح أو منتهي الصلاحية' });
    }

    try {
      const user = await dbGet(`SELECT * FROM users WHERE username = ?`, [username]);
      const now = Date.now();

      if (user && user.locked_until && Number(user.locked_until) > now) {
        const minsLeft = Math.ceil((Number(user.locked_until) - now) / 60000);
        if (writeLog) {
          writeLog(
            user.username,
            isAdminPortal ? 'ADMIN_LOGIN_BLOCKED' : 'LOGIN_BLOCKED',
            'محاولة دخول أثناء القفل المؤقت',
            req.ip
          );
        }
        return res.status(423).json({
          error: isAdminPortal
            ? `حساب الأدمن مقفل مؤقتاً، حاول بعد ${minsLeft} دقيقة`
            : `الحساب مقفل مؤقتاً للحماية، حاول بعد ${minsLeft} دقيقة`
        });
      }

      const hashToCompare = user ? user.password_hash : DUMMY_BCRYPT_HASH;
      const passwordOk = await bcrypt.compare(password, hashToCompare);

      if (!user) {
        if (writeLog) writeLog(username, isAdminPortal ? 'ADMIN_LOGIN_FAILED' : 'LOGIN_FAILED', 'اسم مستخدم غير موجود', req.ip);
        return res.status(401).json({ error: isAdminPortal ? 'بيانات الأدمن غير صحيحة' : 'اسم المستخدم أو كلمة المرور غلط' });
      }

      if (isAdminPortal && user.role !== 'admin') {
        if (writeLog) writeLog(user.username, 'ADMIN_LOGIN_FAILED', 'محاولة دخول أدمن غير صالحة', req.ip);
        return res.status(401).json({ error: 'بيانات الأدمن غير صحيحة' });
      }

      if (!isAdminPortal && user.role === 'admin') {
        if (writeLog) writeLog(user.username, 'ADMIN_PUBLIC_LOGIN_BLOCKED', 'محاولة دخول أدمن من المسار العام', req.ip);
        return res.status(401).json({ error: 'اسم المستخدم أو كلمة المرور غلط' });
      }

      if (!passwordOk) {
        const errMsg = await recordFailedAttempt(
          user.id,
          user.username,
          now,
          (u, act, det) => writeLog(u, act, det, req.ip),
          isAdminPortal
        );
        return res.status(401).json({ error: errMsg });
      }

      const nowIso = new Date().toISOString();
      const ua = String(req.headers['user-agent'] || '').slice(0, 120);
      await dbRun(
        `UPDATE users SET failed_attempts = 0, locked_until = 0, last_seen_at = ?, last_activity = 'تسجيل دخول', last_ip = ?, last_ua = ? WHERE id = ?`,
        [nowIso, req.ip || '', ua, user.id]
      );

      const token = jwt.sign(
        { id: user.id, username: user.username, role: user.role, tv: Number(user.token_version || 1) },
        secret,
        { algorithm: 'HS256', expiresIn: '24h', issuer: 'silina-smart-home' }
      );

      if (writeLog) {
        writeLog(
          user.username,
          isAdminPortal ? 'ADMIN_LOGIN' : 'LOGIN',
          'تسجيل دخول ناجح مع التحقق',
          req.ip
        );
      }

      return res.json({
        token,
        username: user.username,
        role: user.role,
        capabilities: formatCapabilities(user)
      });
    } catch (_) {
      return res.status(500).json({ error: 'خطأ في قاعدة البيانات' });
    }
  }

  function handleStandardLogin(req, res, writeLog) {
    return processLogin(req, res, writeLog, { isAdminPortal: false });
  }

  function handleAdminLogin(req, res, writeLog) {
    return processLogin(req, res, writeLog, { isAdminPortal: true });
  }

  async function handleChangePassword(req, res, writeLog) {
    const body = req.body;
    if (!body || typeof body !== 'object' || Array.isArray(body)) {
      return res.status(400).json({ error: 'صيغة الطلب غير صحيحة' });
    }

    const currentPassword = typeof body.currentPassword === 'string' ? body.currentPassword : '';
    const newPassword = typeof body.newPassword === 'string' ? body.newPassword : '';

    if (!currentPassword || !newPassword || newPassword.length < 6 || newPassword.length > 72) {
      return res.status(400).json({ error: 'كلمة المرور الجديدة يجب أن تكون بين 6 و 72 حرفاً' });
    }

    if (currentPassword === newPassword) {
      return res.status(400).json({ error: 'كلمة المرور الجديدة يجب أن تختلف عن كلمة المرور الحالية' });
    }

    try {
      const user = await dbGet(`SELECT * FROM users WHERE id = ?`, [req.user.id]);
      if (!user) return res.status(404).json({ error: 'تعذر العثور على الحساب' });

      const match = await bcrypt.compare(currentPassword, user.password_hash);
      if (!match) {
        if (writeLog) writeLog(user.username, 'PASSWORD_CHANGE_FAILED', 'محاولة تغيير كلمة مرور بكلمة حالية خاطئة', req.ip);
        return res.status(401).json({ error: 'كلمة المرور الحالية غير صحيحة' });
      }

      const newHash = await bcrypt.hash(newPassword, 12);
      await dbRun(
        `UPDATE users SET password_hash = ?, token_version = COALESCE(token_version, 1) + 1 WHERE id = ?`,
        [newHash, user.id]
      );

      if (writeLog) writeLog(user.username, 'PASSWORD_CHANGE', 'تم تغيير كلمة المرور وإبطال الجلسات القديمة', req.ip);
      return res.json({ ok: true, message: 'تم تحديث كلمة المرور وإغلاق الجلسات السابقة بنجاح' });
    } catch (_) {
      return res.status(500).json({ error: 'فشل تحديث كلمة المرور' });
    }
  }

  async function handleRevokeSessions(req, res, writeLog) {
    try {
      await dbRun(
        `UPDATE users SET token_version = COALESCE(token_version, 1) + 1 WHERE id = ?`,
        [req.user.id]
      );
      if (writeLog) writeLog(req.user.username, 'SESSIONS_REVOKED', 'تم تسجيل الخروج من جميع الأجهزة', req.ip);
      return res.json({ ok: true, message: 'تم إنهاء جميع الجلسات النشطة' });
    } catch (_) {
      return res.status(500).json({ error: 'تعذر إبطال الجلسات' });
    }
  }

  async function handleListUsers(req, res) {
    if (typeof dbAll !== 'function') {
      return res.status(500).json({ error: 'دالة الاستعلام غير متاحة' });
    }
    try {
      const rows = await dbAll(
        `SELECT id, username, role, failed_attempts, locked_until, token_version,
                can_move, can_control_devices, can_watch_tv, can_sleep, can_use_robot,
                last_seen_at, last_activity, last_ip, last_ua
         FROM users ORDER BY id ASC`
      );
      const now = Date.now();
      const onlineThresholdMs = 75 * 1000;

      return res.json(
        rows.map((r) => {
          const lastSeenMs = r.last_seen_at ? Date.parse(r.last_seen_at) : 0;
          return {
            id: r.id,
            username: r.username,
            role: r.role,
            failedAttempts: Number(r.failed_attempts || 0),
            isLocked: Boolean(r.locked_until && Number(r.locked_until) > now),
            lockedUntil: Number(r.locked_until || 0),
            isOnline: Boolean(lastSeenMs && now - lastSeenMs <= onlineThresholdMs),
            lastSeenAt: r.last_seen_at || null,
            lastActivity: r.last_activity || 'غير نشط',
            lastIp: r.last_ip || '',
            lastUa: r.last_ua || '',
            capabilities: formatCapabilities(r)
          };
        })
      );
    } catch (_) {
      return res.status(500).json({ error: 'تعذر جلب قائمة المستخدمين' });
    }
  }

  async function handleCreateUser(req, res, writeLog) {
    const body = req.body;
    if (!body || typeof body !== 'object' || Array.isArray(body)) {
      return res.status(400).json({ error: 'صيغة بيانات المستخدم غير صحيحة' });
    }

    const username = typeof body.username === 'string' ? body.username.trim() : '';
    const password = typeof body.password === 'string' ? body.password : '';
    const role = typeof body.role === 'string' ? body.role.trim() : 'guest';

    if (!USERNAME_REGEX.test(username)) {
      return res.status(400).json({ error: 'اسم المستخدم يجب أن يكون 3 إلى 32 حرفاً أو رقماً أو شرطة سفلية' });
    }
    if (!password || password.length < 6 || password.length > 72) {
      return res.status(400).json({ error: 'كلمة المرور يجب أن تكون بين 6 و 72 حرفاً' });
    }
    if (!ASSIGNABLE_ROLES.has(role)) {
      return res.status(400).json({ error: 'الدور المسموح لإنشاء حساب جديد هو guest أو visitor فقط' });
    }

    try {
      const exists = await dbGet(`SELECT id FROM users WHERE username = ?`, [username]);
      if (exists) {
        return res.status(409).json({ error: 'اسم المستخدم مستخدم بالفعل' });
      }

      const hash = await bcrypt.hash(password, 12);
      const enableAll = role === 'guest' ? 1 : 0;
      const inserted = await dbRun(
        `INSERT INTO users (username, password_hash, role, can_move, can_control_devices, can_watch_tv, can_sleep, can_use_robot)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        [username, hash, role, enableAll, enableAll, enableAll, enableAll, enableAll]
      );

      if (writeLog) writeLog(req.user.username, 'USER_CREATED', `إنشاء حساب ${username} بدور ${role}`, req.ip);
      return res.status(201).json({ id: inserted.lastID, username, role });
    } catch (_) {
      return res.status(500).json({ error: 'تعذر إنشاء المستخدم' });
    }
  }

  async function handleUnlockUser(req, res, writeLog) {
    const userId = Number.parseInt(req.params.id, 10);
    if (!Number.isInteger(userId) || userId <= 0) {
      return res.status(400).json({ error: 'معرف المستخدم غير صالح' });
    }

    try {
      const target = await dbGet(`SELECT id, username FROM users WHERE id = ?`, [userId]);
      if (!target) {
        return res.status(404).json({ error: 'المستخدم غير موجود' });
      }

      await dbRun(
        `UPDATE users SET failed_attempts = 0, locked_until = 0 WHERE id = ?`,
        [userId]
      );

      if (writeLog) writeLog(req.user.username, 'USER_UNLOCKED', `فك قفل الحساب ${target.username}`, req.ip);
      return res.json({ ok: true, message: `تم فك قفل الحساب ${target.username}` });
    } catch (_) {
      return res.status(500).json({ error: 'تعذر فك قفل الحساب' });
    }
  }

  async function handleUpdateUserRole(req, res, writeLog) {
    const userId = Number.parseInt(req.params.id, 10);
    if (!Number.isInteger(userId) || userId <= 0) {
      return res.status(400).json({ error: 'معرف المستخدم غير صالح' });
    }

    const body = req.body;
    const nextRole = body && typeof body.role === 'string' ? body.role.trim() : '';
    if (!ASSIGNABLE_ROLES.has(nextRole)) {
      return res.status(400).json({ error: 'الدور غير صالح (guest أو visitor)' });
    }

    try {
      const target = await dbGet(`SELECT id, username, role FROM users WHERE id = ?`, [userId]);
      if (!target) {
        return res.status(404).json({ error: 'المستخدم غير موجود' });
      }
      if (target.role === 'admin') {
        return res.status(403).json({ error: 'لا يمكن تعديل دور حساب المشرف من هنا' });
      }

      const enableAll = nextRole === 'guest' ? 1 : 0;
      await dbRun(
        `UPDATE users
         SET role = ?, can_move = ?, can_control_devices = ?, can_watch_tv = ?, can_sleep = ?, can_use_robot = ?,
             token_version = COALESCE(token_version, 1) + 1
         WHERE id = ?`,
        [nextRole, enableAll, enableAll, enableAll, enableAll, enableAll, userId]
      );

      if (writeLog) {
        writeLog(req.user.username, 'USER_ROLE_UPDATED', `تغيير دور ${target.username} إلى ${nextRole}`, req.ip);
      }
      return res.json({ ok: true, id: userId, username: target.username, role: nextRole });
    } catch (_) {
      return res.status(500).json({ error: 'تعذر تحديث دور المستخدم' });
    }
  }

  return {
    helmetMiddleware,
    authLimiter,
    changePassLimiter,
    apiLimiter,
    jsonErrorHandler,
    blockSensitivePaths,
    authRequired,
    requireRole,
    issueCaptcha,
    handleStandardLogin,
    handleAdminLogin,
    handleChangePassword,
    handleRevokeSessions,
    handleListUsers,
    handleCreateUser,
    handleUnlockUser,
    handleUpdateUserRole
  };
}

module.exports = { createSecurityLayer };