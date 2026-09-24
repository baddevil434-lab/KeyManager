// api/index.js — all API routes
const L = require('./_lib');

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Session-Token, X-Admin-Session');

  if (req.method === 'OPTIONS') return res.status(204).end();

  const path = (req.url || '').split('?')[0].replace(/\/$/, '');
  try {
    // ─── Client (Android) auth ───────────────────────────────────────────
    if (path === '/api/client/auth/login')      return await clientLogin(req, res);
    if (path === '/api/client/auth/verify')     return await clientVerify(req, res);
    if (path === '/api/client/auth/logout')     return await clientLogout(req, res);
    if (path === '/api/client/auth/change-key') return await clientChangeKey(req, res);
    if (path === '/api/client/wake')            return await clientWake(req, res);

    // ─── Admin web auth ──────────────────────────────────────────────────
    if (path === '/api/admin/auth/login')   return await adminLogin(req, res);
    if (path === '/api/admin/auth/logout')  return await adminLogout(req, res);
    if (path === '/api/admin/auth/me')      return await adminMe(req, res);

    // ─── Admin: keys ─────────────────────────────────────────────────────
    if (path === '/api/admin/keys/create')  return await keyCreate(req, res);
    if (path === '/api/admin/keys/list')    return await keyList(req, res);
    if (path === '/api/admin/keys/update')  return await keyUpdate(req, res);

    // ─── Admin: projects ─────────────────────────────────────────────────
    if (path === '/api/admin/projects/manage')    return await projectManage(req, res);
    if (path === '/api/admin/projects/upload-sa') return await projectUploadSa(req, res);

    // ─── Admin: sessions ─────────────────────────────────────────────────
    if (path === '/api/admin/sessions/list') return await sessionList(req, res);
    if (path === '/api/admin/sessions/kill') return await sessionKill(req, res);

    // ─── Admin: wake (web panel) ─────────────────────────────────────────
    if (path === '/api/admin/wake') return await wakeDevices(req, res);

    // ─── Health check ────────────────────────────────────────────────────
    if (path === '/api/health') return L.ok(res, { ts: Date.now() });

    return L.fail(res, 'not_found', 404, { path });
  } catch (e) {
    console.error('[API ERROR]', path, e);
    return L.fail(res, 'internal_error', 500, { detail: e.message });
  }
};

// ═══════════════════════════════════════════════════════════════════════════
// CLIENT (ANDROID) ENDPOINTS
// ═══════════════════════════════════════════════════════════════════════════

async function clientLogin(req, res) {
  if (req.method !== 'POST') return L.fail(res, 'method_not_allowed', 405);

  const body = L.readBody(req);
  const rawKey      = L.sanitizeStr(body.key, 64);
  const packageName = L.sanitizeStr(body.package_name, 128);
  const androidId   = L.sanitizeStr(body.android_id, 64);

  if (!rawKey)      return L.fail(res, 'key_required', 400);
  if (!packageName) return L.fail(res, 'package_required', 400);
  if (!androidId)   return L.fail(res, 'android_id_required', 400);

  const ip = L.clientIp(req);

  const ipCheck = await L.checkRate(`ip:${ip}`, 15, 60);
  if (!ipCheck.allowed)
    return L.fail(res, 'rate_limited', 429, { retry_after: ipCheck.retryAfter });

  const keyHash = L.hashKey(rawKey);
  const key = await L.qOne(
    `SELECT k.*,
            fp.id AS fp_id, fp.rtdb_url, fp.project_id AS fb_project_id,
            fp.sa_json_base64, fp.allowed_packages
     FROM license_keys k
     JOIN firebase_projects fp ON k.project_id = fp.id
     WHERE k.key_hash = $1 AND fp.is_active = TRUE`,
    [keyHash]
  );

  if (!key) {
    await L.checkRate(`key:${keyHash}`, 15, 60);
    return L.fail(res, 'invalid_key', 401);
  }

  const allowed = (key.allowed_packages || '')
    .split(',')
    .map(s => s.trim())
    .filter(Boolean);

  if (allowed.length === 0) {
    return L.fail(res, 'package_not_configured', 403,
      { detail: 'No allowed packages configured for this project.' });
  }
  if (!allowed.includes('*') && !allowed.includes(packageName)) {
    return L.fail(res, 'package_mismatch', 403,
      { detail: `Package '${packageName}' not allowed for this project.` });
  }

  const kCheck = await L.checkRate(`key:${keyHash}`, 15, 60);
  if (!kCheck.allowed)
    return L.fail(res, 'rate_limited', 429, { retry_after: kCheck.retryAfter });

  if (key.status === 'blocked') return L.fail(res, 'key_blocked', 403);

  const now = Math.floor(Date.now() / 1000);
  if (key.status === 'expired' || Number(key.expiry_ts) < now) {
    await L.run(`UPDATE license_keys SET status='expired' WHERE id=$1`, [key.id]);
    return L.fail(res, 'key_expired', 403);
  }

  if (!key.sa_json_base64) {
    return L.fail(res, 'project_not_configured', 500,
      { detail: 'Service account not uploaded for this project.' });
  }

  // ── SINGLE-DEVICE BINDING ─────────────────────────────────────────────
  if (key.bound_device_fp && key.bound_device_fp !== androidId) {
    return L.fail(res, 'device_mismatch', 403, {
      detail: 'This key is already bound to another device. Contact admin to unbind.'
    });
  }

  if (!key.bound_device_fp) {
    await L.run(
      `UPDATE license_keys SET bound_device_fp=$1 WHERE id=$2`,
      [androidId, key.id]
    );
    key.bound_device_fp = androidId;
  }

  let customToken;
  try {
    const uid = `admin_${key.id}_${L.crypto.createHash('sha256')
      .update(androidId).digest('hex').substring(0, 8)}`;
    customToken = await L.mintCustomToken(key, uid, {
      admin: true,
      projectId: String(key.fb_project_id).toLowerCase(),
      keyId: key.id,
      type: key.type
    });
  } catch (e) {
    return L.fail(res, 'token_mint_failed', 500, { detail: e.message });
  }

  const sessionId = L.crypto.randomBytes(24).toString('hex');
  await L.run(
    `INSERT INTO client_sessions
     (session_id, key_id, project_id, android_id, package_name, ip, user_agent,
      created_at, expires_at, last_ping, is_active)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,TRUE)`,
    [sessionId, key.id, key.project_id, androidId, packageName, ip,
     String(req.headers['user-agent'] || '').substring(0, 512),
     now, now + 3600, now]
  );

  await L.run(
    `UPDATE license_keys
     SET last_login_at=$1, login_count=login_count+1,
         first_login_at=CASE WHEN first_login_at=0 THEN $1 ELSE first_login_at END
     WHERE id=$2`,
    [now, key.id]
  );

  await L.resetRate(`ip:${ip}`);
  await L.resetRate(`key:${keyHash}`);

  return L.ok(res, {
    custom_token: customToken,
    project_id: String(key.fb_project_id).toLowerCase(),
    fb_database_url: key.rtdb_url,
    type: key.type,
    session_id: sessionId,
    expires_in: 3600,
    key_id: key.id
  });
}

async function clientVerify(req, res) {
  const sessionId = String(req.headers['x-session-token'] || '').trim();
  if (!sessionId || sessionId.length !== 48)
    return L.fail(res, 'invalid_session', 400);

  const now = Math.floor(Date.now() / 1000);
  const row = await L.qOne(
    `SELECT cs.*, k.status AS key_status, k.expiry_ts
     FROM client_sessions cs
     JOIN license_keys k ON cs.key_id = k.id
     WHERE cs.session_id = $1`,
    [sessionId]
  );

  if (!row)                         return L.ok(res, { valid: false, reason: 'not_found' });
  if (!row.is_active)               return L.ok(res, { valid: false, reason: 'killed' });
  if (Number(row.expires_at) < now) return L.ok(res, { valid: false, reason: 'expired' });
  if (row.key_status === 'blocked') {
    await L.run(`UPDATE client_sessions SET is_active=FALSE WHERE session_id=$1`, [sessionId]);
    return L.ok(res, { valid: false, reason: 'key_blocked' });
  }
  if (Number(row.expiry_ts) < now) {
    await L.run(`UPDATE client_sessions SET is_active=FALSE WHERE session_id=$1`, [sessionId]);
    return L.ok(res, { valid: false, reason: 'key_expired' });
  }

  await L.run(`UPDATE client_sessions SET last_ping=$1 WHERE session_id=$2`, [now, sessionId]);
  return L.ok(res, { valid: true });
}

async function clientLogout(req, res) {
  const sessionId = String(req.headers['x-session-token'] || '').trim();
  if (sessionId && sessionId.length === 48) {
    await L.run(`UPDATE client_sessions SET is_active=FALSE WHERE session_id=$1`, [sessionId]);
  }
  return L.ok(res, {});
}

async function clientChangeKey(req, res) {
  if (req.method !== 'POST') return L.fail(res, 'method_not_allowed', 405);

  const sessionId = String(req.headers['x-session-token'] || '').trim();
  if (!sessionId || sessionId.length !== 48)
    return L.fail(res, 'invalid_session', 400);

  const b = L.readBody(req);
  const oldKey = L.sanitizeStr(b.old_key, 64);
  const newKey = L.sanitizeStr(b.new_key, 64);

  if (!oldKey || !newKey) return L.fail(res, 'missing_fields', 400);

  if (!/^\d{6}$/.test(newKey))
    return L.fail(res, 'invalid_new_key_format', 400,
      { detail: 'New key must be exactly 6 digits (0-9).' });

  const session = await L.qOne(
    `SELECT cs.*, k.id AS key_id, k.key_hash AS current_hash,
            k.status AS key_status, k.expiry_ts
     FROM client_sessions cs
     JOIN license_keys k ON cs.key_id = k.id
     WHERE cs.session_id=$1 AND cs.is_active=TRUE`,
    [sessionId]
  );
  if (!session) return L.fail(res, 'session_invalid', 401);
  if (session.key_status === 'blocked') return L.fail(res, 'key_blocked', 403);

  const now = Math.floor(Date.now() / 1000);
  if (Number(session.expiry_ts) < now) return L.fail(res, 'key_expired', 403);

  const oldHash = L.hashKey(oldKey);
  if (oldHash !== session.current_hash)
    return L.fail(res, 'old_key_mismatch', 400);

  const newHash = L.hashKey(newKey);
  const existing = await L.qOne(
    `SELECT id FROM license_keys WHERE key_hash=$1`,
    [newHash]
  );
  if (existing) return L.fail(res, 'new_key_taken', 409);

  await L.run(
    `UPDATE license_keys SET key_hash=$1, key_plain=$2 WHERE id=$3`,
    [newHash, newKey, session.key_id]
  );

  await L.run(
    `UPDATE client_sessions SET is_active=FALSE WHERE key_id=$1`,
    [session.key_id]
  );

  return L.ok(res, {
    message: 'Key changed. Please log in again with the new key.',
    key_id: session.key_id
  });
}

// ═══════════════════════════════════════════════════════════════════════════
// CLIENT: WAKE OFFLINE DEVICES
// ═══════════════════════════════════════════════════════════════════════════

async function clientWake(req, res) {
  if (req.method !== 'POST') return L.fail(res, 'method_not_allowed', 405);

  const sessionId = String(req.headers['x-session-token'] || '').trim();
  if (!sessionId || sessionId.length !== 48)
    return L.fail(res, 'invalid_session', 401);

  const now = Math.floor(Date.now() / 1000);
  const sess = await L.qOne(
    `SELECT cs.*, k.status AS key_status, k.expiry_ts,
            fp.sa_json_base64, fp.project_id AS fb_project_id, fp.rtdb_url
     FROM client_sessions cs
     JOIN license_keys k ON cs.key_id = k.id
     JOIN firebase_projects fp ON cs.project_id = fp.id
     WHERE cs.session_id = $1 AND cs.is_active = TRUE`,
    [sessionId]
  );

  if (!sess) return L.fail(res, 'session_invalid', 401);
  if (Number(sess.expires_at) < now) return L.fail(res, 'session_expired', 401);
  if (sess.key_status === 'blocked') return L.fail(res, 'key_blocked', 403);
  if (Number(sess.expiry_ts) < now) return L.fail(res, 'key_expired', 403);
  if (!sess.sa_json_base64) return L.fail(res, 'project_not_configured', 500);

  const b = L.readBody(req);
  const tokens = Array.isArray(b.tokens)
    ? b.tokens.filter(t => typeof t === 'string' && t.length > 20)
    : [];

  if (tokens.length === 0) return L.fail(res, 'no_tokens', 400);

  try {
    const projectRow = {
      project_id: sess.fb_project_id,
      rtdb_url: sess.rtdb_url,
      sa_json_base64: sess.sa_json_base64
    };
    const { app } = await L.fbApp(projectRow);

    const message = {
      data: { type: 'wake', ts: String(Date.now()) },
      android: { priority: 'high', ttl: 60 * 1000 },
      tokens: tokens.slice(0, 500)
    };

    const result = await app.messaging().sendEachForMulticast(message);

    await L.run(`UPDATE client_sessions SET last_ping=$1 WHERE session_id=$2`, [now, sessionId]);

    return L.ok(res, {
      success: result.successCount,
      failed: result.failureCount
    });

  } catch (e) {
    console.error('[clientWake] Error:', e);
    return L.fail(res, 'wake_failed', 500, { detail: e.message });
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// ADMIN WEB AUTH
// ═══════════════════════════════════════════════════════════════════════════

async function adminLogin(req, res) {
  if (req.method !== 'POST') return L.fail(res, 'method_not_allowed', 405);

  const body = L.readBody(req);
  const username = L.sanitizeStr(body.username, 64);
  const password = typeof body.password === 'string' ? body.password : '';

  if (!username || !password) return L.fail(res, 'missing_fields', 400);

  const ip = L.clientIp(req);
  const rl = await L.checkRate(`admin:${ip}`, 5, 300);
  if (!rl.allowed)
    return L.fail(res, 'rate_limited', 429, { retry_after: rl.retryAfter });

  if (username !== process.env.ADMIN_USERNAME)
    return L.fail(res, 'invalid_credentials', 401);

  const hash = process.env.ADMIN_PASSWORD_HASH;
  if (!hash || !L.bcrypt.compareSync(password, hash))
    return L.fail(res, 'invalid_credentials', 401);

  const token = L.signJwt({ role: 'admin', username }, 60 * 60 * 8);

  res.setHeader('Set-Cookie',
    `admin_session=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${60*60*8}`);

  await L.resetRate(`admin:${ip}`);
  return L.ok(res, { username });
}

async function adminLogout(req, res) {
  res.setHeader('Set-Cookie',
    'admin_session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0');
  return L.ok(res, {});
}

async function adminMe(req, res) {
  const sess = L.requireAdminSession(req);
  if (!sess) return L.fail(res, 'unauthorized', 401);
  return L.ok(res, { username: sess.username });
}

// ═══════════════════════════════════════════════════════════════════════════
// ADMIN: KEYS
// ═══════════════════════════════════════════════════════════════════════════

async function keyCreate(req, res) {
  if (req.method !== 'POST') return L.fail(res, 'method_not_allowed', 405);
  if (!L.requireAdminSession(req)) return L.fail(res, 'unauthorized', 401);

  const b = L.readBody(req);
  const type = L.sanitizeStr(b.type || 'Client', 20);
  const projectId = parseInt(b.project_id, 10);
  const customerName = L.sanitizeStr(b.customer_name || '', 128);
  const notes = L.sanitizeStr(b.notes || '', 512);
  const expiryDays = Math.max(1, Math.min(3650, parseInt(b.expiry_days, 10) || 30));

  if (!['Admin', 'Client', 'Third Client'].includes(type))
    return L.fail(res, 'invalid_type', 400);
  if (!projectId) return L.fail(res, 'project_id_required', 400);

  const project = await L.qOne(
    `SELECT id FROM firebase_projects WHERE id=$1 AND is_active=TRUE`,
    [projectId]
  );
  if (!project) return L.fail(res, 'project_not_found', 404);

  const now = Math.floor(Date.now() / 1000);
  const expiryTs = now + (expiryDays * 86400);

  let inserted = null;
  let rawKey = '';
  for (let attempt = 0; attempt < 10; attempt++) {
    rawKey = L.generateKey();
    const keyHash = L.hashKey(rawKey);
    try {
      inserted = await L.qOne(
        `INSERT INTO license_keys
         (key_hash, key_plain, type, status, expiry_ts, project_id, customer_name, notes, created_at, bound_device_fp)
         VALUES ($1,$2,$3,'active',$4,$5,$6,$7,$8,'') RETURNING id`,
        [keyHash, rawKey, type, expiryTs, projectId, customerName, notes, now]
      );
      break;
    } catch (e) {
      if (e.code === '23505') continue;
      throw e;
    }
  }

  if (!inserted) {
    return L.fail(res, 'key_generation_failed', 500,
      { detail: 'Could not generate a unique key after multiple attempts. Try again.' });
  }

  return L.ok(res, {
    id: inserted.id, key: rawKey, type, expiry_ts: expiryTs
  });
}

async function keyList(req, res) {
  if (!L.requireAdminSession(req)) return L.fail(res, 'unauthorized', 401);

  const keys = await L.q(
    `SELECT k.id, k.key_plain, k.type, k.status, k.expiry_ts, k.customer_name,
            k.notes, k.login_count, k.last_login_at, k.first_login_at, k.created_at,
            k.bound_device_fp,
            fp.name AS project_name, fp.project_id AS fb_project_id
     FROM license_keys k
     JOIN firebase_projects fp ON k.project_id = fp.id
     ORDER BY k.created_at DESC LIMIT 500`
  );

  const now = Math.floor(Date.now() / 1000);
  const enriched = keys.map(k => ({
    ...k,
    expiry_ts: Number(k.expiry_ts),
    is_expired: Number(k.expiry_ts) < now,
    expires_in_s: Math.max(0, Number(k.expiry_ts) - now),
    is_bound: !!(k.bound_device_fp && k.bound_device_fp.trim()),
    bound_device_short: k.bound_device_fp ? k.bound_device_fp.substring(0, 12) + '...' : ''
  }));

  return L.ok(res, { keys: enriched });
}

async function keyUpdate(req, res) {
  if (req.method !== 'POST') return L.fail(res, 'method_not_allowed', 405);
  if (!L.requireAdminSession(req)) return L.fail(res, 'unauthorized', 401);

  const b = L.readBody(req);
  const id = parseInt(b.id, 10);
  const action = L.sanitizeStr(b.action, 32);
  if (!id || !action) return L.fail(res, 'id_and_action_required', 400);

  const key = await L.qOne(`SELECT * FROM license_keys WHERE id=$1`, [id]);
  if (!key) return L.fail(res, 'not_found', 404);

  const now = Math.floor(Date.now() / 1000);

  switch (action) {
    case 'block':
      await L.run(`UPDATE license_keys SET status='blocked' WHERE id=$1`, [id]);
      await L.run(`UPDATE client_sessions SET is_active=FALSE WHERE key_id=$1`, [id]);
      return L.ok(res, { message: 'Key blocked, sessions killed' });

    case 'unblock':
      await L.run(`UPDATE license_keys SET status='active' WHERE id=$1`, [id]);
      return L.ok(res, {});

    case 'extend': {
      const days = Math.max(1, Math.min(3650, parseInt(b.days, 10) || 30));
      const newExpiry = Math.max(now, Number(key.expiry_ts)) + (days * 86400);
      await L.run(
        `UPDATE license_keys SET expiry_ts=$1, status='active' WHERE id=$2`,
        [newExpiry, id]
      );
      return L.ok(res, { new_expiry_ts: newExpiry });
    }

    case 'reset_device':
      await L.run(`UPDATE license_keys SET bound_device_fp='' WHERE id=$1`, [id]);
      await L.run(`UPDATE client_sessions SET is_active=FALSE WHERE key_id=$1`, [id]);
      return L.ok(res, { message: 'Device unbound. Client can log in from a new device.' });

    case 'update_info':
      await L.run(
        `UPDATE license_keys SET customer_name=$1, notes=$2, type=$3 WHERE id=$4`,
        [
          L.sanitizeStr(b.customer_name ?? key.customer_name, 128),
          L.sanitizeStr(b.notes ?? key.notes, 512),
          L.sanitizeStr(b.type ?? key.type, 20),
          id
        ]
      );
      return L.ok(res, {});

    case 'delete':
      await L.run(`UPDATE client_sessions SET is_active=FALSE WHERE key_id=$1`, [id]);
      await L.run(`DELETE FROM license_keys WHERE id=$1`, [id]);
      return L.ok(res, {});

    default:
      return L.fail(res, 'unknown_action', 400);
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// ADMIN: PROJECTS
// ═══════════════════════════════════════════════════════════════════════════

async function projectManage(req, res) {
  if (!L.requireAdminSession(req)) return L.fail(res, 'unauthorized', 401);

  if (req.method === 'GET') {
    const projects = await L.q(
      `SELECT id, name, rtdb_url, project_id, is_active, created_at, allowed_packages,
              (CASE WHEN COALESCE(sa_json_base64,'') != '' THEN TRUE ELSE FALSE END) AS has_sa
       FROM firebase_projects ORDER BY name`
    );
    return L.ok(res, { projects });
  }

  if (req.method === 'POST') {
    const b = L.readBody(req);
    const action = L.sanitizeStr(b.action || 'create', 32);

    if (action === 'create') {
      const name = L.sanitizeStr(b.name, 128);
      const rtdbUrl = L.sanitizeStr(b.rtdb_url, 256).replace(/\/$/, '');
      const projectId = L.sanitizeStr(b.project_id, 128);
      const packages = L.sanitizeStr(b.allowed_packages || 'com.cloud.tools750', 512);

      if (!name || !rtdbUrl || !projectId)
        return L.fail(res, 'missing_fields', 400);

      const now = Math.floor(Date.now() / 1000);
      const inserted = await L.qOne(
        `INSERT INTO firebase_projects (name, rtdb_url, project_id, is_active, created_at, allowed_packages)
         VALUES ($1,$2,$3,TRUE,$4,$5) RETURNING id`,
        [name, rtdbUrl, projectId, now, packages]
      );

      return L.ok(res, { id: inserted.id });
    }

    if (action === 'update_packages') {
      const id = parseInt(b.id, 10);
      const packages = L.sanitizeStr(b.allowed_packages || '', 512);
      if (!id) return L.fail(res, 'id_required', 400);
      if (!packages) return L.fail(res, 'packages_required', 400);
      await L.run(`UPDATE firebase_projects SET allowed_packages=$1 WHERE id=$2`, [packages, id]);
      return L.ok(res, { message: 'Packages updated' });
    }

    if (action === 'toggle_active') {
      const id = parseInt(b.id, 10);
      if (!id) return L.fail(res, 'id_required', 400);
      const p = await L.qOne(`SELECT is_active FROM firebase_projects WHERE id=$1`, [id]);
      if (!p) return L.fail(res, 'not_found', 404);
      const newState = !p.is_active;
      await L.run(`UPDATE firebase_projects SET is_active=$1 WHERE id=$2`, [newState, id]);
      return L.ok(res, { is_active: newState });
    }

    return L.fail(res, 'unknown_action', 400);
  }

  return L.fail(res, 'method_not_allowed', 405);
}

async function projectUploadSa(req, res) {
  if (req.method !== 'POST') return L.fail(res, 'method_not_allowed', 405);
  if (!L.requireAdminSession(req)) return L.fail(res, 'unauthorized', 401);

  const b = L.readBody(req);
  const projectId = parseInt(b.project_id, 10);
  const saJson = typeof b.sa_json === 'string' ? b.sa_json : '';

  if (!projectId) return L.fail(res, 'project_id_required', 400);
  if (!saJson || saJson.length < 100)
    return L.fail(res, 'sa_json_required', 400, { detail: 'Paste valid service account JSON' });

  let sa;
  try {
    sa = JSON.parse(saJson);
  } catch (e) {
    return L.fail(res, 'invalid_json', 400, { detail: e.message });
  }

  if (sa.type !== 'service_account' || !sa.private_key || !sa.client_email || !sa.project_id) {
    return L.fail(res, 'not_service_account', 400,
      { detail: 'Not a valid service account JSON.' });
  }

  const proj = await L.qOne(`SELECT id, project_id FROM firebase_projects WHERE id=$1`, [projectId]);
  if (!proj) return L.fail(res, 'project_not_found', 404);

  const b64 = Buffer.from(saJson, 'utf8').toString('base64');

  await L.run(
    `UPDATE firebase_projects SET sa_json_base64=$1 WHERE id=$2`,
    [b64, projectId]
  );

  return L.ok(res, {
    message: 'Service account uploaded successfully',
    project_id: proj.project_id,
    sa_project_id: sa.project_id,
    client_email: sa.client_email
  });
}

// ═══════════════════════════════════════════════════════════════════════════
// ADMIN: SESSIONS
// ═══════════════════════════════════════════════════════════════════════════

async function sessionList(req, res) {
  if (!L.requireAdminSession(req)) return L.fail(res, 'unauthorized', 401);

  const sessions = await L.q(
    `SELECT cs.session_id, cs.key_id, cs.android_id, cs.package_name, cs.ip,
            cs.created_at, cs.expires_at, cs.last_ping, cs.is_active,
            k.customer_name, k.type, fp.name AS project_name
     FROM client_sessions cs
     JOIN license_keys k ON cs.key_id = k.id
     JOIN firebase_projects fp ON cs.project_id = fp.id
     WHERE cs.is_active = TRUE
     ORDER BY cs.last_ping DESC LIMIT 200`
  );

  return L.ok(res, { sessions });
}

async function sessionKill(req, res) {
  if (req.method !== 'POST') return L.fail(res, 'method_not_allowed', 405);
  if (!L.requireAdminSession(req)) return L.fail(res, 'unauthorized', 401);

  const b = L.readBody(req);
  const sessionId = L.sanitizeStr(b.session_id, 64);
  if (!sessionId || sessionId.length !== 48)
    return L.fail(res, 'invalid_session_id', 400);

  await L.run(`UPDATE client_sessions SET is_active=FALSE WHERE session_id=$1`, [sessionId]);
  return L.ok(res, {});
}

// ═══════════════════════════════════════════════════════════════════════════
// ADMIN: WAKE (web panel)
// ═══════════════════════════════════════════════════════════════════════════

async function wakeDevices(req, res) {
  if (req.method !== 'POST') return L.fail(res, 'method_not_allowed', 405);
  if (!L.requireAdminSession(req)) return L.fail(res, 'unauthorized', 401);

  const b = L.readBody(req);
  const projectRef = String(b.project_id || '').trim();
  const tokens = Array.isArray(b.tokens)
    ? b.tokens.filter(t => typeof t === 'string' && t.length > 20)
    : [];

  if (!projectRef) return L.fail(res, 'project_id_required', 400);
  if (tokens.length === 0) return L.fail(res, 'no_tokens', 400);

  const project = await L.qOne(
    `SELECT id, project_id, rtdb_url, sa_json_base64
     FROM firebase_projects
     WHERE (id::text = $1 OR project_id = $1)
       AND is_active = TRUE
     LIMIT 1`,
    [projectRef]
  );

  if (!project) return L.fail(res, 'project_not_found', 404);
  if (!project.sa_json_base64) {
    return L.fail(res, 'project_not_configured', 500,
      { detail: 'Service account not uploaded for this project.' });
  }

  try {
    const { app } = await L.fbApp(project);

    const message = {
      data: { type: 'wake', ts: String(Date.now()) },
      android: { priority: 'high', ttl: 60 * 1000 },
      tokens: tokens.slice(0, 500)
    };

    const result = await app.messaging().sendEachForMulticast(message);

    return L.ok(res, {
      success: result.successCount,
      failed: result.failureCount
    });

  } catch (e) {
    console.error('[wake] Error:', e);
    return L.fail(res, 'wake_failed', 500, { detail: e.message });
  }
}
