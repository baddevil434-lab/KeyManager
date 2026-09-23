// api/_lib.js — shared helpers for all API endpoints
const crypto = require('crypto');
const admin  = require('firebase-admin');
const { Pool } = require('pg');
const { Redis } = require('@upstash/redis');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

// ─── Postgres pool (lazy) ────────────────────────────────────────────────
let _pool;
function db() {
  if (!_pool) {
    _pool = new Pool({
      connectionString: process.env.DATABASE_URL,
      ssl: { rejectUnauthorized: false },
      max: 5,
      idleTimeoutMillis: 30000,
      connectionTimeoutMillis: 10000
    });
  }
  return _pool;
}
async function q(sql, params = []) {
  const r = await db().query(sql, params);
  return r.rows;
}
async function qOne(sql, params = []) {
  const rows = await q(sql, params);
  return rows[0] || null;
}
async function run(sql, params = []) {
  await db().query(sql, params);
}

// ─── Redis (Upstash) ─────────────────────────────────────────────────────
let _redis;
function redis() {
  if (!_redis) _redis = Redis.fromEnv();
  return _redis;
}

// ─── Firebase Admin multi-project (SA base64 in env) ─────────────────────
const _fbApps = {};
function fbApp(prefix) {
  const key = String(prefix).toUpperCase();
  if (_fbApps[key]) return _fbApps[key];

  const encoded = process.env[`SA_${key}`];
  if (!encoded) throw new Error(`SA_${key} not set in Vercel env`);

  let sa;
  try {
    sa = JSON.parse(Buffer.from(encoded, 'base64').toString('utf8'));
  } catch (e) {
    throw new Error(`Invalid SA_${key}: ${e.message}`);
  }

  const app = admin.initializeApp({
    credential: admin.credential.cert(sa),
    databaseURL: sa.database_url
      || `https://${sa.project_id}-default-rtdb.firebaseio.com`
  }, key);

  _fbApps[key] = { app, sa };
  return _fbApps[key];
}

async function mintCustomToken(prefix, uid, claims) {
  const { app } = fbApp(prefix);
  return app.auth().createCustomToken(uid, claims);
}

// ─── Security helpers ────────────────────────────────────────────────────
function hashKey(rawKey) {
  return crypto.createHmac('sha256', process.env.JWT_SECRET)
    .update(String(rawKey).toUpperCase().trim())
    .digest('hex');
}

function generateKey(length = 24) {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let key = '';
  for (let i = 0; i < length; i++) {
    if (i > 0 && i % 6 === 0) key += '-';
    key += chars[crypto.randomInt(0, chars.length)];
  }
  return key; // XXXXXX-XXXXXX-XXXXXX-XXXXXX
}

function signJwt(payload, expiresInSec = 3600) {
  return jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: expiresInSec });
}

function verifyJwt(token) {
  try {
    return jwt.verify(token, process.env.JWT_SECRET);
  } catch {
    return null;
  }
}

function sanitizeStr(v, max = 512) {
  if (typeof v !== 'string') return '';
  return v.trim().slice(0, max);
}

// ─── Rate limit (Upstash sliding window) ─────────────────────────────────
async function checkRate(identifier, max = 10, windowSec = 60) {
  const r = redis();
  const key = `rl:${identifier}`;
  const count = await r.incr(key);
  if (count === 1) await r.expire(key, windowSec);
  if (count > max) {
    const ttl = await r.ttl(key);
    return { allowed: false, retryAfter: ttl > 0 ? ttl : windowSec };
  }
  return { allowed: true, remaining: max - count };
}

async function resetRate(identifier) {
  await redis().del(`rl:${identifier}`);
}

// ─── HTTP helpers ────────────────────────────────────────────────────────
function clientIp(req) {
  const h = req.headers['x-forwarded-for'] || req.headers['x-real-ip'] || '';
  return String(h).split(',')[0].trim() || '0.0.0.0';
}

function readBody(req) {
  // Vercel auto-parses JSON if content-type is JSON
  if (req.body && typeof req.body === 'object') return req.body;
  return {};
}

function sendJson(res, status, obj) {
  res.status(status).setHeader('Content-Type', 'application/json');
  res.send(JSON.stringify(obj));
}

function ok(res, obj = {}) {
  sendJson(res, 200, { ok: true, ...obj });
}

function fail(res, error, status = 400, extra = {}) {
  sendJson(res, status, { ok: false, error, ...extra });
}

function getCookie(req, name) {
  const raw = req.headers.cookie || '';
  const m = raw.match(new RegExp('(?:^|; )' + name + '=([^;]+)'));
  return m ? decodeURIComponent(m[1]) : '';
}

function requireAdminSession(req) {
  const token = getCookie(req, 'admin_session');
  if (!token) return null;
  const sess = verifyJwt(token);
  if (!sess || sess.role !== 'admin') return null;
  return sess;
}

// ─── Exports ─────────────────────────────────────────────────────────────
module.exports = {
  q, qOne, run,
  redis,
  fbApp, mintCustomToken,
  hashKey, generateKey, signJwt, verifyJwt, sanitizeStr,
  checkRate, resetRate,
  clientIp, readBody, sendJson, ok, fail,
  getCookie, requireAdminSession,
  bcrypt,
  crypto
};
