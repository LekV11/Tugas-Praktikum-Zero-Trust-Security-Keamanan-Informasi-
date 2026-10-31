'use strict';

/**
 * API Gateway — Zero Trust Sistem Nilai
 * Port: 3000
 * Peran: Policy Enforcement Point (PEP)
 *
 * Menggunakan forward manual dengan fetch() bawaan Node.js
 * untuk menghindari masalah body-stream yang sudah dikonsumsi express.json()
 */

const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '..', '.env') });

// =============================================
// VALIDASI KONFIGURASI SAAT STARTUP
// =============================================
const REQUIRED_ENV = [
  'JWT_ACCESS_SECRET',
  'JWT_REFRESH_SECRET',
  'JWT_SERVICE_SECRET',
  'GATEWAY_SECRET',
  'SERVICE_NILAI_CLIENT_ID',
  'SERVICE_NILAI_CLIENT_SECRET',
];
const SECRET_FIELDS = ['JWT_ACCESS_SECRET', 'JWT_REFRESH_SECRET', 'JWT_SERVICE_SECRET', 'GATEWAY_SECRET'];
const MIN_SECRET_LENGTH = 32;

for (const key of REQUIRED_ENV) {
  if (!process.env[key]) {
    console.error(`[STARTUP ERROR] Variabel lingkungan wajib tidak ditemukan: ${key}`);
    process.exit(1);
  }
}
for (const key of SECRET_FIELDS) {
  if (process.env[key].length < MIN_SECRET_LENGTH) {
    console.error(`[STARTUP ERROR] ${key} terlalu pendek (minimal ${MIN_SECRET_LENGTH} karakter).`);
    process.exit(1);
  }
}

const express = require('express');
const crypto  = require('crypto');

const { login, refresh, logout, serviceToken } = require('./auth');
const { evaluate }    = require('./policy');
const { verifyToken } = require('./middleware/verify-request');
const { writeAuditLog } = require('./middleware/audit');

const app  = express();
const PORT = parseInt(process.env.GATEWAY_PORT) || 3000;

const SERVICE_NILAI_URL     = `http://localhost:${process.env.SERVICE_NILAI_PORT || 3001}`;
const SERVICE_TRANSKRIP_URL = `http://localhost:${process.env.SERVICE_TRANSKRIP_PORT || 3002}`;
const GATEWAY_SECRET        = process.env.GATEWAY_SECRET;

// =============================================
// ROUTE MAP: prefix path → service URL
// =============================================
const ROUTE_MAP = [
  { prefixes: ['/nilai', '/kelas'], target: SERVICE_NILAI_URL },
  { prefixes: ['/transkrip'],        target: SERVICE_TRANSKRIP_URL },
];

function resolveTarget(pathname) {
  for (const route of ROUTE_MAP) {
    for (const prefix of route.prefixes) {
      if (pathname === prefix || pathname.startsWith(prefix + '/')) {
        return route.target;
      }
    }
  }
  return null;
}

// =============================================
// MIDDLEWARE GLOBAL
// =============================================
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

app.use((req, res, next) => {
  req.requestId = crypto.randomUUID();
  res.setHeader('X-Request-ID', req.requestId);
  next();
});

// =============================================
// HEALTH CHECK
// =============================================
app.get('/health', (req, res) => {
  res.json({ service: 'API Gateway', status: 'running', port: PORT, timestamp: new Date().toISOString() });
});

// =============================================
// ENDPOINT AUTENTIKASI
// =============================================
app.post('/auth/login',   login);
app.post('/auth/refresh', refresh);
app.post('/auth/logout',  logout);
app.post('/auth/service', serviceToken);

// =============================================
// VERIFIKASI TOKEN
// =============================================
app.use(verifyToken);

// =============================================
// POLICY ENFORCEMENT
// =============================================
app.use((req, res, next) => {
  const ipAddress = req.ip || req.connection?.remoteAddress;
  const deviceId  = req.headers['x-device-id'] || null;

  if (!req.tokenPayload) {
    const reason = req.tokenError || 'Token akses tidak valid atau tidak ada';
    writeAuditLog({ subject: 'unknown', method: req.method, endpoint: req.path, deviceId, decision: 'deny', reason, httpStatus: 401, requestId: req.requestId, ipAddress });
    return res.status(401).json({ success: false, message: reason });
  }

  const context = {
    method: req.method, path: req.path, tokenPayload: req.tokenPayload,
    tokenError: req.tokenError, deviceId, params: req.params,
    body: req.body, headers: req.headers, ipAddress, requestId: req.requestId,
  };

  const policyResult = evaluate(context);

  writeAuditLog({
    subject:     req.tokenPayload.username || req.tokenPayload.sub,
    subjectRole: req.tokenPayload.role,
    method:      req.method,
    endpoint:    req.path,
    deviceId,
    decision:    policyResult.decision,
    reason:      policyResult.reason,
    httpStatus:  policyResult.httpStatus,
    requestId:   req.requestId,
    ipAddress,
  });

  if (policyResult.decision !== 'allow') {
    return res.status(policyResult.httpStatus || 403).json({ success: false, message: policyResult.reason });
  }

  req.policyData = policyResult.data;
  next();
});

// =============================================
// FORWARD HANDLER — menggunakan fetch() bawaan Node.js
// Menghindari masalah stream body yang sudah dikonsumsi express.json()
// =============================================
app.use(async (req, res) => {
  const target = resolveTarget(req.path);

  if (!target) {
    return res.status(404).json({ success: false, message: 'Endpoint tidak ditemukan' });
  }

  // Bangun URL tujuan — teruskan path dan query string utuh
  const targetUrl = `${target}${req.path}${req.url.includes('?') ? '?' + req.url.split('?')[1] : ''}`;

  // Bangun headers yang akan diteruskan
  const forwardHeaders = {
    'Content-Type':      'application/json',
    'X-Gateway-Secret':  GATEWAY_SECRET,
    'X-Request-ID':      req.requestId,
  };

  // Teruskan Authorization header
  if (req.headers['authorization']) {
    forwardHeaders['Authorization'] = req.headers['authorization'];
  }

  // Teruskan Device ID
  if (req.headers['x-device-id']) {
    forwardHeaders['X-Device-ID'] = req.headers['x-device-id'];
  }

  // Teruskan policy data
  if (req.policyData && Object.keys(req.policyData).length > 0) {
    forwardHeaders['X-Policy-Data'] = JSON.stringify(req.policyData);
  }

  // Siapkan body — gunakan body yang sudah di-parse express.json()
  let fetchBody;
  const hasBody = ['POST', 'PUT', 'PATCH'].includes(req.method);
  if (hasBody) {
    fetchBody = JSON.stringify(req.body ?? {});
  }

  try {
    const upstreamResp = await fetch(targetUrl, {
      method:  req.method,
      headers: forwardHeaders,
      body:    fetchBody,
    });

    // Teruskan status dan response dari service ke client
    const data = await upstreamResp.json().catch(() => ({ success: false, message: 'Response dari service tidak valid' }));
    return res.status(upstreamResp.status).json(data);

  } catch (err) {
    console.error(`[GATEWAY FORWARD ERROR] ${req.method} ${req.path}:`, err.message);

    writeAuditLog({
      subject:     req.tokenPayload?.username || 'unknown',
      subjectRole: req.tokenPayload?.role,
      method:      req.method,
      endpoint:    req.path,
      deviceId:    req.headers['x-device-id'],
      decision:    'deny',
      reason:      `Service tidak dapat dijangkau: ${err.message}`,
      httpStatus:  503,
      requestId:   req.requestId,
    });

    return res.status(503).json({ success: false, message: 'Service tidak tersedia saat ini' });
  }
});

// =============================================
// ERROR HANDLER
// =============================================
app.use((err, req, res, next) => {
  console.error('[GATEWAY ERROR]', err);
  if (!res.headersSent) {
    res.status(500).json({ success: false, message: 'Terjadi kesalahan internal pada gateway' });
  }
});

// =============================================
// START SERVER
// =============================================
app.listen(PORT, () => {
  console.log('='.repeat(50));
  console.log(`API Gateway berjalan di port ${PORT}`);
  console.log(`Service Nilai     : ${SERVICE_NILAI_URL}`);
  console.log(`Service Transkrip : ${SERVICE_TRANSKRIP_URL}`);
  console.log(`Timezone          : ${process.env.TIMEZONE || 'Asia/Jakarta'}`);
  console.log(`Jam Akses         : ${process.env.ACCESS_TIME_START}–${process.env.ACCESS_TIME_END}`);
  console.log('='.repeat(50));
});

module.exports = app;
