'use strict';

/**
 * Auth Module — API Gateway
 * Menangani login, refresh, logout, dan service token
 */

const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '..', '.env') });

const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const { getDatabase } = require('../shared/database');
const {
  generateAccessToken,
  generateRefreshToken,
  generateServiceToken,
  verifyRefreshToken,
} = require('../shared/token-verification');
const { isDeviceRegisteredForUser } = require('./policy');
const { writeAuditLog } = require('./middleware/audit');

/**
 * Hash refresh token untuk penyimpanan aman di database
 * Menyimpan hash, bukan token mentah
 */
function hashRefreshToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

/**
 * POST /auth/login
 * Login pengguna dengan kredensial dan device ID
 */
async function login(req, res) {
  const { username, password } = req.body;
  const deviceId = req.headers['x-device-id'];
  const ipAddress = req.ip || req.connection?.remoteAddress;

  // Validasi input
  if (!username || !password) {
    writeAuditLog({
      subject: username || 'unknown',
      method: 'POST',
      endpoint: '/auth/login',
      deviceId,
      decision: 'deny',
      reason: 'Username atau password tidak disediakan',
      httpStatus: 400,
      ipAddress,
    });
    return res.status(400).json({
      success: false,
      message: 'Username dan password wajib diisi',
    });
  }

  if (!deviceId) {
    writeAuditLog({
      subject: username,
      method: 'POST',
      endpoint: '/auth/login',
      deviceId: null,
      decision: 'deny',
      reason: 'Device ID tidak disediakan',
      httpStatus: 401,
      ipAddress,
    });
    return res.status(401).json({
      success: false,
      message: 'Header X-Device-ID wajib disediakan',
    });
  }

  const db = getDatabase();

  // Cari user di database
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);

  if (!user) {
    writeAuditLog({
      subject: username,
      method: 'POST',
      endpoint: '/auth/login',
      deviceId,
      decision: 'deny',
      reason: 'Username tidak ditemukan',
      httpStatus: 401,
      ipAddress,
    });
    // Pesan generik untuk mencegah user enumeration
    return res.status(401).json({
      success: false,
      message: 'Kredensial tidak valid',
    });
  }

  // Verifikasi password
  const isPasswordValid = bcrypt.compareSync(password, user.password_hash);
  if (!isPasswordValid) {
    writeAuditLog({
      subject: username,
      subjectRole: user.role,
      method: 'POST',
      endpoint: '/auth/login',
      deviceId,
      decision: 'deny',
      reason: 'Password salah',
      httpStatus: 401,
      ipAddress,
    });
    return res.status(401).json({
      success: false,
      message: 'Kredensial tidak valid',
    });
  }

  // Verifikasi device ID terdaftar
  if (!isDeviceRegisteredForUser(user.id, deviceId)) {
    writeAuditLog({
      subject: username,
      subjectRole: user.role,
      method: 'POST',
      endpoint: '/auth/login',
      deviceId,
      decision: 'deny',
      reason: `Device '${deviceId}' tidak terdaftar untuk pengguna ini`,
      httpStatus: 403,
      ipAddress,
    });
    return res.status(403).json({
      success: false,
      message: 'Device tidak terdaftar untuk akun ini',
    });
  }

  // Generate token
  const accessToken  = generateAccessToken(user);
  const refreshToken = generateRefreshToken(user);
  const tokenHash    = hashRefreshToken(refreshToken);

  // Simpan refresh token ke database (hash saja)
  const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
  try {
    db.prepare(`
      INSERT INTO refresh_tokens (user_id, token_hash, expires_at)
      VALUES (?, ?, ?)
    `).run(user.id, tokenHash, expiresAt);
  } catch (dbErr) {
    console.error('[AUTH] Gagal menyimpan refresh token:', dbErr.message);
    return res.status(500).json({ success: false, message: 'Terjadi kesalahan internal saat login' });
  }

  writeAuditLog({
    subject: username,
    subjectRole: user.role,
    method: 'POST',
    endpoint: '/auth/login',
    deviceId,
    decision: 'allow',
    reason: 'Login berhasil',
    httpStatus: 200,
    ipAddress,
  });

  return res.status(200).json({
    success: true,
    message: 'Login berhasil',
    data: {
      access_token: accessToken,
      refresh_token: refreshToken,
      token_type: 'Bearer',
      expires_in: 600, // 10 menit dalam detik
    },
  });
}

/**
 * POST /auth/refresh
 * Minta access token baru menggunakan refresh token
 */
async function refresh(req, res) {
  const { refresh_token } = req.body;
  const ipAddress = req.ip || req.connection?.remoteAddress;

  if (!refresh_token) {
    return res.status(400).json({
      success: false,
      message: 'Refresh token wajib disediakan',
    });
  }

  // Verifikasi signature dan masa berlaku
  const verification = verifyRefreshToken(refresh_token);
  if (!verification.valid) {
    writeAuditLog({
      subject: 'unknown',
      method: 'POST',
      endpoint: '/auth/refresh',
      deviceId: null,
      decision: 'deny',
      reason: `Refresh token tidak valid: ${verification.error}`,
      httpStatus: 401,
      ipAddress,
    });
    return res.status(401).json({
      success: false,
      message: verification.error || 'Refresh token tidak valid',
    });
  }

  const db = getDatabase();
  const tokenHash = hashRefreshToken(refresh_token);

  // Periksa apakah token ada dan belum dicabut
  const storedToken = db.prepare(`
    SELECT rt.*, u.username, u.role FROM refresh_tokens rt
    JOIN users u ON u.id = rt.user_id
    WHERE rt.token_hash = ?
  `).get(tokenHash);

  if (!storedToken) {
    writeAuditLog({
      subject: verification.payload?.sub || 'unknown',
      method: 'POST',
      endpoint: '/auth/refresh',
      deviceId: null,
      decision: 'deny',
      reason: 'Refresh token tidak ditemukan di database',
      httpStatus: 401,
      ipAddress,
    });
    return res.status(401).json({
      success: false,
      message: 'Refresh token tidak valid',
    });
  }

  if (storedToken.revoked) {
    writeAuditLog({
      subject: storedToken.username,
      subjectRole: storedToken.role,
      method: 'POST',
      endpoint: '/auth/refresh',
      deviceId: null,
      decision: 'deny',
      reason: 'Refresh token sudah dicabut (logout sebelumnya)',
      httpStatus: 401,
      ipAddress,
    });
    return res.status(401).json({
      success: false,
      message: 'Refresh token sudah tidak valid',
    });
  }

  // Periksa masa berlaku di database (double-check)
  if (new Date(storedToken.expires_at) < new Date()) {
    writeAuditLog({
      subject: storedToken.username,
      subjectRole: storedToken.role,
      method: 'POST',
      endpoint: '/auth/refresh',
      deviceId: null,
      decision: 'deny',
      reason: 'Refresh token sudah kedaluwarsa',
      httpStatus: 401,
      ipAddress,
    });
    return res.status(401).json({
      success: false,
      message: 'Refresh token sudah kedaluwarsa',
    });
  }

  // Ambil data user terbaru dari database
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(storedToken.user_id);
  if (!user) {
    return res.status(401).json({ success: false, message: 'Pengguna tidak ditemukan' });
  }

  // Generate access token baru
  const newAccessToken = generateAccessToken(user);

  writeAuditLog({
    subject: user.username,
    subjectRole: user.role,
    method: 'POST',
    endpoint: '/auth/refresh',
    deviceId: null,
    decision: 'allow',
    reason: 'Refresh token berhasil digunakan, access token baru diterbitkan',
    httpStatus: 200,
    ipAddress,
  });

  return res.status(200).json({
    success: true,
    message: 'Access token berhasil diperbarui',
    data: {
      access_token: newAccessToken,
      token_type: 'Bearer',
      expires_in: 600,
    },
  });
}

/**
 * POST /auth/logout
 * Cabut refresh token (logout)
 */
async function logout(req, res) {
  const { refresh_token } = req.body;
  const ipAddress = req.ip || req.connection?.remoteAddress;

  if (!refresh_token) {
    return res.status(400).json({
      success: false,
      message: 'Refresh token wajib disediakan untuk logout',
    });
  }

  const verification = verifyRefreshToken(refresh_token);
  const tokenHash = hashRefreshToken(refresh_token);
  const db = getDatabase();

  const storedToken = db.prepare(`
    SELECT rt.*, u.username, u.role FROM refresh_tokens rt
    JOIN users u ON u.id = rt.user_id
    WHERE rt.token_hash = ?
  `).get(tokenHash);

  if (!storedToken || storedToken.revoked) {
    // Tetap return success untuk logout — tidak expose info apakah token pernah ada
    return res.status(200).json({
      success: true,
      message: 'Logout berhasil',
    });
  }

  // Cabut refresh token
  db.prepare(`
    UPDATE refresh_tokens 
    SET revoked = 1, revoked_at = datetime('now')
    WHERE token_hash = ?
  `).run(tokenHash);

  writeAuditLog({
    subject: storedToken.username,
    subjectRole: storedToken.role,
    method: 'POST',
    endpoint: '/auth/logout',
    deviceId: null,
    decision: 'allow',
    reason: 'Logout berhasil, refresh token dicabut',
    httpStatus: 200,
    ipAddress,
  });

  return res.status(200).json({
    success: true,
    message: 'Logout berhasil',
  });
}

/**
 * POST /auth/service
 * Minta service token untuk komunikasi antar-service
 */
async function serviceToken(req, res) {
  const { client_id, client_secret } = req.body;
  const ipAddress = req.ip || req.connection?.remoteAddress;

  if (!client_id || !client_secret) {
    return res.status(400).json({
      success: false,
      message: 'client_id dan client_secret wajib disediakan',
    });
  }

  const db = getDatabase();
  const client = db.prepare(
    'SELECT * FROM service_clients WHERE client_id = ? AND is_active = 1'
  ).get(client_id);

  if (!client) {
    writeAuditLog({
      subject: `service:${client_id}`,
      method: 'POST',
      endpoint: '/auth/service',
      deviceId: null,
      decision: 'deny',
      reason: 'Service client tidak ditemukan atau tidak aktif',
      httpStatus: 401,
      ipAddress,
    });
    return res.status(401).json({
      success: false,
      message: 'Kredensial service tidak valid',
    });
  }

  // Verifikasi secret
  const isSecretValid = bcrypt.compareSync(client_secret, client.client_secret_hash);
  if (!isSecretValid) {
    writeAuditLog({
      subject: `service:${client_id}`,
      method: 'POST',
      endpoint: '/auth/service',
      deviceId: null,
      decision: 'deny',
      reason: 'Service client secret salah',
      httpStatus: 401,
      ipAddress,
    });
    return res.status(401).json({
      success: false,
      message: 'Kredensial service tidak valid',
    });
  }

  // Generate service token
  const token = generateServiceToken({
    clientId: client.client_id,
    serviceName: client.service_name,
    scope: client.allowed_scopes,
  });

  writeAuditLog({
    subject: `service:${client_id}`,
    method: 'POST',
    endpoint: '/auth/service',
    deviceId: null,
    decision: 'allow',
    reason: `Service token diterbitkan untuk ${client.service_name}`,
    httpStatus: 200,
    ipAddress,
  });

  return res.status(200).json({
    success: true,
    message: 'Service token berhasil diterbitkan',
    data: {
      access_token: token,
      token_type: 'Bearer',
      expires_in: 300, // 5 menit
    },
  });
}

module.exports = { login, refresh, logout, serviceToken };
