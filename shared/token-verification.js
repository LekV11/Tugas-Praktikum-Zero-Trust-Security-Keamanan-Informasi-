'use strict';

/**
 * Shared Token Verification Module
 * Digunakan oleh semua service untuk verifikasi token secara independen
 * Prinsip Zero Trust: setiap service verifikasi token sendiri, tidak percaya token yang sudah diverifikasi gateway
 */

const jwt = require('jsonwebtoken');
const path = require('path');

// Load dotenv dari root proyek
const rootDir = path.resolve(__dirname, '..');
require('dotenv').config({ path: path.join(rootDir, '.env') });

const ACCESS_SECRET = process.env.JWT_ACCESS_SECRET;
const REFRESH_SECRET = process.env.JWT_REFRESH_SECRET;
const SERVICE_SECRET = process.env.JWT_SERVICE_SECRET;
const ISSUER = process.env.JWT_ISSUER || 'zero-trust-sistem-nilai';
const AUDIENCE = process.env.JWT_AUDIENCE || 'zt-api';

/**
 * Verifikasi Access Token pengguna
 * @param {string} token - JWT access token
 * @returns {{ valid: boolean, payload: object|null, error: string|null }}
 */
function verifyAccessToken(token) {
  if (!token) {
    return { valid: false, payload: null, error: 'Token tidak disediakan' };
  }
  try {
    const payload = jwt.verify(token, ACCESS_SECRET, {
      issuer: ISSUER,
      audience: AUDIENCE,
      algorithms: ['HS256'],
    });
    // Pastikan token bukan service token yang salah digunakan
    if (payload.type === 'service') {
      return { valid: false, payload: null, error: 'Token service tidak dapat digunakan sebagai token pengguna' };
    }
    return { valid: true, payload, error: null };
  } catch (err) {
    return { valid: false, payload: null, error: mapJwtError(err) };
  }
}

/**
 * Verifikasi Refresh Token pengguna
 * @param {string} token - JWT refresh token
 * @returns {{ valid: boolean, payload: object|null, error: string|null }}
 */
function verifyRefreshToken(token) {
  if (!token) {
    return { valid: false, payload: null, error: 'Refresh token tidak disediakan' };
  }
  try {
    const payload = jwt.verify(token, REFRESH_SECRET, {
      issuer: ISSUER,
      audience: AUDIENCE,
      algorithms: ['HS256'],
    });
    return { valid: true, payload, error: null };
  } catch (err) {
    return { valid: false, payload: null, error: mapJwtError(err) };
  }
}

/**
 * Verifikasi Service Token (untuk komunikasi antar-service)
 * @param {string} token - JWT service token
 * @returns {{ valid: boolean, payload: object|null, error: string|null }}
 */
function verifyServiceToken(token) {
  if (!token) {
    return { valid: false, payload: null, error: 'Service token tidak disediakan' };
  }
  try {
    const payload = jwt.verify(token, SERVICE_SECRET, {
      issuer: ISSUER,
      audience: AUDIENCE,
      algorithms: ['HS256'],
    });
    // Wajib memiliki type=service dan role=service
    if (payload.type !== 'service' || payload.role !== 'service') {
      return { valid: false, payload: null, error: 'Token bukan service token yang valid' };
    }
    return { valid: true, payload, error: null };
  } catch (err) {
    return { valid: false, payload: null, error: mapJwtError(err) };
  }
}

/**
 * Generate Access Token
 * @param {object} user - Data pengguna { id, username, role }
 * @returns {string} JWT access token (berlaku 10 menit)
 */
function generateAccessToken(user) {
  return jwt.sign(
    {
      sub: user.id.toString(),
      username: user.username,
      role: user.role,
      type: 'access',
    },
    ACCESS_SECRET,
    {
      expiresIn: '10m',
      issuer: ISSUER,
      audience: AUDIENCE,
      algorithm: 'HS256',
    }
  );
}

/**
 * Generate Refresh Token
 * @param {object} user - Data pengguna { id, username, role }
 * @returns {string} JWT refresh token (berlaku 1 hari)
 */
function generateRefreshToken(user) {
  return jwt.sign(
    {
      sub: user.id.toString(),
      username: user.username,
      role: user.role,
      type: 'refresh',
    },
    REFRESH_SECRET,
    {
      expiresIn: '1d',
      issuer: ISSUER,
      audience: AUDIENCE,
      algorithm: 'HS256',
    }
  );
}

/**
 * Generate Service Token
 * @param {object} service - Data service { clientId, serviceName, scope }
 * @returns {string} JWT service token (berlaku 5 menit)
 */
function generateServiceToken(service) {
  return jwt.sign(
    {
      sub: service.clientId,
      service_name: service.serviceName,
      scope: service.scope || 'sync_transkrip',
      role: 'service',
      type: 'service',
    },
    SERVICE_SECRET,
    {
      expiresIn: '5m',
      issuer: ISSUER,
      audience: AUDIENCE,
      algorithm: 'HS256',
    }
  );
}

/**
 * Konversi error JWT ke pesan yang informatif namun tidak bocor
 */
function mapJwtError(err) {
  if (err.name === 'TokenExpiredError') return 'Token telah kedaluwarsa';
  if (err.name === 'JsonWebTokenError') return 'Token tidak valid';
  if (err.name === 'NotBeforeError') return 'Token belum aktif';
  return 'Verifikasi token gagal';
}

/**
 * Verifikasi Gateway Secret dengan perbandingan aman (constant-time-like)
 * @param {string} provided - Secret yang dikirim dalam header
 * @returns {boolean}
 */
function verifyGatewaySecret(provided) {
  const expected = process.env.GATEWAY_SECRET;
  if (!expected || !provided) return false;
  // Constant-time comparison untuk mencegah timing attack
  if (provided.length !== expected.length) return false;
  let mismatch = 0;
  for (let i = 0; i < expected.length; i++) {
    mismatch |= provided.charCodeAt(i) ^ expected.charCodeAt(i);
  }
  return mismatch === 0;
}

module.exports = {
  verifyAccessToken,
  verifyRefreshToken,
  verifyServiceToken,
  generateAccessToken,
  generateRefreshToken,
  generateServiceToken,
  verifyGatewaySecret,
};
