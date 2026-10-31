'use strict';

/**
 * Request Verification Middleware
 * Memverifikasi token dan device sebelum diteruskan ke Policy Engine
 */

const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '..', '..', '.env') });

const { verifyAccessToken, verifyServiceToken } = require('../../shared/token-verification');

/**
 * Ekstrak token dari Authorization header
 * @param {string} authHeader
 * @returns {string|null}
 */
function extractBearerToken(authHeader) {
  if (!authHeader || !authHeader.startsWith('Bearer ')) return null;
  const token = authHeader.slice(7).trim();
  return token || null;
}

/**
 * Middleware: verifikasi token untuk endpoint non-auth
 * Mendukung access token pengguna maupun service token
 */
function verifyToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = extractBearerToken(authHeader);

  if (!token) {
    req.tokenPayload = null;
    req.tokenError = 'Token tidak disediakan';
    return next();
  }

  // Coba verifikasi sebagai access token pengguna terlebih dahulu
  const accessResult = verifyAccessToken(token);
  if (accessResult.valid) {
    req.tokenPayload = accessResult.payload;
    req.rawToken = token;
    req.tokenError = null;
    return next();
  }

  // Coba verifikasi sebagai service token
  const serviceResult = verifyServiceToken(token);
  if (serviceResult.valid) {
    req.tokenPayload = serviceResult.payload;
    req.rawToken = token;
    req.tokenError = null;
    return next();
  }

  // Kedua verifikasi gagal — simpan error dari access token verification
  req.tokenPayload = null;
  req.rawToken = null;
  req.tokenError = accessResult.error || 'Token tidak valid';
  next();
}

module.exports = { verifyToken, extractBearerToken };
