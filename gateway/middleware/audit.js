'use strict';

/**
 * Audit Log Middleware
 * Mencatat setiap keputusan akses ke database
 * Tidak mencatat password, secret, atau token mentah
 */

const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '..', '..', '.env') });

let _db = null;

function getDb() {
  if (!_db) {
    const { getDatabase } = require('../../shared/database');
    _db = getDatabase();
  }
  return _db;
}

/**
 * Tulis audit log ke database
 * @param {object} entry - Data audit log
 */
function writeAuditLog(entry) {
  const {
    subject,
    subjectRole = null,
    method,
    endpoint,
    deviceId = null,
    decision,
    reason,
    httpStatus = null,
    requestId = null,
    ipAddress = null,
  } = entry;

  // Validasi field wajib
  if (!subject || !method || !endpoint || !decision || !reason) {
    console.error('[AUDIT] Field wajib audit log tidak lengkap:', entry);
    // Jangan lempar error — pastikan kegagalan audit tidak mengubah keputusan keamanan
    return;
  }

  // Pastikan decision valid
  if (decision !== 'allow' && decision !== 'deny') {
    console.error('[AUDIT] Decision tidak valid:', decision);
    return;
  }

  try {
    const db = getDb();
    db.prepare(`
      INSERT INTO audit_log 
      (subject, subject_role, method, endpoint, device_id, decision, reason, http_status, request_id, ip_address)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      subject,
      subjectRole,
      method.toUpperCase(),
      endpoint,
      deviceId,
      decision,
      reason,
      httpStatus,
      requestId,
      ipAddress,
    );
  } catch (err) {
    // Kegagalan audit log harus dicatat tapi TIDAK boleh mengubah keputusan keamanan
    console.error('[AUDIT] Gagal menulis audit log:', err.message);
  }
}

/**
 * Express middleware untuk mencatat response
 */
function auditMiddleware(req, res, next) {
  // Simpan original end untuk intercept response
  const originalEnd = res.end.bind(res);
  
  res.end = function(chunk, encoding, callback) {
    // Audit log sudah ditulis di handler masing-masing
    // Middleware ini hanya sebagai fallback
    return originalEnd(chunk, encoding, callback);
  };
  
  next();
}

module.exports = { writeAuditLog, auditMiddleware };
