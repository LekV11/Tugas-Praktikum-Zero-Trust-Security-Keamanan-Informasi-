'use strict';

/**
 * Routes: Kelas
 * Service Nilai — mengelola kelas dan finalisasi nilai
 */

const express = require('express');
const router = express.Router();
const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '..', '..', '.env') });

const { getDatabase, runTransaction } = require('../../shared/database');
const { verifyAccessToken, verifyGatewaySecret } = require('../../shared/token-verification');

const GATEWAY_PORT = process.env.GATEWAY_PORT || 3000;

/**
 * Middleware: verifikasi gateway secret dan access token
 */
function requireAuth(req, res, next) {
  const gatewaySecret = req.headers['x-gateway-secret'];
  if (!verifyGatewaySecret(gatewaySecret)) {
    return res.status(403).json({
      success: false,
      message: 'Request tidak diizinkan — gateway secret tidak valid',
    });
  }

  const authHeader = req.headers['authorization'];
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ success: false, message: 'Token akses tidak disediakan' });
  }

  const token = authHeader.slice(7);
  const result = verifyAccessToken(token);

  if (!result.valid) {
    return res.status(401).json({ success: false, message: result.error || 'Token tidak valid' });
  }

  req.tokenPayload = result.payload;
  next();
}

// =============================================
// POST /kelas/:id/finalisasi
// =============================================
router.post('/:id/finalisasi', requireAuth, async (req, res) => {
  const db = getDatabase();
  const kelasId = parseInt(req.params.id);
  const userId  = parseInt(req.tokenPayload.sub);
  const { role } = req.tokenPayload;

  if (role !== 'dosen') {
    return res.status(403).json({ success: false, message: 'Hanya dosen yang dapat memfinalisasi kelas' });
  }

  if (isNaN(kelasId)) {
    return res.status(400).json({ success: false, message: 'ID kelas tidak valid' });
  }

  try {
    // Verifikasi dosen mengampu kelas ini
    const dosen = db.prepare('SELECT * FROM dosen WHERE user_id = ?').get(userId);
    if (!dosen) {
      return res.status(403).json({ success: false, message: 'Data dosen tidak ditemukan' });
    }

    const kelas = db.prepare('SELECT * FROM kelas WHERE id = ? AND dosen_id = ?').get(kelasId, dosen.id);
    if (!kelas) {
      return res.status(403).json({ success: false, message: 'Dosen tidak mengampu kelas ini atau kelas tidak ditemukan' });
    }

    // Periksa apakah sudah ada nilai yang belum diisi (null)
    const nilaiKosong = db.prepare(`
      SELECT COUNT(*) as count FROM enrollment e
      LEFT JOIN nilai n ON n.enrollment_id = e.id
      WHERE e.kelas_id = ? AND (n.nilai_angka IS NULL OR n.id IS NULL)
    `).get(kelasId);

    if (nilaiKosong && nilaiKosong.count > 0) {
      return res.status(409).json({
        success: false,
        message: `Tidak dapat memfinalisasi — masih ada ${nilaiKosong.count} nilai yang belum diisi`,
      });
    }

    // Periksa apakah sudah ada yang difinalisasi
    const alreadyFinalized = db.prepare(`
      SELECT COUNT(*) as count FROM nilai n
      JOIN enrollment e ON e.id = n.enrollment_id
      WHERE e.kelas_id = ? AND n.is_finalized = 1
    `).get(kelasId);

    if (alreadyFinalized && alreadyFinalized.count > 0) {
      return res.status(409).json({
        success: false,
        message: 'Beberapa atau semua nilai di kelas ini sudah difinalisasi',
      });
    }

    // Finalisasi semua nilai dalam kelas — gunakan transaksi
    runTransaction((db) => {
      db.prepare(`
        UPDATE nilai SET is_finalized = 1, finalized_at = datetime('now')
        WHERE enrollment_id IN (
          SELECT id FROM enrollment WHERE kelas_id = ?
        )
      `).run(kelasId);
    });

    console.log(`[SERVICE NILAI] Kelas ${kelasId} berhasil difinalisasi oleh dosen ${userId}`);

    // Kirim response sukses DULU, baru jalankan sinkronisasi di background
    // Ini mencegah deadlock: gateway menunggu Service Nilai yang sedang menunggu gateway
    res.json({
      success: true,
      message: 'Kelas berhasil difinalisasi',
      data: {
        kelas_id:     kelasId,
        kode_kelas:   kelas.kode_kelas,
        nama_kelas:   kelas.nama_kelas,
        finalized_at: new Date().toISOString(),
        sync_transkrip: { status: 'pending', message: 'Sinkronisasi transkrip sedang diproses di background' },
      },
    });

    // Sinkronisasi berjalan setelah response dikirim (non-blocking)
    syncTranskrip(kelasId).then(result => {
      console.log(`[SERVICE NILAI] Sinkronisasi kelas ${kelasId}: ${result.message}`);
    }).catch(err => {
      console.error(`[SERVICE NILAI] Sinkronisasi kelas ${kelasId} gagal:`, err.message);
    });
  } catch (err) {
    console.error('[SERVICE NILAI] POST /kelas/:id/finalisasi error:', err);
    return res.status(500).json({ success: false, message: 'Terjadi kesalahan internal saat finalisasi' });
  }
});

// =============================================
// GET /kelas — Daftar kelas (untuk referensi)
// =============================================
router.get('/', requireAuth, (req, res) => {
  const db = getDatabase();
  const userId = parseInt(req.tokenPayload.sub);
  const { role } = req.tokenPayload;

  try {
    if (role === 'dosen') {
      const dosen = db.prepare('SELECT * FROM dosen WHERE user_id = ?').get(userId);
      if (!dosen) return res.status(403).json({ success: false, message: 'Data dosen tidak ditemukan' });

      const kelas = db.prepare(`
        SELECT k.*, 
          COUNT(DISTINCT e.id) as jumlah_mahasiswa,
          SUM(CASE WHEN n.is_finalized = 1 THEN 1 ELSE 0 END) as jumlah_final
        FROM kelas k
        LEFT JOIN enrollment e ON e.kelas_id = k.id
        LEFT JOIN nilai n ON n.enrollment_id = e.id
        WHERE k.dosen_id = ?
        GROUP BY k.id
        ORDER BY k.tahun_akademik DESC
      `).all(dosen.id);

      return res.json({ success: true, data: { kelas } });
    }

    return res.status(403).json({ success: false, message: 'Role tidak diizinkan' });
  } catch (err) {
    console.error('[SERVICE NILAI] GET /kelas error:', err);
    return res.status(500).json({ success: false, message: 'Terjadi kesalahan internal' });
  }
});

// =============================================
// Fungsi: Minta sinkronisasi transkrip melalui gateway
// Alur: Service Nilai → Gateway → Service Transkrip
// =============================================
async function syncTranskrip(kelasId) {
  const gatewayUrl = `http://localhost:${GATEWAY_PORT}`;
  
  try {
    // Langkah 1: Dapatkan service token dari gateway
    console.log('[SERVICE NILAI] Meminta service token dari gateway...');
    
    const tokenResponse = await fetch(`${gatewayUrl}/auth/service`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        client_id:     process.env.SERVICE_NILAI_CLIENT_ID,
        client_secret: process.env.SERVICE_NILAI_CLIENT_SECRET,
      }),
    });

    if (!tokenResponse.ok) {
      const err = await tokenResponse.json().catch(() => ({}));
      console.error('[SERVICE NILAI] Gagal mendapatkan service token:', err);
      return { success: false, message: 'Gagal mendapatkan service token untuk sinkronisasi' };
    }

    const tokenData = await tokenResponse.json();
    const serviceToken = tokenData.data?.access_token;

    if (!serviceToken) {
      return { success: false, message: 'Service token tidak diterima' };
    }

    // Langkah 2: Kirim request sinkronisasi ke gateway
    console.log(`[SERVICE NILAI] Meminta sinkronisasi transkrip kelas ${kelasId}...`);
    
    const syncResponse = await fetch(`${gatewayUrl}/transkrip/sinkron`, {
      method: 'POST',
      headers: {
        'Content-Type':  'application/json',
        'Authorization': `Bearer ${serviceToken}`,
      },
      body: JSON.stringify({ kelas_id: kelasId }),
    });

    const syncData = await syncResponse.json().catch(() => ({ success: false }));

    if (!syncResponse.ok) {
      console.error('[SERVICE NILAI] Sinkronisasi transkrip gagal:', syncData);
      // Finalisasi tetap berhasil; catat kegagalan sinkronisasi
      return {
        success: false,
        message: syncData.message || 'Sinkronisasi transkrip gagal',
        note: 'Finalisasi berhasil. Sinkronisasi transkrip dapat dicoba ulang secara manual.',
      };
    }

    console.log(`[SERVICE NILAI] Sinkronisasi transkrip kelas ${kelasId} berhasil`);
    return {
      success: true,
      message: 'Sinkronisasi transkrip berhasil',
      data: syncData.data,
    };
  } catch (err) {
    console.error('[SERVICE NILAI] Error saat sinkronisasi transkrip:', err.message);
    return {
      success: false,
      message: `Sinkronisasi transkrip gagal: ${err.message}`,
      note: 'Finalisasi berhasil. Sinkronisasi transkrip dapat dicoba ulang secara manual.',
    };
  }
}

module.exports = router;
