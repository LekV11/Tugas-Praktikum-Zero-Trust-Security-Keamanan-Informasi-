'use strict';

/**
 * Routes: Transkrip
 * Service Transkrip — mengelola transkrip akademik mahasiswa
 */

const express = require('express');
const router  = express.Router();
const path    = require('path');
require('dotenv').config({ path: path.join(__dirname, '..', '..', '.env') });

const { getDatabase, runTransaction } = require('../../shared/database');
const { verifyAccessToken, verifyServiceToken, verifyGatewaySecret } = require('../../shared/token-verification');

// =============================================
// Middleware: verifikasi gateway secret + user access token
// =============================================
function requireUserAuth(req, res, next) {
  // 1. Gateway secret
  if (!verifyGatewaySecret(req.headers['x-gateway-secret'])) {
    return res.status(403).json({ success: false, message: 'Request tidak diizinkan — gateway secret tidak valid' });
  }

  // 2. Access token pengguna
  const authHeader = req.headers['authorization'];
  if (!authHeader?.startsWith('Bearer ')) {
    return res.status(401).json({ success: false, message: 'Token akses tidak disediakan' });
  }

  const token  = authHeader.slice(7);
  const result = verifyAccessToken(token);

  if (!result.valid) {
    return res.status(401).json({ success: false, message: result.error || 'Token tidak valid' });
  }

  // Pastikan bukan service token
  if (result.payload.type === 'service') {
    return res.status(403).json({ success: false, message: 'Token service tidak dapat digunakan untuk endpoint ini' });
  }

  req.tokenPayload = result.payload;
  next();
}

// =============================================
// Middleware: verifikasi gateway secret + service token
// =============================================
function requireServiceAuth(req, res, next) {
  // 1. Gateway secret
  if (!verifyGatewaySecret(req.headers['x-gateway-secret'])) {
    return res.status(403).json({ success: false, message: 'Request tidak diizinkan — gateway secret tidak valid' });
  }

  // 2. Service token
  const authHeader = req.headers['authorization'];
  if (!authHeader?.startsWith('Bearer ')) {
    return res.status(401).json({ success: false, message: 'Token service tidak disediakan' });
  }

  const token  = authHeader.slice(7);
  const result = verifyServiceToken(token);

  if (!result.valid) {
    return res.status(401).json({ success: false, message: result.error || 'Token service tidak valid' });
  }

  // Verifikasi ini benar-benar service token (type=service, role=service)
  if (result.payload.type !== 'service' || result.payload.role !== 'service') {
    return res.status(403).json({ success: false, message: 'Hanya service token yang dapat mengakses endpoint ini' });
  }

  // Verifikasi berasal dari Service Nilai
  const expectedClientId = process.env.SERVICE_NILAI_CLIENT_ID || 'service-nilai';
  if (result.payload.sub !== expectedClientId) {
    return res.status(403).json({ success: false, message: 'Service token tidak berasal dari Service Nilai' });
  }

  req.tokenPayload = result.payload;
  next();
}

// =============================================
// GET /transkrip/:nim — Lihat transkrip mahasiswa
// =============================================
router.get('/:nim', requireUserAuth, (req, res) => {
  const db  = getDatabase();
  const nim = req.params.nim;
  const userId   = parseInt(req.tokenPayload.sub);
  const userRole = req.tokenPayload.role;

  try {
    if (userRole === 'mahasiswa') {
      // Verifikasi mahasiswa hanya dapat melihat transkrip sendiri
      const mhs = db.prepare('SELECT * FROM mahasiswa WHERE user_id = ?').get(userId);
      if (!mhs) return res.status(403).json({ success: false, message: 'Data mahasiswa tidak ditemukan' });
      if (mhs.nim !== nim) {
        return res.status(403).json({ success: false, message: 'Mahasiswa hanya dapat melihat transkrip miliknya sendiri' });
      }

      const transkrip = getTranskrip(db, mhs.id);
      return res.json({
        success: true,
        data: { nim, mahasiswa: mhs, transkrip, summary: calculateSummary(transkrip) },
      });
    }

    if (userRole === 'admin') {
      const mhs = db.prepare('SELECT * FROM mahasiswa WHERE nim = ?').get(nim);
      if (!mhs) return res.status(404).json({ success: false, message: 'Mahasiswa tidak ditemukan' });

      const transkrip = getTranskrip(db, mhs.id);
      const user = db.prepare('SELECT full_name FROM users WHERE id = ?').get(mhs.user_id);
      return res.json({
        success: true,
        data: { nim, mahasiswa: { ...mhs, full_name: user?.full_name }, transkrip, summary: calculateSummary(transkrip) },
      });
    }

    return res.status(403).json({ success: false, message: 'Role tidak diizinkan mengakses transkrip' });
  } catch (err) {
    console.error('[SERVICE TRANSKRIP] GET /transkrip/:nim error:', err);
    return res.status(500).json({ success: false, message: 'Terjadi kesalahan internal' });
  }
});

// =============================================
// POST /transkrip/sinkron — Sinkronisasi transkrip dari Service Nilai
// HANYA service token dari Service Nilai
// =============================================
router.post('/sinkron', requireServiceAuth, (req, res) => {
  const db = getDatabase();
  const { kelas_id } = req.body;

  if (!kelas_id || isNaN(parseInt(kelas_id))) {
    return res.status(400).json({ success: false, message: 'kelas_id wajib dan harus berupa angka' });
  }

  const kelasIdInt = parseInt(kelas_id);

  try {
    // Ambil data kelas
    const kelas = db.prepare('SELECT * FROM kelas WHERE id = ?').get(kelasIdInt);
    if (!kelas) {
      return res.status(404).json({ success: false, message: 'Kelas tidak ditemukan' });
    }

    // Ambil nilai final dari kelas ini
    const nilaiList = db.prepare(`
      SELECT 
        n.nilai_angka, n.nilai_huruf,
        e.mahasiswa_id,
        k.semester, k.tahun_akademik
      FROM nilai n
      JOIN enrollment e ON e.id = n.enrollment_id
      JOIN kelas k ON k.id = e.kelas_id
      WHERE e.kelas_id = ? AND n.is_finalized = 1
    `).all(kelasIdInt);

    if (nilaiList.length === 0) {
      return res.status(409).json({
        success: false,
        message: 'Tidak ada nilai final yang dapat disinkronisasi untuk kelas ini',
      });
    }

    // Sinkronisasi dalam transaksi untuk konsistensi
    const syncedCount = runTransaction((db) => {
      const upsert = db.prepare(`
        INSERT INTO transkrip (mahasiswa_id, kelas_id, nilai_angka, nilai_huruf, bobot_sks, semester, tahun_akademik, synced_at)
        VALUES (?, ?, ?, ?, 3, ?, ?, datetime('now'))
        ON CONFLICT(mahasiswa_id, kelas_id) DO UPDATE SET
          nilai_angka = excluded.nilai_angka,
          nilai_huruf = excluded.nilai_huruf,
          synced_at   = excluded.synced_at
      `);

      let count = 0;
      for (const n of nilaiList) {
        upsert.run(n.mahasiswa_id, kelasIdInt, n.nilai_angka, n.nilai_huruf, n.semester, n.tahun_akademik);
        count++;
      }
      return count;
    });

    console.log(`[SERVICE TRANSKRIP] Sinkronisasi berhasil: ${syncedCount} transkrip dari kelas ${kelasIdInt}`);

    return res.json({
      success: true,
      message: `Sinkronisasi berhasil`,
      data: {
        kelas_id:      kelasIdInt,
        kode_kelas:    kelas.kode_kelas,
        nama_kelas:    kelas.nama_kelas,
        synced_count:  syncedCount,
        synced_at:     new Date().toISOString(),
      },
    });
  } catch (err) {
    console.error('[SERVICE TRANSKRIP] POST /transkrip/sinkron error:', err);
    return res.status(500).json({ success: false, message: 'Terjadi kesalahan internal saat sinkronisasi' });
  }
});

// =============================================
// Helper: Ambil data transkrip mahasiswa
// =============================================
function getTranskrip(db, mahasiswaId) {
  return db.prepare(`
    SELECT 
      t.id, t.nilai_angka, t.nilai_huruf, t.bobot_sks, t.synced_at,
      k.kode_kelas, k.nama_kelas, k.semester, k.tahun_akademik,
      u.full_name as nama_dosen
    FROM transkrip t
    JOIN kelas k ON k.id = t.kelas_id
    JOIN dosen d ON d.id = k.dosen_id
    JOIN users u ON u.id = d.user_id
    WHERE t.mahasiswa_id = ?
    ORDER BY k.tahun_akademik DESC, k.semester DESC
  `).all(mahasiswaId);
}

// =============================================
// Helper: Hitung ringkasan transkrip (IP, SKS)
// =============================================
function calculateSummary(transkrip) {
  const nilaiBobot = { 'A': 4.0, 'AB': 3.5, 'B': 3.0, 'BC': 2.5, 'C': 2.0, 'D': 1.0, 'E': 0.0 };
  
  let totalSks   = 0;
  let totalBobot = 0;

  for (const t of transkrip) {
    const bobot = nilaiBobot[t.nilai_huruf] ?? 0;
    totalSks   += t.bobot_sks;
    totalBobot += bobot * t.bobot_sks;
  }

  const ipk = totalSks > 0 ? (totalBobot / totalSks).toFixed(2) : '0.00';

  return {
    total_sks:    totalSks,
    ipk:          parseFloat(ipk),
    total_matkul: transkrip.length,
  };
}

module.exports = router;
