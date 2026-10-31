'use strict';

/**
 * Routes: Nilai
 * Service Nilai — mengelola data nilai mahasiswa
 */

const express = require('express');
const router = express.Router();
const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '..', '..', '.env') });

const { getDatabase } = require('../../shared/database');
const { verifyAccessToken } = require('../../shared/token-verification');
const { verifyGatewaySecret } = require('../../shared/token-verification');

/**
 * Middleware: verifikasi gateway secret dan access token
 * Prinsip Zero Trust: service tetap verifikasi sendiri, tidak percaya gateway saja
 */
function requireAuth(req, res, next) {
  // 1. Verifikasi gateway secret
  const gatewaySecret = req.headers['x-gateway-secret'];
  if (!verifyGatewaySecret(gatewaySecret)) {
    return res.status(403).json({
      success: false,
      message: 'Request tidak diizinkan — gateway secret tidak valid',
    });
  }

  // 2. Verifikasi access token
  const authHeader = req.headers['authorization'];
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({
      success: false,
      message: 'Token akses tidak disediakan',
    });
  }

  const token = authHeader.slice(7);
  const result = verifyAccessToken(token);

  if (!result.valid) {
    return res.status(401).json({
      success: false,
      message: result.error || 'Token tidak valid',
    });
  }

  req.tokenPayload = result.payload;
  next();
}

// =============================================
// GET /nilai — Lihat daftar nilai
// =============================================
router.get('/', requireAuth, (req, res) => {
  const db = getDatabase();
  const { role } = req.tokenPayload;
  const userId = parseInt(req.tokenPayload.sub);

  try {
    if (role === 'mahasiswa') {
      // Mahasiswa hanya lihat nilai sendiri
      const mhs = db.prepare('SELECT * FROM mahasiswa WHERE user_id = ?').get(userId);
      if (!mhs) {
        return res.status(403).json({ success: false, message: 'Data mahasiswa tidak ditemukan' });
      }

      const nilai = db.prepare(`
        SELECT 
          n.id, n.nilai_angka, n.nilai_huruf, n.is_finalized, n.updated_at,
          k.kode_kelas, k.nama_kelas, k.semester, k.tahun_akademik,
          m.nim
        FROM nilai n
        JOIN enrollment e ON e.id = n.enrollment_id
        JOIN kelas k ON k.id = e.kelas_id
        JOIN mahasiswa m ON m.id = e.mahasiswa_id
        WHERE e.mahasiswa_id = ?
        ORDER BY k.tahun_akademik DESC, k.semester DESC
      `).all(mhs.id);

      return res.json({
        success: true,
        data: { nilai },
      });
    }

    if (role === 'dosen') {
      // Dosen hanya lihat nilai kelas yang diampunya
      const dosen = db.prepare('SELECT * FROM dosen WHERE user_id = ?').get(userId);
      if (!dosen) {
        return res.status(403).json({ success: false, message: 'Data dosen tidak ditemukan' });
      }

      // Query parameter opsional: filter per kelas
      const { kelas_id } = req.query;
      
      let query = `
        SELECT 
          n.id, n.nilai_angka, n.nilai_huruf, n.is_finalized, n.updated_at,
          k.id as kelas_id, k.kode_kelas, k.nama_kelas, k.semester, k.tahun_akademik,
          m.nim, u.full_name as nama_mahasiswa
        FROM nilai n
        JOIN enrollment e ON e.id = n.enrollment_id
        JOIN kelas k ON k.id = e.kelas_id
        JOIN mahasiswa m ON m.id = e.mahasiswa_id
        JOIN users u ON u.id = m.user_id
        WHERE k.dosen_id = ?
      `;
      const params = [dosen.id];

      if (kelas_id) {
        query += ' AND k.id = ?';
        params.push(parseInt(kelas_id));
      }

      query += ' ORDER BY k.kode_kelas, m.nim';

      const nilai = db.prepare(query).all(...params);

      return res.json({
        success: true,
        data: { nilai },
      });
    }

    return res.status(403).json({
      success: false,
      message: 'Role tidak diizinkan',
    });
  } catch (err) {
    console.error('[SERVICE NILAI] GET /nilai error:', err);
    return res.status(500).json({ success: false, message: 'Terjadi kesalahan internal' });
  }
});

// =============================================
// PUT /nilai/:id — Ubah nilai
// =============================================
router.put('/:id', requireAuth, (req, res) => {
  const db = getDatabase();
  const { role } = req.tokenPayload;
  const userId = parseInt(req.tokenPayload.sub);
  const nilaiId = parseInt(req.params.id);

  if (role !== 'dosen') {
    return res.status(403).json({ success: false, message: 'Hanya dosen yang dapat mengubah nilai' });
  }

  if (isNaN(nilaiId)) {
    return res.status(400).json({ success: false, message: 'ID nilai tidak valid' });
  }

  const { nilai_angka } = req.body;

  if (nilai_angka === undefined || nilai_angka === null) {
    return res.status(400).json({ success: false, message: 'nilai_angka wajib disediakan' });
  }

  const nilaiNum = parseFloat(nilai_angka);
  if (isNaN(nilaiNum) || nilaiNum < 0 || nilaiNum > 100) {
    return res.status(400).json({ success: false, message: 'nilai_angka harus berupa angka antara 0 dan 100' });
  }

  try {
    // Verifikasi kepemilikan secara langsung di service (tidak hanya percaya gateway)
    const dosen = db.prepare('SELECT * FROM dosen WHERE user_id = ?').get(userId);
    if (!dosen) {
      return res.status(403).json({ success: false, message: 'Data dosen tidak ditemukan' });
    }

    const nilaiData = db.prepare(`
      SELECT n.*, e.kelas_id, k.dosen_id
      FROM nilai n
      JOIN enrollment e ON e.id = n.enrollment_id
      JOIN kelas k ON k.id = e.kelas_id
      WHERE n.id = ?
    `).get(nilaiId);

    if (!nilaiData) {
      return res.status(404).json({ success: false, message: 'Data nilai tidak ditemukan' });
    }

    if (nilaiData.is_finalized) {
      return res.status(409).json({ success: false, message: 'Nilai sudah difinalisasi, tidak dapat diubah' });
    }

    if (nilaiData.dosen_id !== dosen.id) {
      return res.status(403).json({ success: false, message: 'Dosen tidak mengampu kelas terkait nilai ini' });
    }

    // Konversi nilai angka ke huruf
    const nilaiHuruf = angkaKeHuruf(nilaiNum);

    // Update nilai
    db.prepare(`
      UPDATE nilai 
      SET nilai_angka = ?, nilai_huruf = ?, updated_at = datetime('now'), updated_by = ?
      WHERE id = ?
    `).run(nilaiNum, nilaiHuruf, userId, nilaiId);

    const updated = db.prepare(`
      SELECT n.*, k.kode_kelas, k.nama_kelas
      FROM nilai n
      JOIN enrollment e ON e.id = n.enrollment_id
      JOIN kelas k ON k.id = e.kelas_id
      WHERE n.id = ?
    `).get(nilaiId);

    return res.json({
      success: true,
      message: 'Nilai berhasil diperbarui',
      data: { nilai: updated },
    });
  } catch (err) {
    console.error('[SERVICE NILAI] PUT /nilai/:id error:', err);
    return res.status(500).json({ success: false, message: 'Terjadi kesalahan internal' });
  }
});

function angkaKeHuruf(angka) {
  if (angka >= 80) return 'A';
  if (angka >= 75) return 'AB';
  if (angka >= 70) return 'B';
  if (angka >= 65) return 'BC';
  if (angka >= 60) return 'C';
  if (angka >= 50) return 'D';
  return 'E';
}

module.exports = router;
