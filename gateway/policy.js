'use strict';

/**
 * Policy Engine & Policy Administrator
 * Mengimplementasikan aturan Zero Trust: default-deny, least privilege
 * Semua keputusan akses dibuat di sini berdasarkan atribut dari database
 */

const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '..', '.env') });

const { getDatabase } = require('../shared/database');

// =============================================
// KONFIGURASI JAM AKSES
// =============================================
const ACCESS_TIME_START = process.env.ACCESS_TIME_START || '07:00';
const ACCESS_TIME_END   = process.env.ACCESS_TIME_END   || '21:00';
const TIMEZONE          = process.env.TIMEZONE          || 'Asia/Jakarta';

/**
 * Periksa apakah waktu saat ini berada dalam rentang jam akses
 * @returns {{ allowed: boolean, currentTime: string, message: string }}
 */
function checkAccessTime() {
  // Gunakan jam server dengan zona waktu yang dikonfigurasi
  const now = new Date();
  const formatter = new Intl.DateTimeFormat('id-ID', {
    timeZone: TIMEZONE,
    hour: '2-digit',
    minute: '2-digit',
    hour12: false,
  });
  
  const parts = formatter.formatToParts(now);
  const hour   = parts.find(p => p.type === 'hour').value;
  const minute = parts.find(p => p.type === 'minute').value;
  const currentTime = `${hour}:${minute}`;
  
  const [startH, startM] = ACCESS_TIME_START.split(':').map(Number);
  const [endH,   endM]   = ACCESS_TIME_END.split(':').map(Number);
  const [curH,   curM]   = [parseInt(hour), parseInt(minute)];
  
  const currentMinutes = curH * 60 + curM;
  const startMinutes   = startH * 60 + startM;
  const endMinutes     = endH * 60 + endM;
  
  const allowed = currentMinutes >= startMinutes && currentMinutes <= endMinutes;
  
  return {
    allowed,
    currentTime,
    message: allowed
      ? `Akses diizinkan (${currentTime} WIB)`
      : `Akses ditolak — di luar jam akses (${currentTime} WIB, jam akses: ${ACCESS_TIME_START}–${ACCESS_TIME_END} WIB)`,
  };
}

// =============================================
// FUNGSI QUERY DATABASE (Policy Information Point)
// =============================================

function getUserById(userId) {
  const db = getDatabase();
  return db.prepare('SELECT id, username, role, full_name FROM users WHERE id = ?').get(userId);
}

function getMahasiswaByUserId(userId) {
  const db = getDatabase();
  return db.prepare('SELECT * FROM mahasiswa WHERE user_id = ?').get(userId);
}

function getDosenByUserId(userId) {
  const db = getDatabase();
  return db.prepare('SELECT * FROM dosen WHERE user_id = ?').get(userId);
}

function isDeviceRegisteredForUser(userId, deviceId) {
  const db = getDatabase();
  const device = db.prepare(
    'SELECT id FROM registered_devices WHERE user_id = ? AND device_id = ?'
  ).get(userId, deviceId);
  return !!device;
}

function getDosenKelas(dosenId, kelasId) {
  const db = getDatabase();
  return db.prepare('SELECT * FROM kelas WHERE id = ? AND dosen_id = ?').get(kelasId, dosenId);
}

function getNilaiById(nilaiId) {
  const db = getDatabase();
  return db.prepare(`
    SELECT n.*, e.kelas_id, e.mahasiswa_id, k.dosen_id
    FROM nilai n
    JOIN enrollment e ON e.id = n.enrollment_id
    JOIN kelas k ON k.id = e.kelas_id
    WHERE n.id = ?
  `).get(nilaiId);
}

function getMahasiswaByNim(nim) {
  const db = getDatabase();
  return db.prepare('SELECT * FROM mahasiswa WHERE nim = ?').get(nim);
}

function isKelasFinalized(kelasId) {
  const db = getDatabase();
  // Kelas dianggap sudah final jika semua nilai dalam kelas tersebut sudah final
  const result = db.prepare(`
    SELECT COUNT(*) as total, SUM(CASE WHEN n.is_finalized = 1 THEN 1 ELSE 0 END) as finalized
    FROM enrollment e
    LEFT JOIN nilai n ON n.enrollment_id = e.id
    WHERE e.kelas_id = ?
  `).get(kelasId);
  return result && result.total > 0 && result.total === result.finalized;
}

// =============================================
// POLICY DECISIONS
// =============================================

/**
 * Evaluasi kebijakan akses untuk request tertentu
 * @param {object} context - Konteks request
 * @returns {{ decision: 'allow'|'deny', reason: string, httpStatus: number, data: object }}
 */
function evaluate(context) {
  const { method, path: reqPath, tokenPayload, deviceId, params, body } = context;

  // =============================================
  // A. POST /auth/* — Endpoint autentikasi (ditangani langsung di auth.js)
  // =============================================
  if (reqPath.startsWith('/auth/')) {
    return allow('Endpoint autentikasi — diizinkan');
  }

  // =============================================
  // Untuk endpoint non-auth: wajib ada tokenPayload dan deviceId
  // =============================================
  if (!tokenPayload) {
    return deny('Token akses tidak valid atau tidak ada', 401);
  }

  // =============================================
  // H. POST /transkrip/sinkron — Service token path (cek lebih awal)
  // =============================================
  if (method === 'POST' && reqPath === '/transkrip/sinkron') {
    if (tokenPayload.type !== 'service' || tokenPayload.role !== 'service') {
      return deny('Endpoint sinkronisasi hanya dapat diakses oleh service token', 403);
    }
    
    if (tokenPayload.sub !== (process.env.SERVICE_NILAI_CLIENT_ID || 'service-nilai')) {
      return deny('Service token tidak berasal dari Service Nilai', 403);
    }
    
    return allow('Service Nilai diizinkan melakukan sinkronisasi transkrip');
  }

  // =============================================
  // Untuk service token yang bukan endpoint sinkronisasi — tolak
  // =============================================
  if (tokenPayload.type === 'service') {
    return deny('Service token hanya dapat digunakan untuk endpoint sinkronisasi', 403);
  }

  const userId = parseInt(tokenPayload.sub);
  const userRole = tokenPayload.role;

  // Verifikasi user masih ada di database (tidak trust hanya dari token)
  const dbUser = getUserById(userId);
  if (!dbUser) {
    return deny('Pengguna tidak ditemukan di database', 401);
  }

  // Pastikan role di token sama dengan role di database
  if (dbUser.role !== userRole) {
    return deny('Ketidakcocokan role antara token dan database', 403);
  }

  // =============================================
  // Verifikasi device (untuk token pengguna)
  // =============================================
  if (!deviceId) {
    return deny('Header X-Device-ID tidak disediakan', 401);
  }
  if (!isDeviceRegisteredForUser(userId, deviceId)) {
    return deny(`Device '${deviceId}' tidak terdaftar untuk pengguna ini`, 403);
  }
  // =============================================
  // D. GET /nilai — Lihat nilai
  // =============================================
  if (method === 'GET' && reqPath === '/nilai') {
    if (userRole === 'mahasiswa') {
      const mhs = getMahasiswaByUserId(userId);
      if (!mhs) return deny('Data mahasiswa tidak ditemukan', 403);
      return allow('Mahasiswa diizinkan melihat nilai sendiri', { mahasiswaId: mhs.id, nim: mhs.nim });
    }
    if (userRole === 'dosen') {
      const dosen = getDosenByUserId(userId);
      if (!dosen) return deny('Data dosen tidak ditemukan', 403);
      return allow('Dosen diizinkan melihat nilai kelas yang diampu', { dosenId: dosen.id });
    }
    return deny('Role tidak diizinkan mengakses nilai', 403);
  }

  // =============================================
  // E. PUT /nilai/:id — Ubah nilai
  // =============================================
  if (method === 'PUT' && reqPath.startsWith('/nilai/')) {
    if (userRole !== 'dosen') {
      return deny('Hanya dosen yang dapat mengubah nilai', 403);
    }
    
    const timeCheck = checkAccessTime();
    if (!timeCheck.allowed) {
      return deny(timeCheck.message, 403);
    }
    
    // Ambil ID dari path langsung — params belum tersedia di level gateway middleware
    const nilaiId = reqPath.split('/')[2];
    if (!nilaiId || isNaN(parseInt(nilaiId))) return deny('ID nilai tidak valid', 400);
    
    const nilaiData = getNilaiById(parseInt(nilaiId));
    if (!nilaiData) return deny('Data nilai tidak ditemukan', 404);
    
    // Cek kepemilikan DULU sebelum cek finalisasi
    // Agar dosen yang salah kelas mendapat 403, bukan 409
    const dosen = getDosenByUserId(userId);
    if (!dosen) return deny('Data dosen tidak ditemukan', 403);
    
    if (nilaiData.dosen_id !== dosen.id) {
      return deny('Dosen tidak mengampu kelas terkait nilai ini', 403);
    }
    
    if (nilaiData.is_finalized) {
      return deny('Nilai sudah difinalisasi, tidak dapat diubah', 409);
    }
    
    return allow('Dosen diizinkan mengubah nilai', { dosenId: dosen.id, nilaiId: parseInt(nilaiId) });
  }

  // =============================================
  // D2. GET /kelas — Daftar kelas yang diampu dosen
  // =============================================
  if (method === 'GET' && reqPath === '/kelas') {
    if (userRole !== 'dosen') {
      return deny('Hanya dosen yang dapat mengakses daftar kelas', 403);
    }
    const dosen = getDosenByUserId(userId);
    if (!dosen) return deny('Data dosen tidak ditemukan', 403);
    return allow('Dosen diizinkan melihat daftar kelas yang diampu', { dosenId: dosen.id });
  }

  // =============================================
  // F. POST /kelas/:id/finalisasi
  // =============================================
  if (method === 'POST' && reqPath.match(/^\/kelas\/\d+\/finalisasi$/)) {
    if (userRole !== 'dosen') {
      return deny('Hanya dosen yang dapat memfinalisasi kelas', 403);
    }
    
    const timeCheck = checkAccessTime();
    if (!timeCheck.allowed) {
      return deny(timeCheck.message, 403);
    }
    
    // Ambil kelasId dari path langsung
    const kelasId = parseInt(reqPath.split('/')[2]);
    const dosen = getDosenByUserId(userId);
    if (!dosen) return deny('Data dosen tidak ditemukan', 403);
    
    const kelas = getDosenKelas(dosen.id, kelasId);
    if (!kelas) {
      return deny('Dosen tidak mengampu kelas ini atau kelas tidak ditemukan', 403);
    }
    
    return allow('Dosen diizinkan memfinalisasi kelas', { dosenId: dosen.id, kelasId });
  }

  // =============================================
  // G. GET /transkrip/:nim
  // =============================================
  if (method === 'GET' && reqPath.startsWith('/transkrip/') && !reqPath.endsWith('/sinkron')) {
    const requestedNim = reqPath.split('/')[2];
    
    if (userRole === 'mahasiswa') {
      const mhs = getMahasiswaByUserId(userId);
      if (!mhs) return deny('Data mahasiswa tidak ditemukan', 403);
      if (mhs.nim !== requestedNim) {
        return deny('Mahasiswa hanya dapat melihat transkrip miliknya sendiri', 403);
      }
      return allow('Mahasiswa diizinkan melihat transkrip sendiri', { mahasiswaId: mhs.id, nim: mhs.nim });
    }
    
    if (userRole === 'admin') {
      // Verifikasi NIM yang diminta ada di database
      const targetMhs = getMahasiswaByNim(requestedNim);
      if (!targetMhs) return deny('Mahasiswa dengan NIM tersebut tidak ditemukan', 404);
      return allow('Admin diizinkan melihat transkrip semua mahasiswa', { mahasiswaId: targetMhs.id, nim: requestedNim });
    }
    
    return deny('Role tidak diizinkan mengakses transkrip', 403);
  }

  // =============================================
  // DEFAULT: DENY
  // =============================================
  return deny('Endpoint tidak diizinkan atau tidak ditemukan', 404);
}

// =============================================
// HELPER FUNCTIONS
// =============================================
function allow(reason, data = {}) {
  return { decision: 'allow', reason, httpStatus: 200, data };
}

function deny(reason, httpStatus = 403) {
  return { decision: 'deny', reason, httpStatus, data: {} };
}

module.exports = {
  evaluate,
  checkAccessTime,
  isDeviceRegisteredForUser,
  getDosenByUserId,
  getMahasiswaByUserId,
};
