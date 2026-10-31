'use strict';

/**
 * Database Seed Script
 * Aman dijalankan ulang — akan menghapus data lama dan mengisi ulang
 * Gunakan: node database/seed.js (dari root proyek)
 */

const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '..', '.env') });

const bcrypt = require('bcryptjs');
const { getDatabase, runTransaction } = require('../shared/database');

const SALT_ROUNDS = 10;

const DEMO_USERS = [
  {
    username: 'admin01',
    password: 'Admin@Demo2024',
    role: 'admin',
    full_name: 'Administrator Sistem',
    device_id: 'device-admin-001',
    device_name: 'Admin Laptop',
  },
  {
    username: 'dosen01',
    password: 'Dosen@Demo2024',
    role: 'dosen',
    full_name: 'Dr. Budi Santoso, M.Kom.',
    nip: '198501012010011001',
    device_id: 'device-dosen-001',
    device_name: 'Dosen Laptop 1',
  },
  {
    username: 'dosen02',
    password: 'Dosen@Demo2024',
    role: 'dosen',
    full_name: 'Dr. Sari Dewi, M.T.',
    nip: '198701052012012002',
    device_id: 'device-dosen-002',
    device_name: 'Dosen Laptop 2',
  },
  {
    username: 'mhs001',
    password: 'Mahasiswa@Demo2024',
    role: 'mahasiswa',
    full_name: 'Ahmad Fauzi',
    nim: '207006001',
    angkatan: 2020,
    device_id: 'device-mhs-001',
    device_name: 'Mahasiswa HP 1',
  },
  {
    username: 'mhs002',
    password: 'Mahasiswa@Demo2024',
    role: 'mahasiswa',
    full_name: 'Dewi Anggraini',
    nim: '207006002',
    angkatan: 2020,
    device_id: 'device-mhs-002',
    device_name: 'Mahasiswa HP 2',
  },
  {
    username: 'mhs003',
    password: 'Mahasiswa@Demo2024',
    role: 'mahasiswa',
    full_name: 'Rizky Pratama',
    nim: '207006003',
    angkatan: 2020,
    device_id: 'device-mhs-003',
    device_name: 'Mahasiswa HP 3',
  },
];

function nilaiHuruf(angka) {
  if (angka >= 80) return 'A';
  if (angka >= 75) return 'AB';
  if (angka >= 70) return 'B';
  if (angka >= 65) return 'BC';
  if (angka >= 60) return 'C';
  if (angka >= 50) return 'D';
  return 'E';
}

async function seed() {
  const db = getDatabase();

  console.log('='.repeat(60));
  console.log('ZERO TRUST SISTEM NILAI — Database Seed');
  console.log('='.repeat(60));
  console.log('');

  runTransaction((db) => {
    // =============================================
    // BERSIHKAN DATA LAMA
    // =============================================
    console.log('Membersihkan data lama...');
    // Nonaktifkan FK sementara untuk clean-up
    db.exec('PRAGMA foreign_keys = OFF');
    db.exec(`
      DELETE FROM audit_log;
      DELETE FROM transkrip;
      DELETE FROM nilai;
      DELETE FROM enrollment;
      DELETE FROM kelas;
      DELETE FROM refresh_tokens;
      DELETE FROM registered_devices;
      DELETE FROM service_clients;
      DELETE FROM dosen;
      DELETE FROM mahasiswa;
      DELETE FROM users;
    `);
    // Reset autoincrement
    db.exec(`
      DELETE FROM sqlite_sequence WHERE name IN (
        'audit_log','transkrip','nilai','enrollment','kelas',
        'refresh_tokens','registered_devices','service_clients',
        'dosen','mahasiswa','users'
      );
    `);
    db.exec('PRAGMA foreign_keys = ON');

    // =============================================
    // USERS
    // =============================================
    console.log('Membuat pengguna...');
    const insertUser    = db.prepare('INSERT INTO users (username, password_hash, role, full_name) VALUES (?, ?, ?, ?)');
    const insertMhs     = db.prepare('INSERT INTO mahasiswa (user_id, nim, angkatan) VALUES (?, ?, ?)');
    const insertDosen   = db.prepare('INSERT INTO dosen (user_id, nip) VALUES (?, ?)');
    const insertDevice  = db.prepare('INSERT INTO registered_devices (user_id, device_id, device_name) VALUES (?, ?, ?)');

    const userIds = {};

    for (const u of DEMO_USERS) {
      const hash   = bcrypt.hashSync(u.password, SALT_ROUNDS);
      const result = insertUser.run(u.username, hash, u.role, u.full_name);
      const uid    = result.lastInsertRowid;
      userIds[u.username] = uid;

      if (u.role === 'mahasiswa') insertMhs.run(uid, u.nim, u.angkatan);
      if (u.role === 'dosen')     insertDosen.run(uid, u.nip);
      insertDevice.run(uid, u.device_id, u.device_name);
      console.log(`  ✓ ${u.username} (${u.role}) — device: ${u.device_id}`);
    }

    // =============================================
    // KELAS
    // =============================================
    console.log('\nMembuat kelas...');
    const dosen1 = db.prepare('SELECT d.id FROM dosen d JOIN users u ON u.id=d.user_id WHERE u.username=?').get('dosen01');
    const dosen2 = db.prepare('SELECT d.id FROM dosen d JOIN users u ON u.id=d.user_id WHERE u.username=?').get('dosen02');

    const insertKelas = db.prepare('INSERT INTO kelas (kode_kelas, nama_kelas, semester, tahun_akademik, dosen_id) VALUES (?, ?, ?, ?, ?)');
    const k1 = insertKelas.run('IF70065004', 'Keamanan Informasi', 'Ganjil', '2024/2025', dosen1.id);
    const k2 = insertKelas.run('IF60045001', 'Pemrograman Web Lanjut', 'Ganjil', '2024/2025', dosen2.id);
    console.log('  ✓ IF70065004 — Keamanan Informasi (dosen01)');
    console.log('  ✓ IF60045001 — Pemrograman Web Lanjut (dosen02)');

    // =============================================
    // ENROLLMENT
    // =============================================
    console.log('\nMendaftarkan mahasiswa ke kelas...');
    const getMhs = (uname) => db.prepare('SELECT m.id FROM mahasiswa m JOIN users u ON u.id=m.user_id WHERE u.username=?').get(uname);
    const mhs1 = getMhs('mhs001');
    const mhs2 = getMhs('mhs002');
    const mhs3 = getMhs('mhs003');

    const insertEnroll = db.prepare('INSERT INTO enrollment (kelas_id, mahasiswa_id) VALUES (?, ?)');
    const k1id = k1.lastInsertRowid;
    const k2id = k2.lastInsertRowid;

    const e1 = insertEnroll.run(k1id, mhs1.id);
    const e2 = insertEnroll.run(k1id, mhs2.id);
    const e3 = insertEnroll.run(k1id, mhs3.id);
    const e4 = insertEnroll.run(k2id, mhs1.id);
    const e5 = insertEnroll.run(k2id, mhs2.id);
    console.log('  ✓ mhs001, mhs002, mhs003 → Kelas 1 (Keamanan Informasi)');
    console.log('  ✓ mhs001, mhs002 → Kelas 2 (Pemrograman Web Lanjut)');

    // =============================================
    // NILAI
    // =============================================
    console.log('\nMembuat data nilai...');
    const insertNilai = db.prepare('INSERT INTO nilai (enrollment_id, nilai_angka, nilai_huruf, is_finalized) VALUES (?, ?, ?, 0)');

    // Kelas 1 — belum final (untuk test perubahan nilai)
    insertNilai.run(e1.lastInsertRowid, 85, nilaiHuruf(85));
    insertNilai.run(e2.lastInsertRowid, 75, nilaiHuruf(75));
    insertNilai.run(e3.lastInsertRowid, 65, nilaiHuruf(65));

    // Kelas 2 — akan difinalisasi (untuk test penolakan perubahan)
    const n4 = insertNilai.run(e4.lastInsertRowid, 90, nilaiHuruf(90));
    const n5 = insertNilai.run(e5.lastInsertRowid, 78, nilaiHuruf(78));

    // Finalisasi kelas 2
    db.prepare("UPDATE nilai SET is_finalized=1, finalized_at=datetime('now') WHERE id=?").run(n4.lastInsertRowid);
    db.prepare("UPDATE nilai SET is_finalized=1, finalized_at=datetime('now') WHERE id=?").run(n5.lastInsertRowid);

    console.log('  ✓ Kelas 1 (belum final): Ahmad=85(A), Dewi=75(AB), Rizky=65(BC)');
    console.log('  ✓ Kelas 2 (FINAL): Ahmad=90(A), Dewi=78(AB)');

    // =============================================
    // TRANSKRIP (dari kelas yang sudah final)
    // =============================================
    console.log('\nMembuat data transkrip awal...');
    const insertTranskrip = db.prepare(`
      INSERT OR REPLACE INTO transkrip (mahasiswa_id, kelas_id, nilai_angka, nilai_huruf, bobot_sks, semester, tahun_akademik)
      VALUES (?, ?, ?, ?, 3, ?, ?)
    `);
    insertTranskrip.run(mhs1.id, k2id, 90, 'A', 'Ganjil', '2024/2025');
    insertTranskrip.run(mhs2.id, k2id, 78, 'AB', 'Ganjil', '2024/2025');
    console.log('  ✓ Transkrip Ahmad: Pemrograman Web Lanjut = 90 (A)');
    console.log('  ✓ Transkrip Dewi: Pemrograman Web Lanjut = 78 (AB)');

    // =============================================
    // SERVICE CLIENT
    // =============================================
    console.log('\nMendaftarkan service client...');
    const clientSecret = process.env.SERVICE_NILAI_CLIENT_SECRET;
    const secretHash   = bcrypt.hashSync(clientSecret, SALT_ROUNDS);
    db.prepare('INSERT INTO service_clients (client_id, client_secret_hash, service_name, allowed_scopes) VALUES (?, ?, ?, ?)')
      .run(process.env.SERVICE_NILAI_CLIENT_ID || 'service-nilai', secretHash, 'Service Nilai', 'sync_transkrip');
    console.log(`  ✓ Service Client: ${process.env.SERVICE_NILAI_CLIENT_ID || 'service-nilai'}`);
  });

  // =============================================
  // RINGKASAN KREDENSIAL
  // =============================================
  console.log('\n' + '='.repeat(60));
  console.log('KREDENSIAL DEMO');
  console.log('='.repeat(60));
  console.log('PERHATIAN: Hanya untuk demo — JANGAN GUNAKAN DI PRODUKSI\n');

  const users = [
    { role: 'Admin',       username: 'admin01',  password: 'Admin@Demo2024',     device: 'device-admin-001' },
    { role: 'Dosen 1',     username: 'dosen01',  password: 'Dosen@Demo2024',     device: 'device-dosen-001' },
    { role: 'Dosen 2',     username: 'dosen02',  password: 'Dosen@Demo2024',     device: 'device-dosen-002' },
    { role: 'Mahasiswa 1', username: 'mhs001',   password: 'Mahasiswa@Demo2024', device: 'device-mhs-001', nim: '207006001' },
    { role: 'Mahasiswa 2', username: 'mhs002',   password: 'Mahasiswa@Demo2024', device: 'device-mhs-002', nim: '207006002' },
    { role: 'Mahasiswa 3', username: 'mhs003',   password: 'Mahasiswa@Demo2024', device: 'device-mhs-003', nim: '207006003' },
  ];

  users.forEach(u => {
    const nim = u.nim ? ` | NIM: ${u.nim}` : '';
    console.log(`${u.role.padEnd(14)} | ${u.username.padEnd(8)} | ${u.password.padEnd(22)} | ${u.device}${nim}`);
  });

  console.log('\nKelas:');
  console.log('  IF70065004 — Keamanan Informasi      (dosen01, belum final)');
  console.log('  IF60045001 — Pemrograman Web Lanjut  (dosen02, sudah final)');
  console.log('\nSeed selesai!');
  console.log('='.repeat(60));

  process.exit(0);
}

seed().catch(err => {
  console.error('Seed gagal:', err.message);
  process.exit(1);
});
