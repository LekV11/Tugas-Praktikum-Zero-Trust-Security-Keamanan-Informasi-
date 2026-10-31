'use strict';

/**
 * Shared Database Module
 * Menggunakan node:sqlite built-in (Node.js 22+) — tidak perlu native addon
 * Semua service menggunakan file database yang sama via DB_PATH dari .env
 */

const path = require('path');
const fs   = require('fs');

// Load dotenv dari root proyek
const rootDir = path.resolve(__dirname, '..');
require('dotenv').config({ path: path.join(rootDir, '.env') });

const { DatabaseSync } = require('node:sqlite');

// Tentukan path database
const rawDbPath = process.env.DB_PATH || './database/zt_sistem_nilai.db';
const DB_PATH   = path.isAbsolute(rawDbPath)
  ? rawDbPath
  : path.resolve(rootDir, rawDbPath);

// Pastikan direktori database ada
const dbDir = path.dirname(DB_PATH);
if (!fs.existsSync(dbDir)) {
  fs.mkdirSync(dbDir, { recursive: true });
}

// Singleton connection
let db = null;

function getDatabase() {
  if (!db) {
    db = new DatabaseSync(DB_PATH);
    db.exec('PRAGMA foreign_keys = ON');
    db.exec('PRAGMA journal_mode = WAL');
    initializeSchema();
  }
  return db;
}

/**
 * Jalankan fungsi dalam transaksi database
 * node:sqlite tidak memiliki .transaction() helper, jadi dibuat manual
 * @param {function} fn - Fungsi yang akan dijalankan dalam transaksi
 * @returns {*} Hasil dari fungsi fn
 */
function runTransaction(fn) {
  const database = getDatabase();
  database.exec('BEGIN');
  try {
    const result = fn(database);
    database.exec('COMMIT');
    return result;
  } catch (err) {
    database.exec('ROLLBACK');
    throw err;
  }
}

function initializeSchema() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL CHECK(role IN ('admin', 'dosen', 'mahasiswa')),
      full_name TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      updated_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS mahasiswa (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL UNIQUE,
      nim TEXT NOT NULL UNIQUE,
      program_studi TEXT NOT NULL DEFAULT 'Informatika',
      angkatan INTEGER NOT NULL,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS dosen (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL UNIQUE,
      nip TEXT NOT NULL UNIQUE,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS registered_devices (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      device_id TEXT NOT NULL,
      device_name TEXT,
      registered_at TEXT NOT NULL DEFAULT (datetime('now')),
      UNIQUE(user_id, device_id),
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS kelas (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      kode_kelas TEXT NOT NULL UNIQUE,
      nama_kelas TEXT NOT NULL,
      semester TEXT NOT NULL,
      tahun_akademik TEXT NOT NULL,
      dosen_id INTEGER NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      FOREIGN KEY (dosen_id) REFERENCES dosen(id) ON DELETE RESTRICT
    );

    CREATE TABLE IF NOT EXISTS enrollment (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      kelas_id INTEGER NOT NULL,
      mahasiswa_id INTEGER NOT NULL,
      enrolled_at TEXT NOT NULL DEFAULT (datetime('now')),
      UNIQUE(kelas_id, mahasiswa_id),
      FOREIGN KEY (kelas_id) REFERENCES kelas(id) ON DELETE RESTRICT,
      FOREIGN KEY (mahasiswa_id) REFERENCES mahasiswa(id) ON DELETE RESTRICT
    );

    CREATE TABLE IF NOT EXISTS nilai (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      enrollment_id INTEGER NOT NULL UNIQUE,
      nilai_angka REAL CHECK(nilai_angka IS NULL OR (nilai_angka >= 0 AND nilai_angka <= 100)),
      nilai_huruf TEXT CHECK(nilai_huruf IS NULL OR nilai_huruf IN ('A', 'AB', 'B', 'BC', 'C', 'D', 'E')),
      is_finalized INTEGER NOT NULL DEFAULT 0 CHECK(is_finalized IN (0, 1)),
      finalized_at TEXT,
      updated_at TEXT NOT NULL DEFAULT (datetime('now')),
      updated_by INTEGER,
      FOREIGN KEY (enrollment_id) REFERENCES enrollment(id) ON DELETE RESTRICT,
      FOREIGN KEY (updated_by) REFERENCES users(id) ON DELETE SET NULL
    );

    CREATE TABLE IF NOT EXISTS transkrip (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      mahasiswa_id INTEGER NOT NULL,
      kelas_id INTEGER NOT NULL,
      nilai_angka REAL,
      nilai_huruf TEXT,
      bobot_sks INTEGER NOT NULL DEFAULT 3,
      semester TEXT NOT NULL,
      tahun_akademik TEXT NOT NULL,
      synced_at TEXT NOT NULL DEFAULT (datetime('now')),
      UNIQUE(mahasiswa_id, kelas_id),
      FOREIGN KEY (mahasiswa_id) REFERENCES mahasiswa(id) ON DELETE RESTRICT,
      FOREIGN KEY (kelas_id) REFERENCES kelas(id) ON DELETE RESTRICT
    );

    CREATE TABLE IF NOT EXISTS refresh_tokens (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      token_hash TEXT NOT NULL UNIQUE,
      expires_at TEXT NOT NULL,
      revoked INTEGER NOT NULL DEFAULT 0 CHECK(revoked IN (0, 1)),
      revoked_at TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS service_clients (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      client_id TEXT NOT NULL UNIQUE,
      client_secret_hash TEXT NOT NULL,
      service_name TEXT NOT NULL,
      allowed_scopes TEXT NOT NULL DEFAULT 'sync_transkrip',
      is_active INTEGER NOT NULL DEFAULT 1 CHECK(is_active IN (0, 1)),
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS audit_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      timestamp TEXT NOT NULL DEFAULT (datetime('now')),
      subject TEXT NOT NULL,
      subject_role TEXT,
      method TEXT NOT NULL,
      endpoint TEXT NOT NULL,
      device_id TEXT,
      decision TEXT NOT NULL CHECK(decision IN ('allow', 'deny')),
      reason TEXT NOT NULL,
      http_status INTEGER,
      request_id TEXT,
      ip_address TEXT
    );

    CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log(timestamp);
    CREATE INDEX IF NOT EXISTS idx_audit_log_subject   ON audit_log(subject);
    CREATE INDEX IF NOT EXISTS idx_audit_log_decision  ON audit_log(decision);
    CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user ON refresh_tokens(user_id);
    CREATE INDEX IF NOT EXISTS idx_refresh_tokens_hash ON refresh_tokens(token_hash);
    CREATE INDEX IF NOT EXISTS idx_nilai_enrollment    ON nilai(enrollment_id);
    CREATE INDEX IF NOT EXISTS idx_enrollment_kelas    ON enrollment(kelas_id);
    CREATE INDEX IF NOT EXISTS idx_enrollment_mhs      ON enrollment(mahasiswa_id);
    CREATE INDEX IF NOT EXISTS idx_transkrip_mhs       ON transkrip(mahasiswa_id);
  `);
}

module.exports = { getDatabase, runTransaction, DB_PATH };
