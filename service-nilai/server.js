'use strict';

/**
 * Service Nilai — Zero Trust Sistem Nilai
 * Port: 3001
 * 
 * Mengelola data nilai dan kelas.
 * Setiap request diverifikasi secara independen (Zero Trust).
 * Hanya menerima request yang melewati API Gateway (verifikasi gateway secret).
 */

const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '..', '.env') });

// Validasi konfigurasi kritis
const REQUIRED_ENV = ['JWT_ACCESS_SECRET', 'GATEWAY_SECRET'];
for (const key of REQUIRED_ENV) {
  if (!process.env[key]) {
    console.error(`[SERVICE NILAI STARTUP ERROR] Variabel lingkungan wajib tidak ditemukan: ${key}`);
    process.exit(1);
  }
}

const express = require('express');
const nilaiRouter = require('./routes/nilai');
const kelasRouter = require('./routes/kelas');

const app = express();
const PORT = parseInt(process.env.SERVICE_NILAI_PORT) || 3001;

// =============================================
// MIDDLEWARE GLOBAL
// =============================================
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// Log setiap request (tanpa data sensitif)
app.use((req, res, next) => {
  console.log(`[SERVICE NILAI] ${req.method} ${req.path} — ${new Date().toISOString()}`);
  next();
});

// =============================================
// ROUTES
// =============================================
app.use('/nilai', nilaiRouter);
app.use('/kelas', kelasRouter);

// =============================================
// HEALTH CHECK
// =============================================
app.get('/health', (req, res) => {
  res.json({
    service:   'Service Nilai',
    status:    'running',
    port:      PORT,
    timestamp: new Date().toISOString(),
  });
});

// =============================================
// FALLBACK
// =============================================
app.use((req, res) => {
  res.status(404).json({ success: false, message: 'Endpoint tidak ditemukan' });
});

// =============================================
// ERROR HANDLER
// =============================================
app.use((err, req, res, next) => {
  console.error('[SERVICE NILAI ERROR]', err);
  if (!res.headersSent) {
    res.status(500).json({ success: false, message: 'Terjadi kesalahan internal pada service nilai' });
  }
});

// =============================================
// START
// =============================================
app.listen(PORT, () => {
  console.log('='.repeat(50));
  console.log(`Service Nilai berjalan di port ${PORT}`);
  console.log('Hanya menerima request dari API Gateway');
  console.log('='.repeat(50));
});

module.exports = app;
