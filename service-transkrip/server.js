'use strict';

/**
 * Service Transkrip — Zero Trust Sistem Nilai
 * Port: 3002
 * 
 * Menampilkan transkrip akademik mahasiswa.
 * Hanya menerima request dari API Gateway.
 * Sinkronisasi hanya dari Service Nilai menggunakan service token.
 */

const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '..', '.env') });

// Validasi konfigurasi kritis
const REQUIRED_ENV = ['JWT_ACCESS_SECRET', 'JWT_SERVICE_SECRET', 'GATEWAY_SECRET'];
for (const key of REQUIRED_ENV) {
  if (!process.env[key]) {
    console.error(`[SERVICE TRANSKRIP STARTUP ERROR] Variabel lingkungan wajib tidak ditemukan: ${key}`);
    process.exit(1);
  }
}

const express     = require('express');
const transk      = require('./routes/transkrip');

const app  = express();
const PORT = parseInt(process.env.SERVICE_TRANSKRIP_PORT) || 3002;

// =============================================
// MIDDLEWARE GLOBAL
// =============================================
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

app.use((req, res, next) => {
  console.log(`[SERVICE TRANSKRIP] ${req.method} ${req.path} — ${new Date().toISOString()}`);
  next();
});

// =============================================
// ROUTES
// =============================================
app.use('/transkrip', transk);

// =============================================
// HEALTH CHECK
// =============================================
app.get('/health', (req, res) => {
  res.json({
    service:   'Service Transkrip',
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
  console.error('[SERVICE TRANSKRIP ERROR]', err);
  if (!res.headersSent) {
    res.status(500).json({ success: false, message: 'Terjadi kesalahan internal pada service transkrip' });
  }
});

// =============================================
// START
// =============================================
app.listen(PORT, () => {
  console.log('='.repeat(50));
  console.log(`Service Transkrip berjalan di port ${PORT}`);
  console.log('Hanya menerima request dari API Gateway');
  console.log('='.repeat(50));
});

module.exports = app;
