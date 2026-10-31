# Zero Trust Security — Sistem Nilai

**Proyek:** Tugas Praktikum Keamanan Informasi (KP70065004)  
**Program Studi:** Informatika, Universitas Siliwangi  
**Implementasi:** Zero Trust Security Architecture berdasarkan NIST SP 800-207

---

## 1. Deskripsi dan Tujuan Proyek

Sistem backend untuk mengelola nilai mata kuliah yang mengimplementasikan prinsip-prinsip **Zero Trust Security**:

- **Never Trust, Always Verify** — Setiap request diverifikasi ulang meskipun berasal dari jaringan internal
- **Least Privilege** — Setiap pengguna hanya mendapat akses yang diperlukan untuk tugasnya
- **Assume Breach** — Setiap service memverifikasi token secara mandiri, tidak mengandalkan kepercayaan implisit

---

## 2. Arsitektur dan Alur Request

```
Pengguna/Client
       │
       ▼
┌──────────────────────────────────┐
│   API Gateway (Port 3000)        │  ← Policy Enforcement Point (PEP)
│   - Autentikasi & token          │
│   - Policy Engine (allow/deny)   │
│   - Verifikasi device            │
│   - Forward request via fetch()  │
│   - Audit log                    │
└─────────┬──────────────┬─────────┘
          │ (+ gateway   │ secret)
          ▼              ▼
┌─────────────┐  ┌───────────────────┐
│ Service     │  │ Service Transkrip │
│ Nilai :3001 │  │ Port :3002        │
│             │  │                   │
│ - Nilai     │  │ - Transkrip mhs   │
│ - Kelas     │  │ - Sinkronisasi    │
│ - Finalisasi│  │   (hanya service  │
└─────────────┘  │    token)         │
                 └───────────────────┘
         ▲ Semua service share
         └── SQLite Database
```

### Alur Finalisasi Nilai (Komunikasi Antar-Service):

```
1.  Dosen → POST /kelas/:id/finalisasi → Gateway (port 3000)
2.  Gateway validasi: token, device, role, kepemilikan kelas, jam akses
3.  Gateway → Service Nilai (port 3001) + X-Gateway-Secret (via fetch)
4.  Service Nilai verifikasi gateway secret + token mandiri
5.  Service Nilai finalisasi nilai di database
6.  Gateway mengembalikan response 200 ke dosen
7.  Service Nilai (background) → POST /auth/service → Gateway (minta service token)
8.  Service Nilai (background) → POST /transkrip/sinkron → Gateway + service token
9.  Gateway validasi: token service, kepemilikan service-nilai
10. Gateway → Service Transkrip (port 3002) + X-Gateway-Secret
11. Service Transkrip verifikasi gateway secret + service token mandiri
12. Service Transkrip sinkronisasi transkrip ke database
```

> **Catatan:** Sinkronisasi transkrip (langkah 7–12) berjalan secara non-blocking di background setelah response finalisasi dikirim ke dosen. Ini mencegah deadlock akibat Service Nilai memanggil balik Gateway pada koneksi yang sama.

---

## 3. Teknologi yang Digunakan

| Komponen | Teknologi |
|----------|-----------|
| Runtime | Node.js v22+ (menggunakan `node:sqlite` built-in) |
| Framework | Express.js 4.18 |
| API Gateway | Express + `fetch()` built-in Node.js |
| Token | jsonwebtoken 9.0 (JWT HS256) |
| Database | SQLite via `node:sqlite` (built-in Node.js 22+) |
| Password hashing | bcryptjs 2.4 |
| HTTP client antar-service | `fetch()` built-in Node.js |
| Konfigurasi | dotenv 16.4 |

> **Tidak menggunakan** `http-proxy-middleware` — diganti dengan forward manual menggunakan `fetch()` untuk menghindari masalah kompatibilitas body stream dengan `express.json()`.

---

## 4. Persyaratan Instalasi

- **Node.js v22 atau lebih baru** (wajib — menggunakan `node:sqlite` built-in)
- **npm** (tersedia bersama Node.js)
- Windows / Linux / macOS

Cek versi Node.js:
```bash
node --version   # harus v22.0.0 atau lebih baru
```

---

## 5. Cara Memasang Dependensi

```bash
# Masuk ke direktori root proyek
cd zero-trust-sistem-nilai

# Install dependensi shared (bcryptjs, dotenv, express, jsonwebtoken)
npm install

# Install dependensi tiap service
cd gateway          && npm install && cd ..
cd service-nilai    && npm install && cd ..
cd service-transkrip && npm install && cd ..
cd database         && npm install && cd ..
```

---

## 6. Cara Mengatur Environment Variables

```bash
# Windows
copy .env.example .env

# Linux/macOS
cp .env.example .env
```

File `.env` sudah disediakan dengan kredensial demo — tidak perlu diubah untuk menjalankan proyek secara lokal.

> **PENTING:** Jangan gunakan nilai dari `.env` demo di lingkungan produksi.

---

## 7. Cara Menginisialisasi Database dan Menjalankan Seed

```bash
# Dari direktori root proyek
node database/seed.js
```

Seed akan:
- Menghapus data lama dan membuat ulang dari awal
- Membuat 6 pengguna (1 admin, 2 dosen, 3 mahasiswa)
- Mendaftarkan satu device per pengguna
- Membuat 2 kelas dengan enrollment mahasiswa
- Membuat data nilai awal (kelas 1 belum final, kelas 2 sudah final)
- Membuat data transkrip awal dari kelas yang sudah final
- Mendaftarkan service client untuk Service Nilai

> ⚠️ **Wajib matikan semua service sebelum menjalankan seed.** Jika service masih aktif saat seed dijalankan, database bisa konflik dan menyebabkan service crash saat menerima request berikutnya. Selalu restart semua service setelah seed selesai.

---

## 8. Cara Menjalankan Ketiga Aplikasi

Buka **tiga terminal terpisah** dan jalankan masing-masing:

**Terminal 1 — Service Transkrip:**
```bash
cd zero-trust-sistem-nilai
node service-transkrip/server.js
```

**Terminal 2 — Service Nilai:**
```bash
cd zero-trust-sistem-nilai
node service-nilai/server.js
```

**Terminal 3 — API Gateway:**
```bash
cd zero-trust-sistem-nilai
node gateway/server.js
```

Verifikasi semua berjalan:
```bash
curl http://localhost:3000/health
# {"service":"API Gateway","status":"running","port":3000,...}
```

---

## 9. Cara Reset Data ke Kondisi Awal

Jika ingin mengembalikan semua data ke kondisi awal (misalnya setelah finalisasi kelas untuk keperluan testing ulang):

```bash
# Langkah 1: Matikan semua service (tutup terminal atau jalankan ini)
# Windows PowerShell:
foreach ($p in @(3000,3001,3002)) {
  $conn = Get-NetTCPConnection -LocalPort $p -ErrorAction SilentlyContinue
  if ($conn) { Stop-Process -Id ($conn | Select-Object -First 1).OwningProcess -Force -ErrorAction SilentlyContinue }
}

# Langkah 2: Jalankan seed
node database/seed.js

# Langkah 3: Start ulang semua service (tiga terminal)
node service-transkrip/server.js
node service-nilai/server.js
node gateway/server.js

# Langkah 4: Login ulang di Postman (token lama tidak berlaku setelah reset)
```

---

## 10. Port dan Endpoint yang Tersedia

Semua request client harus melalui **API Gateway port 3000**. Jangan akses port 3001/3002 langsung.

| Method | Path | Deskripsi | Role yang Diizinkan |
|--------|------|-----------|---------------------|
| POST | `/auth/login` | Login, dapatkan token | Semua |
| POST | `/auth/refresh` | Perbarui access token | — |
| POST | `/auth/logout` | Logout, cabut refresh token | — |
| POST | `/auth/service` | Minta service token | Service client |
| GET | `/nilai` | Lihat daftar nilai | Mahasiswa, Dosen |
| PUT | `/nilai/:id` | Ubah nilai | Dosen (kelas sendiri, belum final, dalam jam akses) |
| GET | `/kelas` | Daftar kelas yang diampu | Dosen |
| POST | `/kelas/:id/finalisasi` | Finalisasi nilai kelas | Dosen (kelas sendiri, dalam jam akses) |
| GET | `/transkrip/:nim` | Lihat transkrip mahasiswa | Mahasiswa (NIM sendiri), Admin |
| POST | `/transkrip/sinkron` | Sinkronisasi transkrip | Service Nilai (service token saja) |
| GET | `/health` | Health check | Publik |

---

## 11. Akun Demo, Role, dan Device ID

> ⚠️ **Hanya untuk demo/testing — JANGAN GUNAKAN DI PRODUKSI**

| Role | Username | Password | Device ID | Info Tambahan |
|------|----------|----------|-----------|---------------|
| Admin | `admin01` | `Admin@Demo2024` | `device-admin-001` | — |
| Dosen 1 | `dosen01` | `Dosen@Demo2024` | `device-dosen-001` | Mengampu IF70065004 |
| Dosen 2 | `dosen02` | `Dosen@Demo2024` | `device-dosen-002` | Mengampu IF60045001 |
| Mahasiswa 1 | `mhs001` | `Mahasiswa@Demo2024` | `device-mhs-001` | NIM: 207006001 |
| Mahasiswa 2 | `mhs002` | `Mahasiswa@Demo2024` | `device-mhs-002` | NIM: 207006002 |
| Mahasiswa 3 | `mhs003` | `Mahasiswa@Demo2024` | `device-mhs-003` | NIM: 207006003 |

**Data Kelas setelah seed:**

| Kode | Nama | Dosen | Status | ID Nilai |
|------|------|-------|--------|----------|
| IF70065004 | Keamanan Informasi | dosen01 | **Belum final** — bisa diubah dan difinalisasi | 1, 2, 3 |
| IF60045001 | Pemrograman Web Lanjut | dosen02 | **Sudah final** — tidak bisa diubah | 4, 5 |

**ID Nilai setelah seed:**

| ID | Mahasiswa | Kelas | Nilai Awal | Status |
|----|-----------|-------|------------|--------|
| 1 | mhs001 (Ahmad) | Kelas 1 | 85 (A) | Belum final |
| 2 | mhs002 (Dewi) | Kelas 1 | 75 (AB) | Belum final |
| 3 | mhs003 (Rizky) | Kelas 1 | 65 (BC) | Belum final |
| 4 | mhs001 (Ahmad) | Kelas 2 | 90 (A) | **Final** |
| 5 | mhs002 (Dewi) | Kelas 2 | 78 (AB) | **Final** |

---

## 12. Contoh Request dengan cURL

### Login
```bash
curl -X POST http://localhost:3000/auth/login \
  -H "Content-Type: application/json" \
  -H "X-Device-ID: device-dosen-001" \
  -d '{"username":"dosen01","password":"Dosen@Demo2024"}'
```

### Lihat Nilai (sebagai Dosen)
```bash
curl http://localhost:3000/nilai \
  -H "Authorization: Bearer <ACCESS_TOKEN>" \
  -H "X-Device-ID: device-dosen-001"
```

### Lihat Daftar Kelas (sebagai Dosen)
```bash
curl http://localhost:3000/kelas \
  -H "Authorization: Bearer <DOSEN01_TOKEN>" \
  -H "X-Device-ID: device-dosen-001"
```

### Ubah Nilai (ID 1, dalam jam akses 07:00–21:00)
```bash
curl -X PUT http://localhost:3000/nilai/1 \
  -H "Authorization: Bearer <DOSEN01_TOKEN>" \
  -H "X-Device-ID: device-dosen-001" \
  -H "Content-Type: application/json" \
  -d '{"nilai_angka": 88}'
```

### Finalisasi Kelas
```bash
curl -X POST http://localhost:3000/kelas/1/finalisasi \
  -H "Authorization: Bearer <DOSEN01_TOKEN>" \
  -H "X-Device-ID: device-dosen-001" \
  -H "Content-Type: application/json" \
  -d '{}'
```

### Lihat Transkrip (sebagai Mahasiswa)
```bash
curl http://localhost:3000/transkrip/207006001 \
  -H "Authorization: Bearer <MHS001_TOKEN>" \
  -H "X-Device-ID: device-mhs-001"
```

### Refresh Token
```bash
curl -X POST http://localhost:3000/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refresh_token":"<REFRESH_TOKEN>"}'
```

### Logout
```bash
curl -X POST http://localhost:3000/auth/logout \
  -H "Content-Type: application/json" \
  -d '{"refresh_token":"<REFRESH_TOKEN>"}'
```

---

## 13. Skenario Pengujian

| # | Skenario | HTTP yang Diharapkan | Pesan |
|---|----------|---------------------|-------|
| 1 | Login berhasil (kredensial + device valid) | 200 | access_token diterima |
| 2 | Login gagal — password salah | 401 | Kredensial tidak valid |
| 3 | Login gagal — device tidak terdaftar | 403 | Device tidak terdaftar |
| 4 | Mahasiswa lihat nilai sendiri | 200 | Data nilai |
| 5 | Mahasiswa tidak bisa ubah nilai | 403 | Hanya dosen yang dapat mengubah nilai |
| 6 | Dosen lihat nilai kelas yang diampu | 200 | Data nilai semua mahasiswa di kelas |
| 7 | Dosen tidak akses kelas dosen lain (PUT /nilai/4 oleh dosen01) | 403 | Dosen tidak mengampu kelas terkait |
| 8 | Dosen ubah nilai belum final dalam jam akses | 200 | Nilai berhasil diperbarui |
| 9 | Dosen tidak ubah nilai sudah final (PUT /nilai/4 oleh dosen02) | 409 | Nilai sudah difinalisasi |
| 10 | Akses di luar jam 07:00–21:00 WIB | 403 | Di luar jam akses |
| 11 | Dosen finalisasi kelas sendiri dalam jam akses | 200 | Kelas berhasil difinalisasi |
| 12 | Dosen tidak finalisasi kelas dosen lain | 403 | Dosen tidak mengampu kelas ini |
| 13 | Mahasiswa lihat transkrip NIM sendiri | 200 | Data transkrip + IPK |
| 13b | Mahasiswa tidak lihat transkrip orang lain | 403 | Hanya dapat melihat milik sendiri |
| 14 | Admin lihat transkrip semua mahasiswa | 200 | Data transkrip |
| 15 | Dosen tidak akses transkrip | 403 | Role tidak diizinkan |
| 16 | Token tidak valid/kedaluwarsa ditolak | 401 | Token tidak valid |
| 17 | Refresh token valid perbarui access token | 200 | Access token baru |
| 18 | Refresh token dicabut setelah logout ditolak | 401 | Token sudah tidak valid |
| 19 | Akses langsung ke service tanpa gateway secret | 403 | Gateway secret tidak valid |
| 20 | Gateway secret benar tapi token invalid | 401 | Token tidak valid |
| 21 | Token signature palsu ditolak | 401 | Token tidak valid |
| 22 | Token pengguna ditolak di /transkrip/sinkron | 403 | Hanya service token |
| 23 | Service token valid untuk sinkronisasi | 200 | Sinkronisasi berhasil |
| 24 | Device ID tidak sesuai token ditolak | 403 | Device tidak terdaftar |
| 25 | Audit log mencatat keputusan allow dan deny | — | Lihat tabel audit_log di DB |
| 26 | Finalisasi otomatis memicu sinkronisasi transkrip | 200 | sync_transkrip: pending (berjalan di background) |

---

## 14. Penjelasan Penerapan Prinsip Zero Trust

### Never Trust, Always Verify
- Gateway memverifikasi **setiap request** — tidak ada pengecualian untuk jaringan lokal
- Setiap service memverifikasi token secara **mandiri** (tidak percaya gateway saja)
- Role dari token dicocokkan ulang dengan data di **database** (tidak percaya klaim token saja)
- Device diverifikasi per pengguna di database pada setiap request
- Gateway secret saja tidak cukup — token tetap wajib valid

### Least Privilege
- **Mahasiswa:** hanya GET /nilai (nilai sendiri) dan GET /transkrip/:nim (NIM sendiri)
- **Dosen:** hanya GET /nilai, GET /kelas, PUT /nilai/:id, dan POST /kelas/:id/finalisasi untuk kelas yang diampu saja
- **Admin:** hanya GET /transkrip/:nim untuk semua NIM, tidak bisa ubah data
- **Service Nilai:** hanya POST /transkrip/sinkron menggunakan service token
- **Default-deny:** semua endpoint atau kondisi yang tidak secara eksplisit diizinkan akan ditolak

### Assume Breach
- Setiap service memvalidasi: gateway secret, token signature, masa berlaku token, dan klaim role
- Token kedaluwarsa, dicabut, atau dipalsukan ditolak di setiap lapisan secara independen
- Audit log mencatat setiap keputusan allow/deny lengkap dengan alasan
- Error response tidak membocorkan detail internal, stack trace, atau data sensitif

---

## 15. Batasan Implementasi

1. **Jam Akses Berbasis Waktu Server:** Pemeriksaan jam menggunakan waktu server dengan timezone Asia/Jakarta. Jika sistem tidak tersinkronisasi dengan NTP, pemeriksaan jam bisa tidak akurat.

2. **Sinkronisasi Non-Blocking:** Sinkronisasi transkrip setelah finalisasi berjalan di background — response finalisasi dikirim lebih dulu, baru sinkronisasi diproses. Ini berarti jika sinkronisasi gagal, dosen tidak mendapat notifikasi langsung. Data transkrip dapat disinkronisasi ulang secara manual melalui `POST /transkrip/sinkron` dengan service token.

3. **Single SQLite Database:** Semua service berbagi satu file SQLite. Di produksi, setiap service sebaiknya memiliki database sendiri dengan mekanisme event/message queue (misal RabbitMQ atau Kafka) untuk komunikasi data antar-service.

4. **Wajib Restart Setelah Seed:** Karena Node.js menyimpan koneksi database sebagai singleton di memory, menjalankan seed saat service aktif akan menyebabkan konflik constraint. Selalu matikan semua service sebelum seed, lalu restart setelahnya.

5. **Token Storage di Client:** Implementasi tidak mengatur penyimpanan token di sisi client. Di produksi, gunakan HttpOnly cookies untuk refresh token dan memory saja untuk access token.

6. **HTTP Only:** Semua komunikasi menggunakan HTTP. Di produksi, wajib menggunakan HTTPS dengan TLS certificate yang valid untuk mencegah token disadap.

7. **Rate Limiting:** Belum ada rate limiting pada endpoint `/auth/login`. Di produksi, tambahkan pembatasan percobaan login untuk mencegah serangan brute force.

---

## Panduan Demo Video (6–9 Menit)

### Segmen 1 — Pendahuluan (±1 menit)
- Tampilkan struktur folder proyek
- Jelaskan arsitektur tiga service di README
- Sebutkan tiga prinsip Zero Trust yang diimplementasikan

### Segmen 2 — Autentikasi (±2 menit)
- Login berhasil: dosen01 + device-dosen-001 → 200 + token
- Login gagal: password salah → 401
- Login gagal: device tidak terdaftar → 403
- Tunjukkan kode di `gateway/auth.js` — bagian verifikasi device
- Demo refresh token → 200, lalu logout, lalu coba refresh lagi → 401

### Segmen 3 — Kebijakan Akses (±3 menit)
- Mahasiswa lihat nilai sendiri → 200
- Mahasiswa coba ubah nilai → 403
- Dosen lihat nilai kelas yang diampu → 200
- Dosen coba ubah nilai kelas dosen lain (nilai ID 4 oleh dosen01) → 403
- Dosen ubah nilai yang belum final (nilai ID 1 oleh dosen01) → 200 atau 403 jika di luar jam
- Dosen coba finalisasi kelas dosen lain → 403
- Dosen finalisasi kelas sendiri → 200 (sinkronisasi berjalan di background)
- Tunjukkan kode di `gateway/policy.js` — fungsi `evaluate()`

### Segmen 4 — Verifikasi Konteks (±1.5 menit)
- Device mismatch: token mhs001 + X-Device-ID milik mhs002 → 403
- Token tidak valid → 401
- Akses langsung ke port 3001 tanpa X-Gateway-Secret → 403
- Akses ke port 3001 dengan gateway secret benar tapi token invalid → 401
- Tunjukkan kode verifikasi di `service-nilai/routes/nilai.js` — fungsi `requireAuth()`

### Segmen 5 — Audit Log (±1 menit)
- Buka file database dengan SQLite viewer (misal DB Browser for SQLite)
- Jalankan query: `SELECT * FROM audit_log ORDER BY id DESC LIMIT 15`
- Tunjukkan kolom: subject, decision (allow/deny), reason, endpoint, device_id
- Tunjukkan tidak ada password, secret, atau token lengkap di kolom manapun

---

*Proyek ini dibuat untuk keperluan akademik — Keamanan Informasi (KP70065004), Universitas Siliwangi.*  
*Jangan gunakan kredensial demo di lingkungan produksi.*
