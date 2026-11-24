# Barrio de Fantasía (Web & API Server)

<p align="center">
  <img src="public/logo.png" width="128" height="128" alt="Barrio Fantasia Logo" style="border-radius: 28px; box-shadow: 0 10px 25px rgba(0,0,0,0.3);" />
</p>

<p align="center">
  <strong>High-performance, secure backend API and progressive web application for grassroots soccer leagues, 24-hour peer ratings, automated lineups, and Fantasy manager tracking.</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Node.js-24_LTS-green.svg?style=for-the-badge&logo=node.js" alt="Node.js 24 LTS" />
  <img src="https://img.shields.io/badge/PostgreSQL-16-blue.svg?style=for-the-badge&logo=postgresql" alt="PostgreSQL 16" />
  <img src="https://img.shields.io/badge/Express-4.x-black.svg?style=for-the-badge&logo=express" alt="Express" />
  <img src="https://img.shields.io/badge/Security-27--Point_Hardened-red.svg?style=for-the-badge&logo=shield" alt="Security Hardened" />
  <img src="https://img.shields.io/badge/License-MIT-lightgrey.svg?style=for-the-badge" alt="License MIT" />
</p>

---

## ⚽ Core Capabilities

- **24-Hour Peer Rating Window**: Fair-play matchday ratings (1.0 to 10.0 scale) and unanimous MVP election. Includes preventive notifications 2 hours prior to deadline to avoid -2 pts Fantasy penalties.
- **Transactional Integrity (PostgreSQL Advisory Locks)**: Concurrent goal/assist submissions are serialized via `pg_advisory_xact_lock` to eliminate race conditions (TOCTOU).
- **Fantasy Engine**: Strict 40M€ budget limits, 5-a-side rosters, and automated scoring computed strictly server-side.
- **Decoupled Avatar Storage**: High-speed avatar uploads strictly verified by binary magic bytes (JPEG `FF D8 FF` / PNG `89 50 4E 47`) and capped at 500 KB.
- **RESTful API**: Powers both the responsive Web SPA and the native [Barrio de Fantasía iOS client](https://github.com/Wacko87/barrio-fantasia-ios).

---

## 🛡️ 27-Point Security & Hardening Audit

The application has been audited and hardened across 27 critical defensive points:

| Check | Feature | Implementation |
|---|---|---|
| **1. Authentication** | Verified Accounts & Sessions | Session token table in PostgreSQL (`30 days` sliding expiry). |
| **2. Password Hashing** | Cryptographic Scrypt | `crypto.scrypt` with 16-byte random salt and `crypto.timingSafeEqual`. |
| **3. Secure Cookies** | `HttpOnly; SameSite=Lax; Secure` | Persistent session cookies immune to script theft. |
| **4. Password Reset** | 1-Hour Ephemeral Tokens | Single-use reset tokens with atomic row locking (`FOR UPDATE`). |
| **5. Secret Isolation** | Zero Client Secrets | All DB/SMTP credentials isolated strictly in environment variables. |
| **6. Public Envs** | Zero Leaks | Vanilla client bundles contain no private configuration variables. |
| **7. Git Cleanliness** | History Scanned | Secrets excluded via `.gitignore`. |
| **8. Revocation** | Ephemeral Access | Session invalidation on password reset or account revocation. |
| **9. Authorization (IDOR)**| User-Level Scoping | Strict ownership mapping (`OWNED` collections; users edit only their ID). |
| **10. SQL Injection** | Parameterized Queries | 100% of queries use `$1, $2` positional parameters. |
| **11. Admin Access** | Role-Based Server Checks | Admin-only route guards enforce `ADMIN_EMAILS` whitelist. |
| **12. Security Logging** | Suspicious Activity Alerts | `logSecurityEvent()` logs failed logins, 403 IDOR attempts, and probes. |
| **13. Input Validation** | Server-Side Schema Checks | Type, range, and format constraints on all API payloads. |
| **14. XSS Mitigation** | Helmet CSP & HTML Escaping | Strict `Content-Security-Policy` and DOM entity escaping. |
| **15. CSRF Defense** | SameSite & JSON Enforced | `SameSite=Lax` cookies + mandatory `application/json` headers. |
| **16. File Uploads** | Magic Bytes & 500 KB Limit | Binary header inspection (`FF D8 FF` / `89 50 4E 47`) on image payloads. |
| **17. Server-Side Economy**| Fantasy Market Computation | Prices and budget balance computed 100% on server from ratings. |
| **18. HTTPS Enforcement** | 301 Redirect & HSTS Header | `Strict-Transport-Security` header with `preload` directive. |
| **19. Rate Limiting** | Express Rate Limiters | 30 req/15m on login, 10 req/1h on reset, 300 req/15m on global API. |
| **20. Strict CORS** | Whitelisted Origins | Rejects foreign cross-origin requests with `403 Forbidden`. |
| **21. Security Headers** | Helmet Suite | `nosniff`, `SAMEORIGIN`, `noopen`, `referrer-policy: no-referrer`. |
| **22. Debug Mode Off** | Sanitized Error Responses | Generic 500 error responses with zero stack trace exposure. |
| **23. Dependencies** | Zero CVEs | Audited with `npm audit` (0 vulnerabilities). |
| **24. Dependency Hygiene** | Zero Bloat | Minimal footprint (only `express`, `pg`, `helmet`, `nodemailer`, `rate-limit`). |
| **25. Blocked Endpoints** | Explicit Dotfile Blocker | Instant `403 Forbidden` on requests for `/.env`, `.git`, `.sql`, backups. |
| **26. End-to-End Review** | Architecture Audit | Full codebase inspected and documented. |
| **27. Live Security Tests** | Automated Verification | Probed unauthorized endpoints, oversized uploads, and forbidden routes. |

---

## 🚀 Getting Started

### Prerequisites
- Node.js 20+ (or 24 LTS)
- PostgreSQL 16+
- Docker & Docker Compose (optional)

### 1. Environment Configuration

Copy the example environment template:

```bash
cp .env.example .env
```

Configure your database and mail credentials in `.env`:

```env
POSTGRES_PASSWORD=your_secure_password
DATABASE_URL=postgres://barrio:your_secure_password@localhost:5432/barrio
APP_URL=http://localhost:3000
ADMIN_EMAILS=admin@yourleague.com
```

### 2. Local Installation

```bash
npm install
npm start
```

### 3. Docker Deployment

```bash
docker compose -f docker-compose.example.yml up -d
```

The application will be running on `http://localhost:3000`.

---

## 📱 Mobile Companion

Looking for the native iOS application? Check out [barrio-fantasia-ios](https://github.com/Wacko87/barrio-fantasia-ios) (Swift 6, SwiftUI, SwiftData, TipKit, and Face ID).
