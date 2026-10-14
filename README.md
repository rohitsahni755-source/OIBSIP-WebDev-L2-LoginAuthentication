# VaultAuth — Secure Login Authentication System

> "Secure access. Simple experience."

A modern, production-grade browser authentication system built for the **Oasis Infobyte Internship Program (OIBSIP) — Web Development & Designing (Level 2 Task 4)**.

---

## 📌 Project Overview
- **Project Name:** VaultAuth — Secure Login
- **Organization:** Oasis Infobyte (OIBSIP)
- **Task Category:** Web Development & Designing — Level 2 Task 4
- **Year:** 2026
- **Architecture:** Client-side SPA Authentication with Native Web Crypto API (Salted SHA-256 Hashing) & Protected Route Gates.

> **⚠️ Security & Educational Note:**  
> *This implementation is intended for educational/demo purposes and is not a production authentication system.* To ensure maximum compatibility in browser environments while avoiding plaintext password storage, credentials are encrypted using the native Web Crypto API (`SubtleCrypto.digest('SHA-256')`) with a unique cryptographically generated 16-byte salt per user.

---

## 🚀 Key Features

### 1. Dual Flow: Registration & Login
- **Full Name Validation:** Non-empty, trimmed formatting.
- **Email Validation:** RFC-compliant regex validation and lowercase normalization.
- **Duplicate Account Prevention:** Verifies whether an email is already registered before writing to database.
- **Password Strength Evaluation:** Real-time feedback bar measuring length, lowercase, uppercase, digits, and special characters (Weak / Medium / Strong).
- **Complexity Requirements:** Minimum 8 characters, at least 1 uppercase letter, 1 lowercase letter, and 1 number.
- **Confirm Password Verification:** Ensures passwords match before submission.
- **Show/Hide Password Visibility Toggles:** Accessible interactive buttons with real-time icon state changes (`👁️` / `🔒`).
- **Remember Me Functionality:** Safely caches verified email for subsequent logins.

### 2. Security & Anti-Enumeration Protections
- **Generic Error Responses:** When login credentials fail, a generic `"Invalid email or password."` message is displayed to prevent user enumeration attacks.
- **No Plaintext Passwords:** Passwords are never saved in plaintext; only salted SHA-256 digests are stored.
- **Zero Sensitive Data in Session:** The active session only preserves the user's name, email, and timestamp—never passwords or hashes.
- **No `eval()`:** Clean JavaScript execution with strict event handling (`addEventListener`).
- **No Inline Handlers:** Zero `onclick` attributes in HTML.

### 3. Protected Dashboard
- **Route Authorization Gate:** Unauthenticated users attempting to view the dashboard are redirected to the Login view with an explanatory toast notification.
- **Personalized Header & Stats:** Displays user initials avatar, full name, verified email address, session start time, and security audit metrics.
- **Interactive Logout:** Immediately invalidates session, purges state, and returns to the login screen with a signed-out banner.

---

## 🎨 Design System & Palette
- **Background:** `#070B14` (Deep obsidian)
- **Card Surface:** `rgba(255, 255, 255, 0.05)` (24px backdrop blur glassmorphism)
- **Primary Accent:** `#3B82F6` (Electric Blue)
- **Secondary Accent:** `#8B5CF6` (Vibrant Violet)
- **Success Color:** `#10B981` (Emerald Green)
- **Error Color:** `#EF4444` (Crimson Red)
- **Typography:** `Inter` via Google Fonts

---

## 📁 Project Structure
```text
OIBSIP/
└── WebDev-L2-LoginAuthentication/
    ├── index.html       # Semantic single-page layout (Login, Register, Dashboard)
    ├── style.css        # Modern glassmorphism styles, responsive grid, animations
    ├── script.js        # Web Crypto hashing, validation engine, state management
    └── README.md        # Comprehensive documentation and internship report
```

---

## 🧪 Demonstration Test Account

You can register any new account through the UI, or use the pre-seeded demo user:

- **Email:** `alex@vaultauth.dev`
- **Password:** `Demo@2026`

### End-to-End Test Workflow:
1. **Register:** Click *"Create one"* → Fill name, email, password (`Demo@2026`), accept terms → Click *"Create Account"*.
2. **Login:** Enter email and password → Toggle password visibility (`👁️`) → Click *"Sign In"*.
3. **Dashboard:** Verify profile cards, active session timestamp, and security logs.
4. **Logout:** Click *"Logout"* → Confirm redirect back to login and session termination.
5. **Guard Test:** Refresh or attempt direct dashboard access while logged out to verify route protection.

---

## 💻 How to Run the Project
1. Download or clone this repository.
2. Open `index.html` directly in any modern web browser (Google Chrome, Mozilla Firefox, Microsoft Edge, Safari, Brave).
3. No local server, Node.js packages, or build dependencies are required.
