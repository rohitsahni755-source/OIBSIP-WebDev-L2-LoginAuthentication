/**
 * VaultAuth — Secure Login Authentication System
 * Level 2 Task 4 — OIBSIP Web Development & Designing Internship
 * Architecture:
 * - SHA-256 cryptographic salted hashing via native Web Crypto API (SubtleCrypto)
 * - Safe state management: no plaintext passwords stored in session or user database
 * - Zero eval(), no inline onclick handlers
 * - Strict form validation (Regex, length, uppercase, lowercase, numbers)
 * - Duplicate email prevention
 * - Generic error reporting to mitigate user enumeration
 * - Full routing state machine: Login <-> Register <-> Protected Dashboard <-> Logout
 */

(function () {
  'use strict';

  // Storage Keys
  const STORAGE_USERS_KEY = 'vaultauth_users_db_v1';
  const STORAGE_SESSION_KEY = 'vaultauth_active_session_v1';
  const STORAGE_REMEMBER_KEY = 'vaultauth_remember_email_v1';

  // DOM Elements - Views
  const viewLogin = document.getElementById('view-login');
  const viewRegister = document.getElementById('view-register');
  const viewDashboard = document.getElementById('view-dashboard');
  const toastContainer = document.getElementById('toast-container');
  const topHeader = document.getElementById('top-header');

  // Login Form Elements
  const formLogin = document.getElementById('form-login');
  const loginEmailInput = document.getElementById('login-email');
  const loginPasswordInput = document.getElementById('login-password');
  const loginRememberCheckbox = document.getElementById('login-remember');
  const loginGeneralError = document.getElementById('login-general-error');
  const loginEmailError = document.getElementById('login-email-error');
  const loginPasswordError = document.getElementById('login-password-error');
  const btnToggleLoginPw = document.getElementById('btn-toggle-login-pw');
  const btnSubmitLogin = document.getElementById('btn-submit-login');
  const linkToRegister = document.getElementById('link-to-register');

  // Register Form Elements
  const formRegister = document.getElementById('form-register');
  const regNameInput = document.getElementById('reg-name');
  const regEmailInput = document.getElementById('reg-email');
  const regPasswordInput = document.getElementById('reg-password');
  const regConfirmPasswordInput = document.getElementById('reg-confirm-password');
  const regTermsCheckbox = document.getElementById('reg-terms');
  const regGeneralError = document.getElementById('reg-general-error');
  const regNameError = document.getElementById('reg-name-error');
  const regEmailError = document.getElementById('reg-email-error');
  const regPasswordError = document.getElementById('reg-password-error');
  const regConfirmPasswordError = document.getElementById('reg-confirm-password-error');
  const regTermsError = document.getElementById('reg-terms-error');
  const btnToggleRegPw = document.getElementById('btn-toggle-reg-pw');
  const btnToggleRegConfirmPw = document.getElementById('btn-toggle-reg-confirm-pw');
  const btnSubmitRegister = document.getElementById('btn-submit-register');
  const linkToLogin = document.getElementById('link-to-login');

  // Password Strength Elements
  const pwStrengthBar = document.getElementById('pw-strength-bar');
  const pwStrengthText = document.getElementById('pw-strength-text');

  // Dashboard Elements
  const dashUserName = document.getElementById('dash-user-name');
  const dashUserEmail = document.getElementById('dash-user-email');
  const dashAvatarInitials = document.getElementById('dash-avatar-initials');
  const dashWelcomeName = document.getElementById('dash-welcome-name');
  const dashCardProfile = document.getElementById('dash-card-profile');
  const dashCardEmail = document.getElementById('dash-card-email');
  const dashSessionTime = document.getElementById('dash-session-time');
  const btnLogout = document.getElementById('btn-logout');

  // Crypto Utility: Secure SHA-256 Hashing with Salt
  // Ensures passwords are NEVER stored in plaintext in the client database.
  async function hashPassword(password, salt) {
    const enc = new TextEncoder();
    const data = enc.encode(salt + password + 'VaultAuth2026SecureSaltKey');
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  }

  function generateSalt() {
    const array = new Uint8Array(16);
    crypto.getRandomValues(array);
    return Array.from(array, b => b.toString(16).padStart(2, '0')).join('');
  }

  // Toast Notification System
  function showToast(message, type = 'info') {
    if (!toastContainer) return;
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;

    let icon = 'ℹ️';
    if (type === 'success') icon = '✓';
    if (type === 'error') icon = '✕';

    toast.innerHTML = `
      <span class="toast-icon">${icon}</span>
      <span class="toast-message">${escapeHtml(message)}</span>
    `;

    toastContainer.appendChild(toast);

    setTimeout(() => {
      toast.style.opacity = '0';
      toast.style.transform = 'translateY(-10px) scale(0.95)';
      setTimeout(() => toast.remove(), 250);
    }, 3800);
  }

  function escapeHtml(str) {
    if (typeof str !== 'string') return '';
    return str
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  // Database Management (Demo persistent storage via localStorage)
  function getUsersDB() {
    try {
      const data = localStorage.getItem(STORAGE_USERS_KEY);
      return data ? JSON.parse(data) : [];
    } catch (e) {
      console.warn('LocalStorage error:', e);
      return [];
    }
  }

  function saveUsersDB(users) {
    try {
      localStorage.setItem(STORAGE_USERS_KEY, JSON.stringify(users));
    } catch (e) {
      console.warn('LocalStorage save error:', e);
    }
  }

  // Session Management
  function getActiveSession() {
    try {
      // Check session storage first, then local storage (remember me)
      const sessionData = sessionStorage.getItem(STORAGE_SESSION_KEY) || localStorage.getItem(STORAGE_SESSION_KEY);
      return sessionData ? JSON.parse(sessionData) : null;
    } catch (e) {
      return null;
    }
  }

  function setActiveSession(user, remember) {
    // Crucial: session contains only sanitized profile data, NEVER password or hash
    const sessionPayload = {
      id: user.id,
      name: user.name,
      email: user.email,
      loginTime: new Date().toISOString()
    };
    const stringified = JSON.stringify(sessionPayload);
    if (remember) {
      localStorage.setItem(STORAGE_SESSION_KEY, stringified);
    } else {
      sessionStorage.setItem(STORAGE_SESSION_KEY, stringified);
      localStorage.removeItem(STORAGE_SESSION_KEY);
    }
  }

  function clearActiveSession() {
    sessionStorage.removeItem(STORAGE_SESSION_KEY);
    localStorage.removeItem(STORAGE_SESSION_KEY);
  }

  // Router / Screen Switching
  function navigateTo(screenName, optionalMessage) {
    // Hide all views
    viewLogin.classList.add('hidden');
    viewRegister.classList.add('hidden');
    viewDashboard.classList.add('hidden');

    // Reset error banners
    clearFormErrors();

    if (screenName === 'dashboard') {
      const session = getActiveSession();
      if (!session) {
        // Protected route guard
        navigateTo('login', 'Please sign in to access the protected dashboard.');
        return;
      }
      populateDashboard(session);
      viewDashboard.classList.remove('hidden');
      window.scrollTo(0, 0);
      return;
    }

    if (screenName === 'register') {
      viewRegister.classList.remove('hidden');
      regNameInput.focus();
      window.scrollTo(0, 0);
      return;
    }

    // Default: Login screen
    viewLogin.classList.remove('hidden');
    window.scrollTo(0, 0);

    // Pre-populate remembered email
    const rememberedEmail = localStorage.getItem(STORAGE_REMEMBER_KEY);
    if (rememberedEmail) {
      loginEmailInput.value = rememberedEmail;
      loginRememberCheckbox.checked = true;
      loginPasswordInput.focus();
    } else {
      loginEmailInput.focus();
    }

    if (optionalMessage) {
      showToast(optionalMessage, 'info');
    }
  }

  function clearFormErrors() {
    // Clear login errors
    if (loginGeneralError) {
      loginGeneralError.classList.add('hidden');
      loginGeneralError.textContent = '';
    }
    if (loginEmailError) loginEmailError.textContent = '';
    if (loginPasswordError) loginPasswordError.textContent = '';
    loginEmailInput.classList.remove('input-error');
    loginPasswordInput.classList.remove('input-error');

    // Clear register errors
    if (regGeneralError) {
      regGeneralError.classList.add('hidden');
      regGeneralError.textContent = '';
    }
    if (regNameError) regNameError.textContent = '';
    if (regEmailError) regEmailError.textContent = '';
    if (regPasswordError) regPasswordError.textContent = '';
    if (regConfirmPasswordError) regConfirmPasswordError.textContent = '';
    if (regTermsError) regTermsError.textContent = '';

    regNameInput.classList.remove('input-error');
    regEmailInput.classList.remove('input-error');
    regPasswordInput.classList.remove('input-error');
    regConfirmPasswordInput.classList.remove('input-error');
  }

  // Populate Dashboard with Authenticated Session Data
  function populateDashboard(session) {
    const initials = session.name
      .split(' ')
      .filter(Boolean)
      .slice(0, 2)
      .map(part => part[0].toUpperCase())
      .join('') || 'VA';

    dashAvatarInitials.textContent = initials;
    dashUserName.textContent = session.name;
    dashUserEmail.textContent = session.email;
    dashWelcomeName.textContent = session.name;
    dashCardProfile.textContent = session.name;
    dashCardEmail.textContent = session.email;

    const formattedTime = new Date(session.loginTime).toLocaleTimeString([], {
      hour: '2-digit',
      minute: '2-digit'
    });
    dashSessionTime.textContent = `Today, ${formattedTime}`;
  }

  // Validation Helpers
  function isValidEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
  }

  function calculatePasswordStrength(password) {
    let score = 0;
    if (!password) return { score: 0, label: 'None', className: '' };

    if (password.length >= 8) score++;
    if (/[A-Z]/.test(password)) score++;
    if (/[a-z]/.test(password)) score++;
    if (/[0-9]/.test(password)) score++;
    if (/[^A-Za-z0-9]/.test(password)) score++;

    if (score <= 2) return { score: 1, label: 'Weak', className: 'weak' };
    if (score === 3 || score === 4) return { score: 2, label: 'Medium', className: 'medium' };
    return { score: 3, label: 'Strong', className: 'strong' };
  }

  // Real-time password strength listener
  regPasswordInput.addEventListener('input', () => {
    const val = regPasswordInput.value;
    const strength = calculatePasswordStrength(val);

    pwStrengthBar.className = 'pw-strength-bar ' + strength.className;
    pwStrengthText.className = 'pw-strength-text ' + strength.className;
    pwStrengthText.textContent = val.length === 0 ? 'None' : strength.label;
  });

  // Password Visibility Toggles
  function setupPasswordToggle(btn, input) {
    btn.addEventListener('click', () => {
      const isPassword = input.getAttribute('type') === 'password';
      input.setAttribute('type', isPassword ? 'text' : 'password');
      btn.setAttribute('aria-label', isPassword ? 'Hide password' : 'Show password');
      btn.textContent = isPassword ? '🔒' : '👁️';
    });
  }

  setupPasswordToggle(btnToggleLoginPw, loginPasswordInput);
  setupPasswordToggle(btnToggleRegPw, regPasswordInput);
  setupPasswordToggle(btnToggleRegConfirmPw, regConfirmPasswordInput);

  // Registration Flow
  formRegister.addEventListener('submit', async (e) => {
    e.preventDefault();
    clearFormErrors();

    const name = regNameInput.value.trim();
    const email = regEmailInput.value.trim().toLowerCase();
    const password = regPasswordInput.value;
    const confirmPassword = regConfirmPasswordInput.value;
    const termsAccepted = regTermsCheckbox.checked;

    let hasError = false;

    // Full name validation
    if (!name) {
      regNameError.textContent = 'Please enter your full name.';
      regNameInput.classList.add('input-error');
      hasError = true;
    }

    // Email validation
    if (!email) {
      regEmailError.textContent = 'Please enter your email address.';
      regEmailInput.classList.add('input-error');
      hasError = true;
    } else if (!isValidEmail(email)) {
      regEmailError.textContent = 'Enter a valid email address.';
      regEmailInput.classList.add('input-error');
      hasError = true;
    }

    // Password validation (min 8 chars, 1 uppercase, 1 lowercase, 1 number)
    const hasMinLength = password.length >= 8;
    const hasUpper = /[A-Z]/.test(password);
    const hasLower = /[a-z]/.test(password);
    const hasNumber = /[0-9]/.test(password);

    if (!password) {
      regPasswordError.textContent = 'Password is required.';
      regPasswordInput.classList.add('input-error');
      hasError = true;
    } else if (!hasMinLength) {
      regPasswordError.textContent = 'Password must be at least 8 characters.';
      regPasswordInput.classList.add('input-error');
      hasError = true;
    } else if (!hasUpper || !hasLower || !hasNumber) {
      regPasswordError.textContent = 'Must include at least 1 uppercase, 1 lowercase, and 1 number.';
      regPasswordInput.classList.add('input-error');
      hasError = true;
    }

    // Confirm password validation
    if (!confirmPassword) {
      regConfirmPasswordError.textContent = 'Please confirm your password.';
      regConfirmPasswordInput.classList.add('input-error');
      hasError = true;
    } else if (password !== confirmPassword) {
      regConfirmPasswordError.textContent = 'Passwords do not match.';
      regConfirmPasswordInput.classList.add('input-error');
      hasError = true;
    }

    // Terms validation
    if (!termsAccepted) {
      regTermsError.textContent = 'Please accept the Terms of Service to proceed.';
      hasError = true;
    }

    if (hasError) return;

    // Loading State
    btnSubmitRegister.disabled = true;
    const originalBtnHtml = btnSubmitRegister.innerHTML;
    btnSubmitRegister.innerHTML = `<span class="btn-spinner"></span> Creating Account...`;

    try {
      // Duplicate account check
      const users = getUsersDB();
      const existingUser = users.find(u => u.email === email);

      if (existingUser) {
        regGeneralError.textContent = 'An account with these details already exists.';
        regGeneralError.classList.remove('hidden');
        regEmailInput.classList.add('input-error');
        showToast('An account with these details already exists.', 'error');
        btnSubmitRegister.disabled = false;
        btnSubmitRegister.innerHTML = originalBtnHtml;
        return;
      }

      // Hash password using SHA-256 with random salt
      const salt = generateSalt();
      const passwordHash = await hashPassword(password, salt);

      const newUser = {
        id: 'usr_' + Date.now() + Math.random().toString(36).substring(2, 7),
        name: name,
        email: email,
        passwordHash: passwordHash,
        salt: salt,
        createdAt: new Date().toISOString()
      };

      users.push(newUser);
      saveUsersDB(users);

      // Reset form
      formRegister.reset();
      pwStrengthBar.className = 'pw-strength-bar';
      pwStrengthText.textContent = 'None';
      pwStrengthText.className = 'pw-strength-text';

      showToast('Account created successfully. You can now sign in.', 'success');

      // Navigate to login with success banner
      navigateTo('login');
      loginEmailInput.value = email;
      loginPasswordInput.focus();

      if (loginGeneralError) {
        loginGeneralError.className = 'general-banner banner-success';
        loginGeneralError.textContent = 'Account created successfully. You can now sign in.';
        loginGeneralError.classList.remove('hidden');
      }

    } catch (err) {
      console.error('Registration error:', err);
      regGeneralError.textContent = 'An error occurred while creating your account. Please try again.';
      regGeneralError.classList.remove('hidden');
    } finally {
      btnSubmitRegister.disabled = false;
      btnSubmitRegister.innerHTML = originalBtnHtml;
    }
  });

  // Login Flow
  formLogin.addEventListener('submit', async (e) => {
    e.preventDefault();
    clearFormErrors();

    const email = loginEmailInput.value.trim().toLowerCase();
    const password = loginPasswordInput.value;
    const remember = loginRememberCheckbox.checked;

    let hasError = false;

    if (!email) {
      loginEmailError.textContent = 'Please enter your email address.';
      loginEmailInput.classList.add('input-error');
      hasError = true;
    } else if (!isValidEmail(email)) {
      loginEmailError.textContent = 'Enter a valid email address.';
      loginEmailInput.classList.add('input-error');
      hasError = true;
    }

    if (!password) {
      loginPasswordError.textContent = 'Please enter your password.';
      loginPasswordInput.classList.add('input-error');
      hasError = true;
    }

    if (hasError) return;

    // Loading State
    btnSubmitLogin.disabled = true;
    const originalBtnHtml = btnSubmitLogin.innerHTML;
    btnSubmitLogin.innerHTML = `<span class="btn-spinner"></span> Authenticating...`;

    try {
      const users = getUsersDB();
      const user = users.find(u => u.email === email);

      // Security requirement: Generic error to prevent account enumeration
      if (!user) {
        loginGeneralError.className = 'general-banner';
        loginGeneralError.textContent = 'Invalid email or password.';
        loginGeneralError.classList.remove('hidden');
        loginPasswordInput.classList.add('input-error');
        showToast('Invalid email or password.', 'error');
        return;
      }

      // Hash entered password with user's stored salt
      const testHash = await hashPassword(password, user.salt);

      if (testHash !== user.passwordHash) {
        loginGeneralError.className = 'general-banner';
        loginGeneralError.textContent = 'Invalid email or password.';
        loginGeneralError.classList.remove('hidden');
        loginPasswordInput.classList.add('input-error');
        showToast('Invalid email or password.', 'error');
        return;
      }

      // Handle "Remember Me"
      if (remember) {
        localStorage.setItem(STORAGE_REMEMBER_KEY, email);
      } else {
        localStorage.removeItem(STORAGE_REMEMBER_KEY);
      }

      // Create session state
      setActiveSession(user, remember);

      // Clear password field
      loginPasswordInput.value = '';

      showToast(`Welcome back, ${user.name}!`, 'success');

      // Navigate to Protected Dashboard
      navigateTo('dashboard');

    } catch (err) {
      console.error('Login error:', err);
      loginGeneralError.className = 'general-banner';
      loginGeneralError.textContent = 'Authentication error. Please try again.';
      loginGeneralError.classList.remove('hidden');
    } finally {
      btnSubmitLogin.disabled = false;
      btnSubmitLogin.innerHTML = originalBtnHtml;
    }
  });

  // Logout Flow
  btnLogout.addEventListener('click', () => {
    clearActiveSession();
    showToast('You have been signed out.', 'info');
    navigateTo('login');
    if (loginGeneralError) {
      loginGeneralError.className = 'general-banner';
      loginGeneralError.textContent = 'You have been signed out.';
      loginGeneralError.classList.remove('hidden');
    }
  });

  // Navigation Links
  linkToRegister.addEventListener('click', (e) => {
    e.preventDefault();
    navigateTo('register');
  });

  linkToLogin.addEventListener('click', (e) => {
    e.preventDefault();
    navigateTo('login');
  });

  // Ensure default demo user exists for convenience if storage is fresh
  function ensureDemoUser() {
    const users = getUsersDB();
    if (users.length === 0) {
      // Pre-seed demo user: Alex Rivera (alex@vaultauth.dev / Demo@2026)
      const salt = 'demoSaltVaultAuth2026';
      hashPassword('Demo@2026', salt).then(hash => {
        const demoUser = {
          id: 'usr_demo_01',
          name: 'Alex Rivera',
          email: 'alex@vaultauth.dev',
          passwordHash: hash,
          salt: salt,
          createdAt: new Date().toISOString()
        };
        saveUsersDB([demoUser]);
      });
    }
  }

  // App Init
  function init() {
    ensureDemoUser();

    // Check if user is already authenticated
    const session = getActiveSession();
    if (session) {
      navigateTo('dashboard');
    } else {
      navigateTo('login');
    }
  }

  init();

})();
