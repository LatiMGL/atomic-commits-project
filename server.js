
require('dotenv').config();

const express = require('express');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
const Database = require('better-sqlite3');
const bcrypt = require('bcrypt');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);

const app = express();
const PORT = 3000;
const DATA_DIR = path.join(__dirname, 'data');

if (!process.env.SESSION_SECRET) {
  throw new Error('SESSION_SECRET is missing from your .env file');
}

fs.mkdirSync(DATA_DIR, { recursive: true });

app.use(express.json({ limit: '10kb' }));

// User database
const db = new Database(path.join(DATA_DIR, 'users.sqlite'));

db.pragma('journal_mode = WAL');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  )
`);

db.exec(`
  CREATE TABLE IF NOT EXISTS payment_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    payer_id TEXT NOT NULL,
    code TEXT NOT NULL,
    amount REAL NOT NULL,
    merchant_wallet TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'approved',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (payer_id, code),
    FOREIGN KEY (user_id) REFERENCES users(id)
  )
`);

const findUsedPaymentCode = db.prepare(`
  SELECT id
  FROM payment_records
  WHERE payer_id = ? AND code = ?
`);

const recordPayment = db.prepare(`
  INSERT INTO payment_records (
    user_id,
    payer_id,
    code,
    amount,
    merchant_wallet,
    status
  )
  VALUES (?, ?, ?, ?, ?, ?)
`);

const getMonthlySpending = db.prepare(`
  SELECT COALESCE(SUM(amount), 0) AS total
  FROM payment_records
  WHERE user_id = ?
    AND status = 'approved'
    AND created_at >= datetime('now', 'start of month')
`);


const createUser = db.prepare(`
  INSERT INTO users (name, email, password_hash)
  VALUES (?, ?, ?)
`);

const findUserByEmail = db.prepare(`
  SELECT id, name, email, password_hash
  FROM users
  WHERE email = ?
`);

const findUserById = db.prepare(`
  SELECT id, name, email
  FROM users
  WHERE id = ?
`);

// Login sessions stored in SQLite
app.use(session({
  name: 'atomic.sid',
  store: new SQLiteStore({
    db: 'sessions.sqlite',
    dir: DATA_DIR
  }),
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    maxAge: 2 * 60 * 60 * 1000
  }
}));

// Require a logged-in user for protected routes
function requireLogin(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({
      error: 'Please log in first'
    });
  }

  next();
}

// Register
app.post('/api/auth/register', async (req, res, next) => {
  try {
    const { name, email, password } = req.body || {};

    if (
      typeof name !== 'string' ||
      typeof email !== 'string' ||
      typeof password !== 'string'
    ) {
      return res.status(400).json({
        error: 'Please provide your name, email and password'
      });
    }

    const cleanName = name.trim();
    const cleanEmail = email.trim().toLowerCase();

    if (cleanName.length < 2 || cleanName.length > 80) {
      return res.status(400).json({
        error: 'Name must be between 2 and 80 characters'
      });
    }

    if (
      cleanEmail.length > 254 ||
      !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail)
    ) {
      return res.status(400).json({
        error: 'Enter a valid email address'
      });
    }

    if (password.length < 8 || Buffer.byteLength(password, 'utf8') > 72) {
      return res.status(400).json({
        error: 'Password must be at least 8 characters and no more than 72 bytes'
      });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    let result;

    try {
      result = createUser.run(cleanName, cleanEmail, passwordHash);
    } catch (error) {
      if (error.code === 'SQLITE_CONSTRAINT_UNIQUE') {
        return res.status(409).json({
          error: 'An account with this email already exists'
        });
      }

      throw error;
    }

    // Regenerate the session after registration
    req.session.regenerate((error) => {
      if (error) return next(error);

      req.session.userId = Number(result.lastInsertRowid);

      req.session.save((saveError) => {
        if (saveError) return next(saveError);

        res.status(201).json({
          message: 'Account created successfully',
          user: {
            id: Number(result.lastInsertRowid),
            name: cleanName,
            email: cleanEmail
          }
        });
      });
    });
  } catch (error) {
    next(error);
  }
});

// Login
app.post('/api/auth/login', async (req, res, next) => {
  try {
    const { email, password } = req.body || {};

    if (typeof email !== 'string' || typeof password !== 'string') {
      return res.status(400).json({
        error: 'Please enter your email and password'
      });
    }

    const user = findUserByEmail.get(email.trim().toLowerCase());

    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
      return res.status(401).json({
        error: 'Invalid email or password'
      });
    }

    // Regenerate the session to help prevent session fixation
    req.session.regenerate((error) => {
      if (error) return next(error);

      req.session.userId = user.id;

      req.session.save((saveError) => {
        if (saveError) return next(saveError);

        res.json({
          message: 'Login successful',
          user: {
            id: user.id,
            name: user.name,
            email: user.email
          }
        });
      });
    });
  } catch (error) {
    next(error);
  }
});

// Check current login
app.get('/api/auth/me', requireLogin, (req, res) => {
  const user = findUserById.get(req.session.userId);

  if (!user) {
    return req.session.destroy(() => {
      res.status(401).json({ error: 'Account not found' });
    });
  }

  res.json({ user });
});

// Logout
app.post('/api/auth/logout', requireLogin, (req, res, next) => {
  req.session.destroy((error) => {
    if (error) return next(error);

    res.clearCookie('atomic.sid', {
      httpOnly: true,
      sameSite: 'lax',
      secure: process.env.NODE_ENV === 'production'
    });

    res.json({ message: 'Logged out successfully' });
  });
});

// Serve the existing website from the same server
app.use(express.static(__dirname, { dotfiles: 'deny' }));

// Existing Atomic Commits payment-code demo
const PAYER_ID = '7K3M';
const DEMO_SECRET = 'atomic-commits-demo-shared-secret';
const WINDOW_MS = 5 * 60 * 1000;
const usedCodes = new Set();

function currentWindow() {
  return Math.floor(Date.now() / WINDOW_MS);
}

function codeForWindow(windowNumber) {
  const digest = crypto
    .createHmac('sha256', DEMO_SECRET)
    .update(`${PAYER_ID}|${windowNumber}`)
    .digest();

  let n = 0;

  for (let i = 0; i < Math.min(digest.length, 6); i++) {
    n = (n * 257 + digest[i]) >>> 0;
  }

  return String(n % 1000000).padStart(6, '0');
}

app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    message: 'Atomic Commits backend is running'
  });
});

app.get('/current-code', requireLogin, (req, res) => {
  const windowNumber = currentWindow();

  res.json({
    payerId: PAYER_ID,
    code: codeForWindow(windowNumber),
    expiresAt: new Date(
      (windowNumber + 1) * WINDOW_MS
    ).toISOString()
  });
});

app.post('/verify', requireLogin, (req, res) => {
  const { payerId, code } = req.body || {};

  if (payerId !== PAYER_ID) {
    return res.status(401).json({
      valid: false,
      reason: 'unknown payer ID'
    });
  }

  if (typeof code !== 'string' || !/^\d{6}$/.test(code)) {
    return res.status(400).json({
      valid: false,
      reason: 'code must contain six digits'
    });
  }

  const expected = codeForWindow(currentWindow());
  const codeKey = `${payerId}:${code}`;

  if (code !== expected) {
    return res.status(401).json({
      valid: false,
      reason: 'code expired or invalid'
    });
  }

  if (usedCodes.has(codeKey)) {
    return res.status(409).json({
      valid: false,
      reason: 'code already used'
    });
  }

  usedCodes.add(codeKey);

  res.json({
    valid: true,
    message: 'Code verified successfully'
  });
});

app.post('/api/payments', requireLogin, (req, res) => {
  const payerId = req.body?.payerId;
  const code = req.body?.code;
  const amount = Number(req.body?.amount);
  const wallet = req.body?.wallet;

  if (payerId !== PAYER_ID) {
    return res.status(400).json({ error: 'Unknown payer ID.' });
  }

  if (typeof code !== 'string' || !/^\d{6}$/.test(code)) {
    return res.status(400).json({ error: 'Invalid authorization code.' });
  }

  if (!Number.isFinite(amount) || amount <= 0 || amount > 50) {
    return res.status(400).json({
      error: 'Amount must be greater than R0 and no more than R50.'
    });
  }

  if (typeof wallet !== 'string' || wallet.trim().length === 0) {
    return res.status(400).json({ error: 'Merchant wallet is required.' });
  }

  const expected = codeForWindow(currentWindow());

  if (code !== expected) {
    return res.status(401).json({
      error: 'Authorization code expired or invalid.'
    });
  }

  const userId = req.session.userId;
  const monthly = getMonthlySpending.get(userId);
  const spent = Number(monthly.total);

  if (spent + amount > 500) {
    return res.status(400).json({
      error: 'The R500 monthly spending limit would be exceeded.'
    });
  }

  try {
    recordPayment.run(
      userId,
      payerId,
      code,
      amount,
      wallet.trim(),
      'approved'
    );
  } catch (error) {
    if (error.code === 'SQLITE_CONSTRAINT_UNIQUE') {
      return res.status(409).json({
        error: 'This authorization code has already been used.'
      });
    }

    throw error;
  }

  return res.json({
    approved: true,
    message: 'Demo payment record created.',
    amount,
    monthlySpent: spent + amount
  });
});


// Return safe error messages to the browser
app.use((error, req, res, next) => {
  console.error(error);

  if (res.headersSent) return next(error);

  res.status(500).json({
    error: 'A server error occurred. Please try again.'
  });
});

app.listen(PORT, () => {
  console.log(`Atomic Commits server running at http://localhost:${PORT}`);
});