const express = require('express');
const crypto = require('crypto');

const app = express();
const PORT = 3000;

app.use(express.json());
app.use((req, res, next) => {
 const allowedOrigins = [
  'http://127.0.0.1:8080',
  'http://localhost:8080',
  'http://127.0.0.1:5500',
  'http://localhost:5500'
];

  const origin = req.headers.origin;

  if (allowedOrigins.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  }

  res.setHeader(
    'Access-Control-Allow-Methods',
    'GET, POST, OPTIONS'
  );

  res.setHeader(
    'Access-Control-Allow-Headers',
    'Content-Type'
  );

  if (req.method === 'OPTIONS') {
    return res.sendStatus(204);
  }

  next();
});
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
app.get('/current-code', (req, res) => {
  res.json({
    payerId: PAYER_ID,
    code: codeForWindow(currentWindow()),
    expiresAt: new Date(
      (currentWindow() + 1) * WINDOW_MS
    ).toISOString()
  });
});

app.post('/verify', (req, res) => {
  const { payerId, code } = req.body;

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

  const windowNumber = currentWindow();
  const expected = codeForWindow(windowNumber);
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

  return res.json({
    valid: true,
    message: 'Code verified successfully'
  });
});
  


app.listen(PORT, () => {
  console.log(`Atomic Commits server running at http://localhost:${PORT}`);
});