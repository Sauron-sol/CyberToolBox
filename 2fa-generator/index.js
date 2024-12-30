const express = require('express');
const { authenticator } = require('otplib');
const QRCode = require('qrcode');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const { v4: uuidv4 } = require('uuid');

const app = express();
const port = 3001;
const db = new sqlite3.Database('accounts.db');

// Database configuration
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS accounts (
    id TEXT PRIMARY KEY,
    name TEXT,
    issuer TEXT,
    secret TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
});

app.use(express.static('public'));
app.use(express.json());

// Generate a secret key
const secret = authenticator.generateSecret();

app.get('/api/secret', (req, res) => {
    res.json({ secret });
});

app.get('/api/code', (req, res) => {
    const code = authenticator.generate(secret);
    res.json({ 
        code,
        timeRemaining: 30 - (Math.floor(Date.now() / 1000) % 30)
    });
});

app.get('/api/qr', async (req, res) => {
    const otpauth = authenticator.keyuri('user', '2FA Demo', secret);
    const qrcode = await QRCode.toDataURL(otpauth);
    res.json({ qrcode });
});

// Route to add a new 2FA account
app.post('/api/accounts', (req, res) => {
  const { name, issuer, secret: existingSecret } = req.body;
  const id = uuidv4();
  const secret = existingSecret || authenticator.generateSecret();
  
  db.run('INSERT INTO accounts (id, name, issuer, secret) VALUES (?, ?, ?, ?)',
    [id, name, issuer, secret],
    (err) => {
      if (err) {
        res.status(500).json({ error: 'Failed to create account' });
        return;
      }
      res.json({ id, secret });
    }
  );
});

// Route to get all accounts
app.get('/api/accounts', (req, res) => {
  db.all('SELECT id, name, issuer FROM accounts', (err, rows) => {
    if (err) {
      res.status(500).json({ error: 'Failed to fetch accounts' });
      return;
    }
    res.json(rows);
  });
});

// Route to get code for a specific account
app.get('/api/accounts/:id/code', (req, res) => {
  db.get('SELECT secret FROM accounts WHERE id = ?', [req.params.id], (err, row) => {
    if (err || !row) {
      res.status(404).json({ error: 'Account not found' });
      return;
    }
    const code = authenticator.generate(row.secret);
    res.json({
      code,
      timeRemaining: 30 - (Math.floor(Date.now() / 1000) % 30)
    });
  });
});

// Route to delete an account
app.delete('/api/accounts/:id', (req, res) => {
  db.run('DELETE FROM accounts WHERE id = ?', [req.params.id], (err) => {
    if (err) {
      res.status(500).json({ error: 'Failed to delete account' });
      return;
    }
    res.json({ success: true });
  });
});

app.listen(port, () => {
    console.log(`2FA generator running at http://localhost:${port}`);
});
