// Qalam PT Scribe — backend proxy
//
// AUTH MODEL: no shared password. Every request must carry a real Google
// access token (from the doctor's own Google sign-in, via a popup on the
// frontend) in the Authorization: Bearer <token> header. This server
// verifies that token with Google on every request, then checks the
// doctors table to confirm that email is an APPROVED doctor at this
// clinic before doing anything. Owner-only actions additionally require
// role = 'owner' in that table.
//
// The one exception is a one-time bootstrap step: OWNER_SECRET (an env
// var) is used ONLY to promote the very first signed-in user to owner,
// since the doctors table starts empty and someone has to be able to
// approve the first person.

const express = require('express');
const cors = require('cors');
const crypto = require('crypto');

const app = express();

const DEEPGRAM_API_KEY = process.env.DEEPGRAM_API_KEY || '';
const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY || '';
const GEMINI_API_KEY = process.env.GEMINI_API_KEY || '';
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || '*';
const SUPABASE_URL = process.env.SUPABASE_URL || '';
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY || '';
const OWNER_SECRET = process.env.OWNER_SECRET || '';

const ALLOWED_ORIGIN_LIST = ALLOWED_ORIGIN.split(',').map(x => x.trim()).filter(Boolean);
app.use(cors({
  origin: ALLOWED_ORIGIN_LIST.includes('*') ? '*' : function (origin, cb) {
    // no Origin header (curl, server-to-server) or a listed origin -> allow
    if (!origin || ALLOWED_ORIGIN_LIST.includes(origin)) return cb(null, true);
    return cb(null, false);
  }
}));
app.use(express.json({ limit: '20mb' }));

// Our own long-lived session tokens, stored in a Supabase table
// (app_sessions: token text primary key, email text, created_at
// timestamptz, expires_at timestamptz). Created once after a real Google
// sign-in; from then on the frontend uses THIS token instead of the
// short-lived Google access token, so staying signed in no longer depends
// on Google's ~1hr token lifetime or on the browser keeping a Google
// session alive.
const APP_SESSION_DAYS = 30;

async function lookupAppSession(token) {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY || !token) return null;
  const url = `${SUPABASE_URL}/rest/v1/app_sessions?token=eq.${encodeURIComponent(token)}`;
  const res = await fetch(url, {
    headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` },
  });
  const rows = await res.json();
  const row = Array.isArray(rows) && rows.length > 0 ? rows[0] : null;
  if (!row) return null;
  if (new Date(row.expires_at).getTime() <= Date.now()) return null;
  return row;
}

async function createAppSession(email) {
  const token = crypto.randomBytes(32).toString('hex');
  const expiresAt = new Date(Date.now() + APP_SESSION_DAYS * 24 * 60 * 60 * 1000).toISOString();
  await fetch(`${SUPABASE_URL}/rest/v1/app_sessions`, {
    method: 'POST',
    headers: {
      apikey: SUPABASE_SERVICE_KEY,
      Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ token, email, expires_at: expiresAt }),
  });
  return token;
}

async function verifyGoogleToken(accessToken) {
  if (!accessToken) return null;
  // Try our own app session token first (the common case once someone has
  // signed in at least once) — this never calls Google at all.
  const session = await lookupAppSession(accessToken);
  if (session) return session.email;
  // Fall back to a real Google access token (first sign-in, or a session
  // that hasn't been issued one yet).
  try {
    const res = await fetch(
      `https://www.googleapis.com/oauth2/v3/tokeninfo?access_token=${encodeURIComponent(accessToken)}`
    );
    if (!res.ok) return null;
    const info = await res.json();
    return info.email || null;
  } catch (err) {
    console.error('Google token verify error:', err);
    return null;
  }
}

async function lookupDoctor(email) {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return null;
  const url = `${SUPABASE_URL}/rest/v1/doctors?email=eq.${encodeURIComponent(email)}`;
  const res = await fetch(url, {
    headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` },
  });
  const rows = await res.json();
  return Array.isArray(rows) && rows.length > 0 ? rows[0] : null;
}

// Manually-added doctors (added by the owner from the roster, before that
// doctor has ever signed in with Google) get a placeholder email at
// @empower.local instead of a real one — they're full, normal team members
// (name + color + approved status), just not yet linked to a Google
// account. This looks one up by name so /api/doctors/checkin can merge a
// real Google sign-in into the existing row instead of creating a
// duplicate.
async function lookupManualDoctorByName(name) {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY || !name) return null;
  const normalized = name.trim();
  if (!normalized) return null;
  const url = `${SUPABASE_URL}/rest/v1/doctors?email=like.*@empower.local&name=ilike.${encodeURIComponent(normalized)}`;
  const res = await fetch(url, {
    headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` },
  });
  const rows = await res.json();
  return Array.isArray(rows) && rows.length > 0 ? rows[0] : null;
}

function extractBearerToken(req) {
  const header = req.header('authorization') || '';
  const match = header.match(/^Bearer\s+(.+)$/i);
  return match ? match[1] : null;
}


// ---- Login activity log (owner can see who opened/signed in, from which device) ----
const loginLogSeen = new Map();
function logDevice(ua) {
  ua = String(ua || '');
  const os = /Android/i.test(ua) ? 'Android' : /iPhone|iPad|iOS/i.test(ua) ? 'iPhone/iPad' : /Windows/i.test(ua) ? 'Windows' : /Mac OS/i.test(ua) ? 'Mac' : /Linux/i.test(ua) ? 'Linux' : 'Other';
  const br = /; wv\)|Version\/[\d.]+ Chrome/i.test(ua) ? 'WebView/App' : /Edg\//i.test(ua) ? 'Edge' : /Firefox/i.test(ua) ? 'Firefox' : /Chrome/i.test(ua) ? 'Chrome' : /Safari/i.test(ua) ? 'Safari' : 'Other';
  return os + ' · ' + br;
}
function logActivity(req, event, email, extra) {
  try {
    if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return;
    const ip = String(req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
    if (event === 'open' || event === 'page') {
      const k = event + '|' + (email || '') + '|' + ip + '|' + (extra || '');
      const now = Date.now();
      if (now - (loginLogSeen.get(k) || 0) < 30 * 60000) return;
      loginLogSeen.set(k, now);
      if (loginLogSeen.size > 5000) loginLogSeen.clear();
    }
    fetch(`${SUPABASE_URL}/rest/v1/login_log`, {
      method: 'POST',
      headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`, 'Content-Type': 'application/json', Prefer: 'return=minimal' },
      body: JSON.stringify({ event, email: email ? String(email).slice(0, 160) : null, ip: ip.slice(0, 60), device: logDevice(req.headers['user-agent']), detail: extra ? String(extra).slice(0, 80) : null }),
    }).catch(() => {});
  } catch (e) { /* never break the request */ }
}

async function requireApprovedDoctor(req, res, next) {
  const token = extractBearerToken(req);
  const email = await verifyGoogleToken(token);
  if (!email) {
    return res.status(401).json({ error: 'Sign in with Google required.' });
  }
  const doctor = await lookupDoctor(email);
  if (!doctor || doctor.status !== 'approved') {
    return res.status(403).json({
      error: doctor ? 'Your access is pending approval from the clinic owner.' : 'You are not registered at this clinic yet.',
    });
  }
  if (doctor.role === 'secretary') {
    return res.status(403).json({ error: 'Secretary accounts only have access to the calendar.' });
  }
  req.doctor = doctor;
  next();
}

// Any approved role (doctor, owner, or secretary) — used for calendar
// endpoints, since secretaries need to view/book appointments too.
async function requireApprovedAny(req, res, next) {
  const token = extractBearerToken(req);
  const email = await verifyGoogleToken(token);
  if (!email) {
    return res.status(401).json({ error: 'Sign in with Google required.' });
  }
  const doctor = await lookupDoctor(email);
  if (!doctor || doctor.status !== 'approved') {
    return res.status(403).json({
      error: doctor ? 'Your access is pending approval from the clinic owner.' : 'You are not registered at this clinic yet.',
    });
  }
  req.doctor = doctor;
  next();
}

async function requireOwnerDoctor(req, res, next) {
  const token = extractBearerToken(req);
  const email = await verifyGoogleToken(token);
  if (!email) {
    return res.status(401).json({ error: 'Sign in with Google required.' });
  }
  const doctor = await lookupDoctor(email);
  if (!doctor || doctor.status !== 'approved' || doctor.role !== 'owner') {
    return res.status(403).json({ error: 'Owner access required.' });
  }
  req.doctor = doctor;
  next();
}

// Owner always has every permission implicitly. Everyone else needs the
// specific permission key set true on their own doctor row.
function hasPermission(doctor, key) {
  if (!doctor) return false;
  if (doctor.role === 'owner') return true;
  return !!(doctor.permissions && doctor.permissions[key] === true);
}

// "Own patients only" mode: a non-owner doctor with permissions.own_patients_only
// sees ONLY appointments/patients/packages that belong to them (doctor_name = their name).
function isOwnOnly(doctor) {
  return !!doctor && doctor.role !== 'owner' && !!(doctor.permissions && doctor.permissions.own_patients_only === true);
}
function ownDoctorName(doctor) { return String(doctor.name || doctor.email || ''); }
async function ownPatientSet(doctor) {
  const url = `${SUPABASE_URL}/rest/v1/appointments?select=patient_name&doctor_name=eq.${encodeURIComponent(ownDoctorName(doctor))}&deleted_at=is.null&limit=5000`;
  const r = await fetch(url, { headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` } });
  const rows = r.ok ? await r.json() : [];
  return new Set((Array.isArray(rows) ? rows : []).map(x => String(x.patient_name || '').trim().toLowerCase()).filter(Boolean));
}
// Guard for /api/appointments/:id... — own-only doctors may only touch their own visits.
async function ownApptGuard(req, res, next) {
  try {
    if (!isOwnOnly(req.doctor)) return next();
    const r = await fetch(`${SUPABASE_URL}/rest/v1/appointments?id=eq.${encodeURIComponent(req.params.id)}&select=doctor_name&limit=1`, { headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` } });
    const rows = r.ok ? await r.json() : [];
    const dn = rows && rows[0] ? String(rows[0].doctor_name || '').trim().toLowerCase() : null;
    if (dn === null || dn !== ownDoctorName(req.doctor).trim().toLowerCase()) return res.status(403).json({ error: 'This visit belongs to another doctor.' });
    next();
  } catch (e) { res.status(500).json({ error: 'Access check failed.' }); }
}
// Guard for /api/packages/:id/... — package must belong to one of the doctor's own patients.
async function ownPkgGuard(req, res, next) {
  try {
    if (!isOwnOnly(req.doctor)) return next();
    const r = await fetch(`${SUPABASE_URL}/rest/v1/packages?id=eq.${encodeURIComponent(req.params.id)}&select=patient_name&limit=1`, { headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` } });
    const rows = r.ok ? await r.json() : [];
    const nm = rows && rows[0] ? String(rows[0].patient_name || '').trim().toLowerCase() : '';
    const set = await ownPatientSet(req.doctor);
    if (!nm || !set.has(nm)) return res.status(403).json({ error: 'This package belongs to another doctor\'s patient.' });
    next();
  } catch (e) { res.status(500).json({ error: 'Access check failed.' }); }
}
// Money ledger (expenses, transfers, other income, withdrawals): owner or dashboard-access only.
function requireFinanceAccess(req, res, next) {
  return requireApprovedAny(req, res, () => {
    const d = req.doctor;
    if (d && (d.role === 'owner' || d.can_view_dashboard === true)) return next();
    res.status(403).json({ error: 'Dashboard/finance access required.' });
  });
}

// Middleware factory: owner passes automatically; anyone else needs the
// named permission set true on their account.
function requireOwnerOrPermission(key) {
  return async function (req, res, next) {
    const token = extractBearerToken(req);
    const email = await verifyGoogleToken(token);
    if (!email) return res.status(401).json({ error: 'Sign in with Google required.' });
    const doctor = await lookupDoctor(email);
    if (!doctor || doctor.status !== 'approved') return res.status(403).json({ error: 'Approved account required.' });
    if (!hasPermission(doctor, key)) return res.status(403).json({ error: `You don't have the "${key}" permission — ask the clinic owner to grant it.` });
    req.doctor = doctor;
    next();
  };
}

// Owner or secretary — used for calendar-color management, since
// secretaries handle the schedule day-to-day but shouldn't approve staff.
async function requireOwnerOrSecretary(req, res, next) {
  const token = extractBearerToken(req);
  const email = await verifyGoogleToken(token);
  if (!email) {
    return res.status(401).json({ error: 'Sign in with Google required.' });
  }
  const doctor = await lookupDoctor(email);
  if (!doctor || doctor.status !== 'approved' || (doctor.role !== 'owner' && doctor.role !== 'secretary')) {
    return res.status(403).json({ error: 'Owner or secretary access required.' });
  }
  req.doctor = doctor;
  next();
}

app.post(
  '/api/transcribe',
  requireApprovedDoctor,
  express.raw({ type: '*/*', limit: '50mb' }),
  async (req, res) => {
    if (!DEEPGRAM_API_KEY) {
      return res.status(500).json({ error: 'Server is missing DEEPGRAM_API_KEY.' });
    }
    try {
      const queryString = req.url.split('?')[1] || '';
      const deepgramUrl = `https://api.deepgram.com/v1/listen?${queryString}`;
      const contentType = req.header('content-type') || 'audio/webm';
      const upstream = await fetch(deepgramUrl, {
        method: 'POST',
        headers: { Authorization: `Token ${DEEPGRAM_API_KEY}`, 'Content-Type': contentType },
        body: req.body,
      });
      const data = await upstream.text();
      res.status(upstream.status).type('application/json').send(data);
    } catch (err) {
      console.error('Transcribe proxy error:', err);
      res.status(500).json({ error: 'Transcription proxy failed: ' + err.message });
    }
  }
);

app.post('/api/ai', requireApprovedDoctor, async (req, res) => {
  const { systemPrompt, userContent, maxTokens, provider } = req.body || {};
  if (!systemPrompt || !userContent) {
    return res.status(400).json({ error: 'Missing systemPrompt or userContent.' });
  }
  const tokens = maxTokens || 4000;
  try {
    if (provider === 'gemini') {
      if (!GEMINI_API_KEY) return res.status(500).json({ error: 'Server is missing GEMINI_API_KEY.' });
      const url = `https://generativelanguage.googleapis.com/v1beta/models/gemini-3.6-flash:generateContent?key=${encodeURIComponent(GEMINI_API_KEY)}`;
      const upstream = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          contents: [{ parts: [{ text: userContent }] }],
          systemInstruction: { parts: [{ text: systemPrompt }] },
          generationConfig: { maxOutputTokens: tokens },
        }),
      });
      const data = await upstream.json();
      if (!upstream.ok) return res.status(upstream.status).json({ error: JSON.stringify(data).slice(0, 300) });
      const text = (data?.candidates?.[0]?.content?.parts || []).map((p) => p.text || '').join('');
      return res.json({ text });
    } else {
      if (!ANTHROPIC_API_KEY) return res.status(500).json({ error: 'Server is missing ANTHROPIC_API_KEY.' });
      const upstream = await fetch('https://api.anthropic.com/v1/messages', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-api-key': ANTHROPIC_API_KEY,
          'anthropic-version': '2023-06-01',
        },
        body: JSON.stringify({
          model: 'claude-sonnet-5',
          max_tokens: tokens,
          system: systemPrompt,
          messages: [{ role: 'user', content: userContent }],
        }),
      });
      const data = await upstream.json();
      if (!upstream.ok) return res.status(upstream.status).json({ error: JSON.stringify(data).slice(0, 300) });
      const text = (data.content || []).filter((b) => b.type === 'text').map((b) => b.text).join('');
      return res.json({ text });
    }
  } catch (err) {
    console.error('AI proxy error:', err);
    res.status(500).json({ error: 'AI proxy failed: ' + err.message });
  }
});

// ---- Clinic-wide settings (key-value store) ----
// Any approved role can read (everyone needs to see the current elevator
// code, for example), but only the owner or secretary can change one.
app.get('/api/settings/:key', requireApprovedAny, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  try {
    const url = `${SUPABASE_URL}/rest/v1/clinic_settings?key=eq.${encodeURIComponent(req.params.key)}`;
    const upstream = await fetch(url, {
      headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` },
    });
    const rows = await upstream.json();
    const row = Array.isArray(rows) && rows.length > 0 ? rows[0] : null;
    res.json({ key: req.params.key, value: row ? row.value : null, updated_at: row ? row.updated_at : null });
  } catch (err) {
    console.error('Settings read error:', err);
    res.status(500).json({ error: 'Failed to read setting: ' + err.message });
  }
});

app.post('/api/settings/:key', requireOwnerOrSecretary, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  const { value } = req.body || {};
  try {
    const url = `${SUPABASE_URL}/rest/v1/clinic_settings`;
    const upstream = await fetch(url, {
      method: 'POST',
      headers: {
        apikey: SUPABASE_SERVICE_KEY,
        Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
        'Content-Type': 'application/json',
        Prefer: 'resolution=merge-duplicates,return=representation',
      },
      body: JSON.stringify({ key: req.params.key, value: value || '', updated_at: new Date().toISOString() }),
    });
    const data = await upstream.json();
    if (!upstream.ok) {
      console.error('Settings write failed:', upstream.status, data);
      return res.status(500).json({ error: 'Could not save setting.' });
    }
    res.json(Array.isArray(data) ? data[0] : data);
  } catch (err) {
    console.error('Settings write error:', err);
    res.status(500).json({ error: 'Failed to save setting: ' + err.message });
  }
});

// ---- GET /api/patients ----
// A quick "have we seen this patient before" lookup, built from past
// appointments (name + their most recent phone number) rather than a
// separate patients table. Used by the frontend to autocomplete the name
// and auto-fill the phone when booking a returning patient again.
app.get('/api/patients', requireApprovedAny, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  try {
    const url = `${SUPABASE_URL}/rest/v1/appointments?select=patient_name,patient_phone,start_time&deleted_at=is.null${isOwnOnly(req.doctor) ? '&doctor_name=eq.' + encodeURIComponent(ownDoctorName(req.doctor)) : ''}&order=start_time.desc&limit=1000`;
    const upstream = await fetch(url, { headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` } });
    const rows = await upstream.json();
    if (!upstream.ok) {
      console.error('Patients GET error:', upstream.status, rows);
      return res.status(500).json({ error: 'Failed to load patients.' });
    }
    const seen = new Map();
    (rows || []).forEach(r => {
      const name = (r.patient_name || '').trim();
      if (!name) return;
      const key = name.toLowerCase();
      if (!seen.has(key)) seen.set(key, { name, phone: r.patient_phone || null });
    });
    res.json(Array.from(seen.values()));
  } catch (err) {
    console.error('Patients GET error:', err);
    res.status(500).json({ error: 'Failed to load patients: ' + err.message });
  }
});

// ---- GET /api/appointments/unpaid-by-patient ----
// A patient doesn't always pay per-session — sometimes one payment covers
// this session plus an earlier unpaid one. This lets the owner see every
// unpaid appointment for that patient name so they can pick which ones a
// single payment settles.
// ---- Package tracking ----
// A package is N pre-paid sessions at a discount (e.g. 6 sessions paid
// once). We track total vs used sessions so the app can tell the owner
// exactly when a patient's package runs out, instead of them having to
// remember/count manually.

// ---- POST /api/packages ---- (create a new package, e.g. right after the purchase payment)
// ---- Patient intake forms ----
// A public form (intake.html) patients fill in before their first visit —
// no login needed to submit. Staff then look it up by name/phone from
// inside a session and pull the answers in with one tap.

// ---- POST /api/intake ---- (public — no auth, the patient submits this themselves)
app.post('/api/intake', async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  const { patientName, patientPhone, chiefComplaint, referralSource } = req.body || {};
  if (!patientName || !patientPhone) return res.status(400).json({ error: 'Missing patientName or patientPhone.' });
  try {
    const insertRes = await fetch(`${SUPABASE_URL}/rest/v1/patient_intake_forms`, {
      method: 'POST',
      headers: {
        apikey: SUPABASE_SERVICE_KEY,
        Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
        'Content-Type': 'application/json',
        Prefer: 'return=representation',
      },
      body: JSON.stringify({
        patient_name: patientName,
        patient_phone: patientPhone,
        chief_complaint: chiefComplaint || '',
        referral_source: referralSource || '',
        matched: false,
      }),
    });
    if (!insertRes.ok) throw new Error(await insertRes.text());
    res.json({ ok: true });
  } catch (err) {
    console.error('Intake submit error:', err);
    res.status(500).json({ error: 'Failed to submit: ' + err.message });
  }
});

// ---- GET /api/intake/unmatched-by-name ---- (staff-side lookup)
// ---- GET /api/intake/all-unmatched ----
// Every team member (not just the owner) can see the full list of
// intake forms nobody has pulled into a session yet.
app.get('/api/intake/all-unmatched', requireApprovedAny, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  try {
    const url = `${SUPABASE_URL}/rest/v1/patient_intake_forms?matched=eq.false&order=submitted_at.desc&limit=50`;
    const upstream = await fetch(url, { headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` } });
    const data = await upstream.text();
    res.status(upstream.status).type('application/json').send(data);
  } catch (err) {
    console.error('All-unmatched intake error:', err);
    res.status(500).json({ error: 'Failed to load: ' + err.message });
  }
});

app.get('/api/intake/unmatched-by-name', requireApprovedAny, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  const { name } = req.query;
  if (!name || name.trim().length < 2) return res.status(400).json({ error: 'Name too short.' });
  try {
    const url = `${SUPABASE_URL}/rest/v1/patient_intake_forms?patient_name=ilike.*${encodeURIComponent(name.trim())}*&matched=eq.false&order=submitted_at.desc&limit=1`;
    const upstream = await fetch(url, { headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` } });
    const rows = await upstream.json();
    res.json((Array.isArray(rows) && rows[0]) || null);
  } catch (err) {
    console.error('Intake lookup error:', err);
    res.status(500).json({ error: 'Lookup failed: ' + err.message });
  }
});

// ---- POST /api/intake/:id/mark-matched ----
app.post('/api/intake/:id/mark-matched', requireApprovedAny, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  try {
    const url = `${SUPABASE_URL}/rest/v1/patient_intake_forms?id=eq.${encodeURIComponent(req.params.id)}`;
    await fetch(url, {
      method: 'PATCH',
      headers: {
        apikey: SUPABASE_SERVICE_KEY,
        Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ matched: true }),
    });
    res.json({ ok: true });
  } catch (err) {
    console.error('Mark-matched error:', err);
    res.status(500).json({ error: 'Failed: ' + err.message });
  }
});

// ---- Doctor unavailability (e.g. "Dr X is off this day") ----
// GET /api/doctor-unavailability?start=X&end=Y — for highlighting the
// month grid; POST to mark a doctor unavailable on a date; DELETE to
// un-mark.
app.get('/api/doctor-unavailability', requireApprovedAny, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  const { start, end } = req.query;
  try {
    let url = `${SUPABASE_URL}/rest/v1/doctor_unavailability?order=date.asc`;
    if (start && end) url += `&date=gte.${encodeURIComponent(start)}&date=lte.${encodeURIComponent(end)}`;
    const upstream = await fetch(url, { headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` } });
    const data = await upstream.text();
    res.status(upstream.status).type('application/json').send(data);
  } catch (err) {
    console.error('Doctor-unavailability GET error:', err);
    res.status(500).json({ error: 'Failed: ' + err.message });
  }
});

// ---- Clinic expenses ----
// ---- GET /api/payroll ---- (?start=ISO&end=ISO) owner-only. Computes each
// doctor's pay for the period using the clinic's actual compensation rules:
// - Partners (Mostafa Farag, Youssef, Omnia Ahmed): 50% of their own
//   collected revenue, PLUS an equal 3-way split of net profit
//   (total collected − total expenses − everyone's payout).
// - Zeinab: fixed 3500 + 75/session. Menna: fixed 4000 + 50/session.
// - Marwa: 50% of her own collected revenue (not a partner, no profit share).
// Matching a doctor_name to a rule is done by a lowercase keyword so small
// spelling variations in doctor_name still resolve correctly.
let PAYROLL_RULES = []; // loaded from the clinic settings (owner edits them in Settings > Clinic)
function matchPayrollRule(doctorName) {
  const lower = (doctorName || '').toLowerCase();
  return PAYROLL_RULES.find((r) => lower.includes(r.keyword)) || null;
}

app.get('/api/payroll', requireOwnerDoctor, async (req, res) => {
  await getClinicConfig();
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  const { start, end } = req.query;
  if (!start || !end) return res.status(400).json({ error: 'Missing start or end.' });
  try {
    const headers = { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` };
    const [apptRes, expRes] = await Promise.all([
      // Fetch everyone (including cancelled) so we can positively identify
      // and skip cancelled ones in JS below — a cancelled appointment
      // earns no revenue and doesn't count as a held session, for any
      // doctor, ever.
      fetch(`${SUPABASE_URL}/rest/v1/appointments?start_time=gte.${encodeURIComponent(start)}&start_time=lte.${encodeURIComponent(end)}&deleted_at=is.null`, { headers }),
      fetch(`${SUPABASE_URL}/rest/v1/expenses?expense_date=gte.${encodeURIComponent(start.slice(0, 10))}&expense_date=lte.${encodeURIComponent(end.slice(0, 10))}`, { headers }),
    ]);
    const appointments = await apptRes.json();
    const expenses = await expRes.json();
    if (!Array.isArray(appointments) || !Array.isArray(expenses)) {
      return res.status(500).json({ error: 'Could not read appointments or expenses for this range.' });
    }

    // Revenue/sessions per doctor: group by the MATCHED PAYROLL RULE first
    // (not the raw doctor_name string) — appointments spell the same
    // doctor's name in slightly different ways ("Dr Menna Azzam" vs
    // "menna azzam" etc.), and grouping by raw string would double-pay a
    // fixed-rate doctor once per spelling variant.
    const revenueByKey = {};
    const sessionsByKey = {};
    const unmatchedNames = {};
    appointments.forEach((ev) => {
      const doctorName = ev.doctor_name || 'Unassigned';
      const rule = matchPayrollRule(doctorName);
      const key = rule ? rule.label : `unmatched:${doctorName.trim().toLowerCase()}`;
      if (!rule) unmatchedNames[key] = doctorName;
      if (ev.status === 'cancelled') return; // a cancelled session earns nothing and doesn't count as held
      sessionsByKey[key] = (sessionsByKey[key] || 0) + 1;
      if (!ev.paid || ev.is_free) return;
      const notes = ev.notes || [];
      let amount = 0;
      notes.forEach((n) => {
        const m = (n.text || '').match(/^paid\s+([\d.,]+)\s*egp\s*\((cash|instapay)\)/i);
        if (m) amount = parseFloat(m[1].replace(/,/g, ''));
      });
      revenueByKey[key] = (revenueByKey[key] || 0) + amount;
    });

    const totalExpenses = expenses.reduce((sum, e) => sum + parseFloat(e.amount || 0), 0);
    const totalRevenue = Object.values(revenueByKey).reduce((a, b) => a + b, 0);

    const rows = [];
    let totalPayout = 0;
    const partnerRows = [];
    Object.keys({ ...revenueByKey, ...sessionsByKey }).forEach((key) => {
      const revenue = revenueByKey[key] || 0;
      const sessionCount = sessionsByKey[key] || 0;
      if (key.startsWith('unmatched:')) {
        // No matching compensation rule for this name — report their
        // revenue for visibility but don't guess a payout formula.
        rows.push({ doctorName: unmatchedNames[key], revenue, sessionCount, basePay: null, formula: 'No payroll rule set for this name', kind: 'unknown' });
        return;
      }
      const rule = PAYROLL_RULES.find((r) => r.label === key);
      let basePay = 0;
      let formula = '';
      if (rule.kind === 'partner') {
        basePay = revenue * (rule.share != null ? rule.share : 0.5);
        formula = Math.round((rule.share != null ? rule.share : 0.5) * 100) + '% of own revenue + equal share of net profit';
      } else if (rule.kind === 'revenue_share') {
        basePay = revenue * (rule.share != null ? rule.share : 0.5);
        formula = Math.round((rule.share != null ? rule.share : 0.5) * 100) + '% of own revenue';
      } else if (rule.kind === 'fixed_plus_rate') {
        basePay = rule.fixed + rule.rate * sessionCount;
        formula = `Fixed ${rule.fixed} + ${rule.rate}/session × ${sessionCount} sessions`;
      }
      totalPayout += basePay;
      const row = { doctorName: rule.label, revenue, sessionCount, basePay, formula, kind: rule.kind };
      rows.push(row);
      if (rule.kind === 'partner') partnerRows.push(row);
    });

    const netProfit = totalRevenue - totalExpenses - totalPayout;
    const profitShare = partnerRows.length > 0 ? netProfit / partnerRows.length : 0;
    partnerRows.forEach((row) => {
      row.profitShare = profitShare;
      row.totalPay = row.basePay + profitShare;
    });
    rows.forEach((row) => {
      if (row.kind !== 'partner') row.totalPay = row.basePay;
    });

    res.json({ rows, totalRevenue, totalExpenses, totalPayout, netProfit, profitShare, partnerCount: partnerRows.length });
  } catch (err) {
    console.error('Payroll error:', err);
    res.status(500).json({ error: 'Failed to compute payroll: ' + err.message });
  }
});

// ---- Internal Cash↔InstaPay transfers ----
// Moving money between the clinic's cash drawer and its InstaPay account
// isn't new revenue and isn't a real expense — it just needs to be
// tracked so Net Cash / Net InstaPay stay accurate.
app.get('/api/transfers', requireFinanceAccess, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  const { start, end } = req.query;
  try {
    let url = `${SUPABASE_URL}/rest/v1/transfers?order=transfer_date.desc`;
    if (start && end) url += `&transfer_date=gte.${encodeURIComponent(start)}&transfer_date=lte.${encodeURIComponent(end)}`;
    const upstream = await fetch(url, { headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` } });
    const data = await upstream.text();
    res.status(upstream.status).type('application/json').send(data);
  } catch (err) {
    console.error('Transfers GET error:', err);
    res.status(500).json({ error: 'Failed: ' + err.message });
  }
});

app.post('/api/transfers', requireFinanceAccess, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  const { amount, fromMethod, toMethod, transferDate, note, doctorName } = req.body || {};
  const trDoctor = String(doctorName || '').replace(/[\u0000-\u001f]/g, ' ').trim().slice(0, 80);
  if (!trDoctor) return res.status(400).json({ error: 'Please write which doctor took or sent the money.' });
  if (!amount || !fromMethod || !toMethod) return res.status(400).json({ error: 'Missing amount, fromMethod, or toMethod.' });
  if (fromMethod === toMethod) return res.status(400).json({ error: 'fromMethod and toMethod must differ.' });
  try {
    const insertRes = await fetch(`${SUPABASE_URL}/rest/v1/transfers`, {
      method: 'POST',
      headers: {
        apikey: SUPABASE_SERVICE_KEY,
        Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
        'Content-Type': 'application/json',
        Prefer: 'return=representation',
      },
      body: JSON.stringify({
        amount,
        from_method: fromMethod,
        to_method: toMethod,
        transfer_date: transferDate || new Date().toISOString().slice(0, 10),
        note: note || null,
        doctor_name: trDoctor,
        created_by: req.doctor.name || req.doctor.email,
      }),
    });
    const inserted = await insertRes.json();
    if (!insertRes.ok) throw new Error(JSON.stringify(inserted));
    res.json(Array.isArray(inserted) ? inserted[0] : inserted);
  } catch (err) {
    console.error('Transfers POST error:', err);
    res.status(500).json({ error: 'Failed: ' + err.message });
  }
});

app.delete('/api/transfers/:id', requireFinanceAccess, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  try {
    await fetch(`${SUPABASE_URL}/rest/v1/transfers?id=eq.${encodeURIComponent(req.params.id)}`, {
      method: 'DELETE',
      headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` },
    });
    res.json({ ok: true });
  } catch (err) {
    console.error('Transfers DELETE error:', err);
    res.status(500).json({ error: 'Failed: ' + err.message });
  }
});

// ---- Other income ----
// Revenue that doesn't come from a patient session — clinic-run events,
// workshops, etc. Tracked the same way as Expenses (description, amount,
// date, payment method) but ADDS to the money totals instead of
// subtracting.
app.get('/api/other-income', requireFinanceAccess, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  const { start, end } = req.query;
  try {
    let url = `${SUPABASE_URL}/rest/v1/other_income?order=income_date.desc`;
    if (start && end) url += `&income_date=gte.${encodeURIComponent(start)}&income_date=lte.${encodeURIComponent(end)}`;
    const upstream = await fetch(url, { headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` } });
    const data = await upstream.text();
    res.status(upstream.status).type('application/json').send(data);
  } catch (err) {
    console.error('Other-income GET error:', err);
    res.status(500).json({ error: 'Failed: ' + err.message });
  }
});

app.post('/api/other-income', requireFinanceAccess, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  const { description, amount, incomeDate, paymentMethod } = req.body || {};
  if (!description || !amount) return res.status(400).json({ error: 'Missing description or amount.' });
  try {
    const insertRes = await fetch(`${SUPABASE_URL}/rest/v1/other_income`, {
      method: 'POST',
      headers: {
        apikey: SUPABASE_SERVICE_KEY,
        Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
        'Content-Type': 'application/json',
        Prefer: 'return=representation',
      },
      body: JSON.stringify({
        description,
        amount,
        income_date: incomeDate || new Date().toISOString().slice(0, 10),
        payment_method: paymentMethod === 'instapay' ? 'instapay' : 'cash',
        created_by: req.doctor.name || req.doctor.email,
      }),
    });
    const inserted = await insertRes.json();
    if (!insertRes.ok) throw new Error(JSON.stringify(inserted));
    res.json(Array.isArray(inserted) ? inserted[0] : inserted);
  } catch (err) {
    console.error('Other-income POST error:', err);
    res.status(500).json({ error: 'Failed: ' + err.message });
  }
});

app.patch('/api/other-income/:id', requireFinanceAccess, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  const { paymentMethod } = req.body || {};
  if (paymentMethod !== 'cash' && paymentMethod !== 'instapay') return res.status(400).json({ error: 'paymentMethod must be cash or instapay.' });
  try {
    const patchRes = await fetch(`${SUPABASE_URL}/rest/v1/other_income?id=eq.${encodeURIComponent(req.params.id)}`, {
      method: 'PATCH',
      headers: {
        apikey: SUPABASE_SERVICE_KEY,
        Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
        'Content-Type': 'application/json',
        Prefer: 'return=representation',
      },
      body: JSON.stringify({ payment_method: paymentMethod }),
    });
    const data = await patchRes.json();
    if (!patchRes.ok) throw new Error(JSON.stringify(data));
    res.json(Array.isArray(data) ? data[0] : data);
  } catch (err) {
    console.error('Other-income PATCH error:', err);
    res.status(500).json({ error: 'Failed: ' + err.message });
  }
});

app.delete('/api/other-income/:id', requireFinanceAccess, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  try {
    await fetch(`${SUPABASE_URL}/rest/v1/other_income?id=eq.${encodeURIComponent(req.params.id)}`, {
      method: 'DELETE',
      headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` },
    });
    res.json({ ok: true });
  } catch (err) {
    console.error('Other-income DELETE error:', err);
    res.status(500).json({ error: 'Failed: ' + err.message });
  }
});

// ---- Doctor withdrawals ----
// Money a doctor/partner takes out of the cash or InstaPay pool as their
// own earnings — tracked separately from general business Expenses so
// "Expenses" stays about clinic operating costs (rent, ads, supplies)
// and this stays about who's already been paid how much of their share.
app.get('/api/doctor-withdrawals', requireFinanceAccess, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  const { start, end } = req.query;
  try {
    let url = `${SUPABASE_URL}/rest/v1/doctor_withdrawals?order=withdrawal_date.desc`;
    if (start && end) url += `&withdrawal_date=gte.${encodeURIComponent(start)}&withdrawal_date=lte.${encodeURIComponent(end)}`;
    const upstream = await fetch(url, { headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` } });
    const data = await upstream.text();
    res.status(upstream.status).type('application/json').send(data);
  } catch (err) {
    console.error('Doctor-withdrawals GET error:', err);
    res.status(500).json({ error: 'Failed: ' + err.message });
  }
});

app.post('/api/doctor-withdrawals', requireFinanceAccess, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  const { doctorName, amount, paymentMethod, withdrawalDate, note } = req.body || {};
  if (!doctorName || !amount) return res.status(400).json({ error: 'Missing doctorName or amount.' });
  try {
    const insertRes = await fetch(`${SUPABASE_URL}/rest/v1/doctor_withdrawals`, {
      method: 'POST',
      headers: {
        apikey: SUPABASE_SERVICE_KEY,
        Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
        'Content-Type': 'application/json',
        Prefer: 'return=representation',
      },
      body: JSON.stringify({
        doctor_name: doctorName,
        amount,
        payment_method: paymentMethod === 'instapay' ? 'instapay' : 'cash',
        withdrawal_date: withdrawalDate || new Date().toISOString().slice(0, 10),
        note: note || null,
        created_by: req.doctor.name || req.doctor.email,
      }),
    });
    const inserted = await insertRes.json();
    if (!insertRes.ok) throw new Error(JSON.stringify(inserted));
    res.json(Array.isArray(inserted) ? inserted[0] : inserted);
  } catch (err) {
    console.error('Doctor-withdrawals POST error:', err);
    res.status(500).json({ error: 'Failed: ' + err.message });
  }
});

// Manual pay adjustments (+/-) for a doctor in a period, e.g. a family member treated at clinic share only
app.get('/api/payroll-adjustments', requireFinanceAccess, async (req, res) => {
  try {
    const { start, end } = req.query;
    if (!/^\d{4}-\d{2}-\d{2}$/.test(String(start)) || !/^\d{4}-\d{2}-\d{2}$/.test(String(end))) return res.status(400).json({ error: 'Bad dates.' });
    const r = await fetch(`${SUPABASE_URL}/rest/v1/payroll_adjustments?adj_date=gte.${start}&adj_date=lte.${end}&order=adj_date.desc`, { headers: bookHeaders() });
    const txt = await r.text();
    if (!r.ok) return res.status(500).json({ error: 'Database error (did you run the payroll adjustments SQL?)' });
    res.type('application/json').send(txt);
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});
app.post('/api/payroll-adjustments', requireFinanceAccess, async (req, res) => {
  try {
    const b = req.body || {}, amount = parseFloat(b.amount);
    const name = clinicText(b.doctorName, 60).trim();
    if (!name || !isFinite(amount) || amount === 0 || Math.abs(amount) > 10000000) return res.status(400).json({ error: 'Missing doctor or amount.' });
    if (!/^\d{4}-\d{2}-\d{2}$/.test(String(b.date || ''))) return res.status(400).json({ error: 'Bad date.' });
    const r = await fetch(`${SUPABASE_URL}/rest/v1/payroll_adjustments`, { method: 'POST', headers: { ...bookHeaders(), 'Content-Type': 'application/json', Prefer: 'return=representation' }, body: JSON.stringify({ doctor_name: name, amount, adj_date: b.date, note: clinicText(b.note, 200).trim() || null, created_by: req.doctor.name || req.doctor.email }) });
    const j = await r.json(); if (!r.ok) throw new Error(JSON.stringify(j));
    res.json(Array.isArray(j) ? j[0] : j);
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});
app.delete('/api/payroll-adjustments/:id', requireFinanceAccess, async (req, res) => {
  try { await fetch(`${SUPABASE_URL}/rest/v1/payroll_adjustments?id=eq.${encodeURIComponent(req.params.id)}`, { method: 'DELETE', headers: bookHeaders() }); res.json({ ok: true }); }
  catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

app.delete('/api/doctor-withdrawals/:id', requireFinanceAccess, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  try {
    await fetch(`${SUPABASE_URL}/rest/v1/doctor_withdrawals?id=eq.${encodeURIComponent(req.params.id)}`, {
      method: 'DELETE',
      headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` },
    });
    res.json({ ok: true });
  } catch (err) {
    console.error('Doctor-withdrawals DELETE error:', err);
    res.status(500).json({ error: 'Failed: ' + err.message });
  }
});

app.get('/api/expenses', requireFinanceAccess, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  const { start, end } = req.query;
  try {
    let url = `${SUPABASE_URL}/rest/v1/expenses?order=expense_date.desc`;
    if (start && end) url += `&expense_date=gte.${encodeURIComponent(start)}&expense_date=lte.${encodeURIComponent(end)}`;
    const upstream = await fetch(url, { headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` } });
    const data = await upstream.text();
    res.status(upstream.status).type('application/json').send(data);
  } catch (err) {
    console.error('Expenses GET error:', err);
    res.status(500).json({ error: 'Failed: ' + err.message });
  }
});

app.post('/api/expenses', requireFinanceAccess, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  const { description, amount, expenseDate, paymentMethod } = req.body || {};
  if (!description || !amount) return res.status(400).json({ error: 'Missing description or amount.' });
  try {
    const insertRes = await fetch(`${SUPABASE_URL}/rest/v1/expenses`, {
      method: 'POST',
      headers: {
        apikey: SUPABASE_SERVICE_KEY,
        Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
        'Content-Type': 'application/json',
        Prefer: 'return=representation',
      },
      body: JSON.stringify({
        description,
        amount,
        expense_date: expenseDate || new Date().toISOString().slice(0, 10),
        payment_method: paymentMethod === 'instapay' ? 'instapay' : 'cash',
        created_by: req.doctor.name || req.doctor.email,
      }),
    });
    const inserted = await insertRes.json();
    if (!insertRes.ok) throw new Error(JSON.stringify(inserted));
    res.json(Array.isArray(inserted) ? inserted[0] : inserted);
  } catch (err) {
    console.error('Expenses POST error:', err);
    res.status(500).json({ error: 'Failed: ' + err.message });
  }
});

app.patch('/api/expenses/:id', requireFinanceAccess, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  const { paymentMethod } = req.body || {};
  if (paymentMethod !== 'cash' && paymentMethod !== 'instapay') return res.status(400).json({ error: 'paymentMethod must be cash or instapay.' });
  try {
    const patchRes = await fetch(`${SUPABASE_URL}/rest/v1/expenses?id=eq.${encodeURIComponent(req.params.id)}`, {
      method: 'PATCH',
      headers: {
        apikey: SUPABASE_SERVICE_KEY,
        Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
        'Content-Type': 'application/json',
        Prefer: 'return=representation',
      },
      body: JSON.stringify({ payment_method: paymentMethod }),
    });
    const data = await patchRes.json();
    if (!patchRes.ok) throw new Error(JSON.stringify(data));
    res.json(Array.isArray(data) ? data[0] : data);
  } catch (err) {
    console.error('Expenses PATCH error:', err);
    res.status(500).json({ error: 'Failed: ' + err.message });
  }
});

app.delete('/api/expenses/:id', requireFinanceAccess, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  try {
    await fetch(`${SUPABASE_URL}/rest/v1/expenses?id=eq.${encodeURIComponent(req.params.id)}`, {
      method: 'DELETE',
      headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` },
    });
    res.json({ ok: true });
  } catch (err) {
    console.error('Expenses DELETE error:', err);
    res.status(500).json({ error: 'Failed: ' + err.message });
  }
});

// ---- Day reminders ----
// A lightweight "don't forget to book this patient" note pinned to a
// day — NOT a real appointment (no time yet). Owner/staff schedule the
// actual appointment later and remove the reminder.
app.get('/api/day-reminders', requireApprovedAny, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  const { start, end } = req.query;
  try {
    let url = `${SUPABASE_URL}/rest/v1/day_reminders?order=reminder_date.asc`;
    if (start && end) url += `&reminder_date=gte.${encodeURIComponent(start)}&reminder_date=lte.${encodeURIComponent(end)}`;
    const upstream = await fetch(url, { headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` } });
    const data = await upstream.text();
    res.status(upstream.status).type('application/json').send(data);
  } catch (err) {
    console.error('Day-reminders GET error:', err);
    res.status(500).json({ error: 'Failed: ' + err.message });
  }
});

app.post('/api/day-reminders', requireApprovedAny, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  const { patientName, patientPhone, reminderDate, note } = req.body || {};
  if (!patientName || !reminderDate) return res.status(400).json({ error: 'Missing patientName or reminderDate.' });
  try {
    const insertRes = await fetch(`${SUPABASE_URL}/rest/v1/day_reminders`, {
      method: 'POST',
      headers: {
        apikey: SUPABASE_SERVICE_KEY,
        Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
        'Content-Type': 'application/json',
        Prefer: 'return=representation',
      },
      body: JSON.stringify({
        patient_name: patientName,
        patient_phone: patientPhone || null,
        reminder_date: reminderDate,
        note: note || null,
        created_by: req.doctor.name || req.doctor.email,
      }),
    });
    const inserted = await insertRes.json();
    if (!insertRes.ok) throw new Error(JSON.stringify(inserted));
    res.json(Array.isArray(inserted) ? inserted[0] : inserted);
  } catch (err) {
    console.error('Day-reminders POST error:', err);
    res.status(500).json({ error: 'Failed: ' + err.message });
  }
});

app.delete('/api/day-reminders/:id', requireApprovedAny, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  try {
    await fetch(`${SUPABASE_URL}/rest/v1/day_reminders?id=eq.${encodeURIComponent(req.params.id)}`, {
      method: 'DELETE',
      headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` },
    });
    res.json({ ok: true });
  } catch (err) {
    console.error('Day-reminders DELETE error:', err);
    res.status(500).json({ error: 'Failed: ' + err.message });
  }
});

app.post('/api/doctor-unavailability', requireApprovedAny, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  const { doctorName, date } = req.body || {};
  if (!doctorName || !date) return res.status(400).json({ error: 'Missing doctorName or date.' });
  try {
    const insertRes = await fetch(`${SUPABASE_URL}/rest/v1/doctor_unavailability`, {
      method: 'POST',
      headers: {
        apikey: SUPABASE_SERVICE_KEY,
        Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
        'Content-Type': 'application/json',
        Prefer: 'return=representation,resolution=merge-duplicates',
      },
      body: JSON.stringify({ doctor_name: doctorName, date }),
    });
    const inserted = await insertRes.json();
    if (!insertRes.ok) throw new Error(JSON.stringify(inserted));
    res.json(Array.isArray(inserted) ? inserted[0] : inserted);
  } catch (err) {
    console.error('Doctor-unavailability POST error:', err);
    res.status(500).json({ error: 'Failed: ' + err.message });
  }
});

app.delete('/api/doctor-unavailability/:id', requireApprovedAny, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  try {
    await fetch(`${SUPABASE_URL}/rest/v1/doctor_unavailability?id=eq.${encodeURIComponent(req.params.id)}`, {
      method: 'DELETE',
      headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` },
    });
    res.json({ ok: true });
  } catch (err) {
    console.error('Doctor-unavailability DELETE error:', err);
    res.status(500).json({ error: 'Failed: ' + err.message });
  }
});

// ---- TimeTree / generic iCal import ----
// TimeTree's own "Share calendar" feature gives a read-only iCal
// (webcal://... or https://...ics) feed — this is the only officially
// supported way to get data out of TimeTree (their real API was shut
// down in Dec 2023). We fetch + parse that feed server-side (avoids
// CORS) and hand back a plain list of events for the owner to review
// before anything is imported — nothing is written automatically.

function parseIcs(icsText) {
  // Unfold lines per RFC 5545 (a line starting with a space/tab is a
  // continuation of the previous line).
  const rawLines = icsText.split(/\r\n|\n|\r/);
  const lines = [];
  rawLines.forEach((line) => {
    if ((line.startsWith(' ') || line.startsWith('\t')) && lines.length > 0) {
      lines[lines.length - 1] += line.slice(1);
    } else {
      lines.push(line);
    }
  });

  function parseIcsDate(val) {
    // Handles YYYYMMDD or YYYYMMDDTHHMMSS(Z)
    const m = val.match(/^(\d{4})(\d{2})(\d{2})(T(\d{2})(\d{2})(\d{2})Z?)?$/);
    if (!m) return null;
    const [, y, mo, d, , h, mi, s] = m;
    if (h === undefined) return `${y}-${mo}-${d}`; // all-day, date only
    return new Date(Date.UTC(+y, +mo - 1, +d, +h, +mi, +s)).toISOString();
  }

  const events = [];
  let current = null;
  lines.forEach((line) => {
    if (line === 'BEGIN:VEVENT') {
      current = {};
    } else if (line === 'END:VEVENT') {
      if (current && current.summary) events.push(current);
      current = null;
    } else if (current) {
      const idx = line.indexOf(':');
      if (idx === -1) return;
      const rawKey = line.slice(0, idx);
      const key = rawKey.split(';')[0];
      const val = line.slice(idx + 1);
      if (key === 'SUMMARY') current.summary = val.replace(/\\,/g, ',').replace(/\\n/gi, ' ').trim();
      else if (key === 'DTSTART') current.start = parseIcsDate(val);
      else if (key === 'DTEND') current.end = parseIcsDate(val);
      else if (key === 'LOCATION') current.location = val;
      else if (key === 'UID') current.uid = val;
    }
  });
  return events;
}

// ---- POST /api/timetree/preview ---- ({ icalUrl }) — read-only, parses and returns events
// ---- POST /api/timetree/parse-screenshot ---- ({ imageBase64, mediaType }) —
// uses Claude's vision to read a TimeTree (or any calendar) screenshot and
// extract a list of events, in the same shape /preview returns, so the
// frontend can reuse the same review/select/import flow either way.
app.post('/api/timetree/parse-screenshot', requireApprovedAny, async (req, res) => {
  if (!ANTHROPIC_API_KEY) return res.status(500).json({ error: 'Server is missing ANTHROPIC_API_KEY.' });
  const { imageBase64, mediaType } = req.body || {};
  if (!imageBase64) return res.status(400).json({ error: 'Missing imageBase64.' });
  try {
    const todayStr = new Date().toISOString().slice(0, 10);
    const upstream = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify({
        model: 'claude-sonnet-5',
        max_tokens: 2000,
        system: `You read screenshots of calendar apps (like TimeTree) and extract each visible appointment/event as JSON. Today's date is ${todayStr}. Each event has a colored bar or dot next to it — classify that color as exactly one of: "pink" (pink/magenta/light red), "green", "blue", "yellow" (yellow/gold/orange), "purple" (purple/lavender), "black" (black/very dark), "gray" (medium gray), or "unknown" if you can't tell. Respond with ONLY a raw JSON array, no markdown fences, no commentary. Each item: {"summary": "<patient or event name>", "start": "<ISO 8601 datetime, your best inference of the full date+time using today's date as reference for any relative/partial dates shown>", "color": "<one of the color words above>"}. If a year isn't shown, assume the current or nearest upcoming year. If you can't confidently read an item, skip it rather than guessing.`,
        messages: [{
          role: 'user',
          content: [
            { type: 'image', source: { type: 'base64', media_type: mediaType || 'image/jpeg', data: imageBase64 } },
            { type: 'text', text: 'Extract every appointment/event visible in this calendar screenshot as the JSON array described.' },
          ],
        }],
      }),
    });
    const data = await upstream.json();
    if (!upstream.ok) return res.status(upstream.status).json({ error: JSON.stringify(data).slice(0, 300) });
    const text = (data.content || []).filter((b) => b.type === 'text').map((b) => b.text).join('').trim();
    let events = [];
    try {
      const cleaned = text.replace(/^```json\s*/i, '').replace(/```\s*$/i, '').trim();
      events = JSON.parse(cleaned);
    } catch (parseErr) {
      console.error('Could not parse Claude screenshot response as JSON:', text);
      return res.status(500).json({ error: 'Could not read structured events from that screenshot — try a clearer photo.' });
    }
    if (!Array.isArray(events)) events = [];
    res.json({ count: events.length, events });
  } catch (err) {
    console.error('TimeTree screenshot parse error:', err);
    res.status(500).json({ error: 'Failed to read the screenshot: ' + err.message });
  }
});

app.post('/api/timetree/preview', requireApprovedAny, async (req, res) => {
  const { icalUrl, icsText } = req.body || {};
  if (!icalUrl && !icsText) return res.status(400).json({ error: 'Provide either icalUrl or icsText.' });
  try {
    let text = icsText;
    if (!text) {
      const fetchUrl = icalUrl.replace(/^webcal:\/\//i, 'https://');
      const upstream = await fetch(fetchUrl);
      if (!upstream.ok) throw new Error(`Could not fetch the calendar (HTTP ${upstream.status}). Double check the link.`);
      text = await upstream.text();
    }
    const events = parseIcs(text);
    // Only future/recent events — no point reviewing years of history.
    const cutoff = Date.now() - 1000 * 60 * 60 * 24 * 30; // last 30 days onward
    const filtered = events.filter((e) => {
      if (!e.start) return false;
      const t = new Date(e.start).getTime();
      return !isNaN(t) && t >= cutoff;
    }).sort((a, b) => new Date(a.start) - new Date(b.start));
    res.json({ count: filtered.length, events: filtered.slice(0, 300) });
  } catch (err) {
    console.error('TimeTree preview error:', err);
    res.status(500).json({ error: 'Failed to read that calendar: ' + err.message });
  }
});

// ---- POST /api/timetree/import ---- ({ events: [{summary, start, end, patientName?, doctorName?}] })
app.post('/api/timetree/import', requireApprovedAny, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  const { events } = req.body || {};
  if (!Array.isArray(events) || events.length === 0) return res.status(400).json({ error: 'No events to import.' });
  let imported = 0;
  let phoneFilled = 0;
  const errors = [];
  const phoneCache = {}; // patientName (lowercased, trimmed) -> phone or null, so we only look each name up once per batch
  for (const ev of events) {
    const patientName = (ev.patientName || ev.summary || '').trim();
    if (!patientName || !ev.start) { errors.push(`Skipped one event — missing name or date.`); continue; }
    const start = ev.start;
    const end = ev.end || new Date(new Date(start).getTime() + 30 * 60000).toISOString();
    try {
      // TimeTree screenshots never show a phone number, so look up this
      // patient's most recent one from their own appointment history
      // (if they've been in before) rather than leaving it blank.
      const cacheKey = patientName.toLowerCase();
      let patientPhone = ev.patientPhone || null;
      if (!patientPhone) {
        if (cacheKey in phoneCache) {
          patientPhone = phoneCache[cacheKey];
        } else {
          const phoneUrl = `${SUPABASE_URL}/rest/v1/appointments?patient_name=eq.${encodeURIComponent(patientName)}&patient_phone=not.is.null&deleted_at=is.null&select=patient_phone&order=start_time.desc&limit=1`;
          const phoneRes = await fetch(phoneUrl, { headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` } });
          const phoneRows = await phoneRes.json();
          patientPhone = (Array.isArray(phoneRows) && phoneRows[0] && phoneRows[0].patient_phone) || null;
          phoneCache[cacheKey] = patientPhone;
        }
        if (patientPhone) phoneFilled++;
      }
      const insertRes = await fetch(`${SUPABASE_URL}/rest/v1/appointments`, {
        method: 'POST',
        headers: {
          apikey: SUPABASE_SERVICE_KEY,
          Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          patient_name: patientName,
          patient_phone: patientPhone,
          start_time: start,
          end_time: end,
          doctor_name: ev.doctorName || req.doctor.name || req.doctor.email,
          doctor_color: ev.doctorColor || req.doctor.color || null,
        }),
      });
      if (insertRes.ok) imported++;
      else errors.push(`Failed to import "${patientName}".`);
    } catch (e) {
      errors.push(`Failed to import "${patientName}": ${e.message}`);
    }
  }
  res.json({ imported, errors, phoneFilled });
});

// ---- Package duplicate protection helpers ----
// Compare patient names loosely: ignore case, and the "el"/"al" prefix.
const pkgCreateLocks = new Set();
function normalizePkgName(s) {
  return String(s || '').trim().toLowerCase().replace(/\s+/g, ' ').split(' ')
    .map(w => w.replace(/^(el|al)(?=[a-z]{3,})/, '')).join(' ');
}
function samePatientLoosely(a, b) {
  const x = normalizePkgName(a), y = normalizePkgName(b);
  if (!x || !y) return false;
  return x === y || (x.length >= 3 && y.length >= 3 && (x.includes(y) || y.includes(x)));
}

app.post('/api/packages', requireApprovedAny, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  if (req.doctor.role === 'doctor' && !hasPermission(req.doctor, 'view_payments')) {
    return res.status(403).json({ error: 'You don\'t have permission to record payments — ask the clinic owner to grant it.' });
  }
  const { patientName, totalSessions, startingUsed, totalPrice, amountPaid } = req.body || {};
  if (!patientName || !totalSessions || totalSessions < 1) return res.status(400).json({ error: 'Missing patientName or totalSessions.' });
  const used = Math.max(0, Math.min(totalSessions, parseInt(startingUsed, 10) || 0));
  if (used > 0 && req.doctor.role === 'doctor' && !hasPermission(req.doctor, 'register_packages')) {
    return res.status(403).json({ error: 'You don\'t have permission to backfill an existing package — ask the clinic owner to grant it.' });
  }
  // Only one package creation per patient at a time (stops double taps).
  const lockKey = normalizePkgName(patientName);
  if (pkgCreateLocks.has(lockKey)) {
    return res.status(409).json({ code: 'PACKAGE_JUST_CREATED', error: 'A package for this patient is being created right now — wait a moment and check the Payment tab before trying again.' });
  }
  pkgCreateLocks.add(lockKey);
  try {
    // A second package for the same patient within 3 minutes = double tap.
    try {
      const listRes = await fetch(`${SUPABASE_URL}/rest/v1/packages?select=id,patient_name,created_at&order=created_at.desc&limit=200`, {
        headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` },
      });
      const recent = listRes.ok ? await listRes.json() : [];
      const justCreated = (Array.isArray(recent) ? recent : []).find(p => normalizePkgName(p.patient_name) === lockKey && (Date.now() - new Date(p.created_at).getTime()) < 3 * 60 * 1000);
      if (justCreated) {
        return res.status(409).json({ code: 'PACKAGE_JUST_CREATED', error: `A package for "${justCreated.patient_name}" was created a moment ago, so a second one was NOT created (probably a double tap). Check the Payment tab.` });
      }
    } catch (e) { console.error('Duplicate check failed (continuing):', e.message); }
    const insertRes = await fetch(`${SUPABASE_URL}/rest/v1/packages`, {
      method: 'POST',
      headers: {
        apikey: SUPABASE_SERVICE_KEY,
        Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
        'Content-Type': 'application/json',
        Prefer: 'return=representation',
      },
      body: JSON.stringify({
        patient_name: patientName,
        total_sessions: totalSessions,
        used_sessions: used,
        total_price: (totalPrice === undefined || totalPrice === null || totalPrice === '') ? null : Number(totalPrice),
        amount_paid: Number(amountPaid) || 0,
        created_by: req.doctor.email,
      }),
    });
    const inserted = await insertRes.json();
    if (!insertRes.ok) throw new Error(JSON.stringify(inserted));
    res.json(Array.isArray(inserted) ? inserted[0] : inserted);
  } catch (err) {
    console.error('Create package error:', err);
    res.status(500).json({ error: 'Failed to create package: ' + err.message });
  } finally {
    pkgCreateLocks.delete(lockKey);
  }
});

// ---- GET /api/packages/active-by-patient ---- (find this patient's not-yet-finished package, if any)
// ---- GET /api/appointments/no-show-count ----
// Counts how many times this patient has been marked "no_show" — the
// frontend only allows marking no_show on an appointment that already
// had a "Confirmed" note, so every row counted here was a confirmed
// appointment the patient still didn't attend.
app.get('/api/appointments/no-show-count', requireApprovedAny, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  const { patientName } = req.query;
  if (!patientName) return res.status(400).json({ error: 'Missing patientName.' });
  try {
    const url = `${SUPABASE_URL}/rest/v1/appointments?patient_name=eq.${encodeURIComponent(patientName)}&status=eq.no_show&deleted_at=is.null${isOwnOnly(req.doctor) ? '&doctor_name=eq.' + encodeURIComponent(ownDoctorName(req.doctor)) : ''}&select=id`;
    const upstream = await fetch(url, { headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`, Prefer: 'count=exact' } });
    const rows = await upstream.json();
    res.json({ count: Array.isArray(rows) ? rows.length : 0 });
  } catch (err) {
    console.error('No-show count error:', err);
    res.status(500).json({ error: 'Failed to count no-shows: ' + err.message });
  }
});

app.get('/api/packages/active-by-patient', requireApprovedAny, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  const { patientName } = req.query;
  if (!patientName) return res.status(400).json({ error: 'Missing patientName.' });
  try {
    if (isOwnOnly(req.doctor)) {
      const mine = await ownPatientSet(req.doctor);
      if (!mine.has(String(patientName).trim().toLowerCase())) return res.json(null);
    }
    // Oldest-first (FIFO): if a patient buys a new package while an older
    // one still has sessions left, the older package must keep being the
    // one sessions get consumed from until it's finished — otherwise its
    // leftover sessions would get stranded forever behind the new one.
    // ilike WITHOUT wildcards = whole-name match that ignores upper/lower case
    // ("Adham Tantawy" and "adham tantawy" are the same patient).
    const safeName = String(patientName).trim().replace(/\*/g, '').replace(/[\\%_]/g, c => '\\' + c);
    const url = `${SUPABASE_URL}/rest/v1/packages?patient_name=ilike.${encodeURIComponent(safeName)}&order=created_at.asc`;
    const upstream = await fetch(url, { headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` } });
    const rows = await upstream.json();
    const active = (Array.isArray(rows) ? rows : []).find(p => p.used_sessions < p.total_sessions);
    if (active) return res.json(active);
    if (req.query.allowSimilar === '1') {
      const allRes = await fetch(`${SUPABASE_URL}/rest/v1/packages?order=created_at.asc`, { headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` } });
      const all = await allRes.json();
      const similarActive = (Array.isArray(all) ? all : []).filter(p => p.used_sessions < p.total_sessions && samePatientLoosely(p.patient_name, patientName));
      const distinctNames = new Set(similarActive.map(p => normalizePkgName(p.patient_name)));
      if (similarActive.length > 0 && distinctNames.size === 1) {
        return res.json({ ...similarActive[0], matched_by_similar_name: true });
      }
    }
    res.json(null);
  } catch (err) {
    console.error('Active package lookup error:', err);
    res.status(500).json({ error: 'Failed to look up package: ' + err.message });
  }
});

// ---- GET /api/packages/owed ---- (every package with money still owed — finished or not — with the patient's phone)
app.get('/api/packages/owed', requireApprovedAny, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  try {
    const headers = { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` };
    const pkgRes = await fetch(`${SUPABASE_URL}/rest/v1/packages?total_price=not.is.null&order=created_at.asc`, { headers });
    const rows = await pkgRes.json();
    if (!pkgRes.ok) throw new Error(JSON.stringify(rows));
    // PostgREST can't compare two columns, so the "still owed" test happens here.
    const ownSet = isOwnOnly(req.doctor) ? await ownPatientSet(req.doctor) : null;
    const owed = (Array.isArray(rows) ? rows : [])
      .filter(p => !ownSet || ownSet.has(String(p.patient_name || '').trim().toLowerCase()))
      .map(p => ({ ...p, owed: Number(p.total_price) - Number(p.amount_paid || 0) }))
      .filter(p => p.owed > 0.5);
    const phoneRes = await fetch(`${SUPABASE_URL}/rest/v1/appointments?select=patient_name,patient_phone&patient_phone=not.is.null&deleted_at=is.null&order=start_time.desc&limit=3000`, { headers });
    const phoneRows = phoneRes.ok ? await phoneRes.json() : [];
    const phoneByName = new Map();
    (Array.isArray(phoneRows) ? phoneRows : []).forEach(r => {
      const k = (r.patient_name || '').trim().toLowerCase();
      if (k && r.patient_phone && !phoneByName.has(k)) phoneByName.set(k, r.patient_phone);
    });
    owed.sort((a, b) => b.owed - a.owed);
    res.json(owed.map(p => ({ ...p, patient_phone: phoneByName.get((p.patient_name || '').trim().toLowerCase()) || null })));
  } catch (err) {
    console.error('Owed packages list error:', err);
    res.status(500).json({ error: 'Failed: ' + err.message });
  }
});

// ---- GET /api/packages/active ---- (every unfinished package, with the patient's phone, for the policy-sent check)
// ---- GET /api/packages/duplicate-report ----
// Finds patients who have 2+ packages (at least one unfinished) and tells the
// story of each: when every package was created, how many visits are really
// marked as "package" on the calendar, and what the counts should be if the
// oldest package is filled first (the app's own rule).
app.get('/api/packages/duplicate-report', requireApprovedAny, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  try {
    const headers = { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` };
    const pkgRes = await fetch(`${SUPABASE_URL}/rest/v1/packages?order=created_at.asc`, { headers });
    const pkgs = await pkgRes.json();
    if (!pkgRes.ok) throw new Error(JSON.stringify(pkgs));
    const ownSet = isOwnOnly(req.doctor) ? await ownPatientSet(req.doctor) : null;
    const all = (Array.isArray(pkgs) ? pkgs : []).filter(p => !ownSet || ownSet.has(String(p.patient_name || '').trim().toLowerCase()));
    // group packages of the same patient (loose name match)
    const groups = [];
    all.forEach(p => {
      const g = groups.find(gr => gr.some(q => samePatientLoosely(q.patient_name, p.patient_name)));
      if (g) g.push(p); else groups.push([p]);
    });
    // Only SUSPICIOUS cases: a normal renewal (old package finished, new one started) is NOT a duplicate.
    // Suspicious = 2+ unfinished packages at the same time, OR two packages created within 10 minutes.
    const dupGroups = groups.filter(g => {
      if (g.length < 2) return false;
      const unfinished = g.filter(p => p.used_sessions < p.total_sessions).length;
      if (unfinished >= 2) return true;
      const times = g.map(p => new Date(p.created_at).getTime()).sort((x, y) => x - y);
      for (let i = 1; i < times.length; i++) if (times[i] - times[i - 1] < 10 * 60000) return true;
      return false;
    });
    if (dupGroups.length === 0) return res.json([]);
    const apRes = await fetch(`${SUPABASE_URL}/rest/v1/appointments?select=id,patient_name,start_time,status,notes&notes=not.is.null&deleted_at=is.null&status=neq.cancelled&order=start_time.asc&limit=6000`, { headers });
    const apRows = apRes.ok ? await apRes.json() : [];
    const appts = Array.isArray(apRows) ? apRows : [];
    const isPkgNote = t => /^covered by package/i.test(t) || /^paid\s+[\d.,]+\s*egp\s*\((cash|instapay)\)[^\n]*starts a package of/i.test(t) || /^nothing paid yet[^\n]*starts a package of/i.test(t);
    const out = dupGroups.map(g => {
      const visits = appts.filter(a => g.some(p => samePatientLoosely(p.patient_name, a.patient_name)) &&
        (Array.isArray(a.notes) ? a.notes : []).some(n => isPkgNote(String((n && n.text) || '').trim())));
      const tagged = visits.length;
      let remaining = tagged;
      const packages = g.map((p, i) => {
        const take = Math.min(remaining, p.total_sessions);
        remaining -= take;
        const prev = i > 0 ? g[i - 1] : null;
        const gapMinutes = prev ? Math.round((new Date(p.created_at) - new Date(prev.created_at)) / 60000) : null;
        return {
          id: p.id, patient_name: p.patient_name, total_sessions: p.total_sessions, used_sessions: p.used_sessions,
          total_price: p.total_price, amount_paid: p.amount_paid, created_at: p.created_at,
          gap_minutes: gapMinutes, suggested_used: take,
        };
      });
      const sumUsed = g.reduce((a, p) => a + p.used_sessions, 0);
      const noMoney = g.every(p => !(Number(p.total_price) > 0) && !(Number(p.amount_paid) > 0));
      const hints = [];
      if (packages.some(p => p.gap_minutes !== null && p.gap_minutes < 3)) hints.push('Two packages were created within minutes of each other — most likely a double tap.');
      else if (noMoney) hints.push('No price or payment on any of them — most likely the same package was registered twice.');
      else {
        const older = g[0];
        const newerPaid = g.slice(1).some(p => Number(p.amount_paid) > 0 || Number(p.total_price) > 0);
        if (older.used_sessions < older.total_sessions && newerPaid) hints.push('A newer package was sold while the older one was never finished in the app — often the older sessions were not tapped as "Package".');
      }
      if (tagged > 0 && sumUsed > tagged) hints.push(`The app counted ${sumUsed} sessions but only ${tagged} visit${tagged === 1 ? ' is' : 's are'} marked as package on the calendar — sessions may be counted twice.`);
      if (tagged > sumUsed) hints.push(`${tagged} visits are marked as package on the calendar but the app counted only ${sumUsed} — some sessions were not counted.`);
      if (hints.length === 0) hints.push('Counts match the calendar. If the patient really bought a second package, this is normal.');
      return { names: [...new Set(g.map(p => p.patient_name))], visits_marked_package: tagged, sum_used: sumUsed, hints, packages,
        visit_dates: visits.slice(-12).map(a => a.start_time) };
    });
    res.json(out);
  } catch (err) {
    console.error('Duplicate report error:', err);
    res.status(500).json({ error: 'Failed: ' + err.message });
  }
});

app.get('/api/packages/active', requireApprovedAny, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  try {
    const headers = { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` };
    const pkgRes = await fetch(`${SUPABASE_URL}/rest/v1/packages?order=created_at.asc`, { headers });
    const rows = await pkgRes.json();
    if (!pkgRes.ok) throw new Error(JSON.stringify(rows));
    const ownSet = isOwnOnly(req.doctor) ? await ownPatientSet(req.doctor) : null;
    const active = (Array.isArray(rows) ? rows : []).filter(p => p.used_sessions < p.total_sessions && (!ownSet || ownSet.has(String(p.patient_name || '').trim().toLowerCase())));
    const phoneRes = await fetch(`${SUPABASE_URL}/rest/v1/appointments?select=patient_name,patient_phone&patient_phone=not.is.null&deleted_at=is.null&order=start_time.desc&limit=3000`, { headers });
    const phoneRows = phoneRes.ok ? await phoneRes.json() : [];
    const phoneByName = new Map();
    (Array.isArray(phoneRows) ? phoneRows : []).forEach(r => {
      const k = (r.patient_name || '').trim().toLowerCase();
      if (k && r.patient_phone && !phoneByName.has(k)) phoneByName.set(k, r.patient_phone);
    });
    res.json(active.map(p => ({ ...p, patient_phone: phoneByName.get((p.patient_name || '').trim().toLowerCase()) || null })));
  } catch (err) {
    console.error('Active packages list error:', err);
    res.status(500).json({ error: 'Failed: ' + err.message });
  }
});

// ---- GET /api/packages/dormant ---- (patients with sessions left on an unfinished package who haven't been in for a while and have nothing booked)
app.get('/api/packages/dormant', requireApprovedAny, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  const minDays = Math.max(1, parseInt(req.query.days, 10) || 14);
  try {
    const headers = { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` };
    const pkgRes = await fetch(`${SUPABASE_URL}/rest/v1/packages?order=created_at.asc`, { headers });
    const rows = await pkgRes.json();
    if (!pkgRes.ok) throw new Error(JSON.stringify(rows));
    const ownSet = isOwnOnly(req.doctor) ? await ownPatientSet(req.doctor) : null;
    const active = (Array.isArray(rows) ? rows : []).filter(p => p.used_sessions < p.total_sessions && (!ownSet || ownSet.has(String(p.patient_name || '').trim().toLowerCase())));
    const since = new Date(Date.now() - 400 * 86400000).toISOString();
    const apRes = await fetch(`${SUPABASE_URL}/rest/v1/appointments?select=patient_name,patient_phone,start_time,status&deleted_at=is.null&start_time=gte.${encodeURIComponent(since)}&order=start_time.desc&limit=8000`, { headers });
    const apRows = apRes.ok ? await apRes.json() : [];
    const now = Date.now();
    const info = new Map(); // lower-case patient name -> { lastPast, nextFuture, phone }
    (Array.isArray(apRows) ? apRows : []).forEach(a => {
      if (a.status === 'cancelled') return;
      const k = (a.patient_name || '').trim().toLowerCase();
      if (!k) return;
      const t = new Date(a.start_time).getTime();
      if (isNaN(t)) return;
      let i = info.get(k);
      if (!i) { i = { lastPast: 0, nextFuture: 0, phone: null }; info.set(k, i); }
      if (a.patient_phone && !i.phone) i.phone = a.patient_phone; // rows come newest first
      if (t <= now) { if (t > i.lastPast) i.lastPast = t; }
      else if (!i.nextFuture || t < i.nextFuture) i.nextFuture = t;
    });
    const out = [];
    active.forEach(p => {
      const i = info.get((p.patient_name || '').trim().toLowerCase()) || { lastPast: 0, nextFuture: 0, phone: null };
      if (i.nextFuture) return; // already has a visit booked — not dormant
      const ref = i.lastPast || new Date(p.created_at).getTime();
      const daysSince = Math.floor((now - ref) / 86400000);
      if (isNaN(daysSince) || daysSince < minDays) return;
      out.push({ ...p, last_visit: i.lastPast ? new Date(i.lastPast).toISOString() : null, days_since: daysSince, patient_phone: i.phone });
    });
    out.sort((a, b) => b.days_since - a.days_since);
    res.json(out);
  } catch (err) {
    console.error('Dormant packages list error:', err);
    res.status(500).json({ error: 'Failed: ' + err.message });
  }
});

// ---- POST /api/packages/:id/followup ---- (record the outcome of chasing a patient: contacted / continuing / not_continuing / no_answer; status null clears it)
app.post('/api/packages/:id/followup', requireApprovedAny, ownPkgGuard, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  const allowed = ['contacted', 'continuing', 'not_continuing', 'no_answer'];
  const status = req.body && req.body.status ? String(req.body.status) : null;
  if (status && !allowed.includes(status)) return res.status(400).json({ error: 'Unknown status.' });
  const patch = { followup_status: status, followup_at: status ? new Date().toISOString() : null };
  if (req.body && typeof req.body.note === 'string') patch.followup_note = req.body.note.trim().slice(0, 500) || null;
  if (!status) patch.followup_note = null;
  try {
    const patchRes = await fetch(`${SUPABASE_URL}/rest/v1/packages?id=eq.${encodeURIComponent(req.params.id)}`, {
      method: 'PATCH',
      headers: {
        apikey: SUPABASE_SERVICE_KEY,
        Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
        'Content-Type': 'application/json',
        Prefer: 'return=representation',
      },
      body: JSON.stringify(patch),
    });
    const updated = await patchRes.json();
    if (!patchRes.ok) throw new Error(JSON.stringify(updated));
    res.json(Array.isArray(updated) ? updated[0] : updated);
  } catch (err) {
    console.error('Package followup error:', err);
    res.status(500).json({ error: 'Failed: ' + err.message });
  }
});

// ---- GET /api/appointments/undocumented?start=&end= ---- (visits that already started in the given window but have no session note saved for that patient yet — the "documentation reminder")
app.get('/api/appointments/undocumented', requireApprovedDoctor, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  const s = new Date(String(req.query.start || '')), e = new Date(String(req.query.end || ''));
  if (isNaN(s.getTime()) || isNaN(e.getTime()) || e < s || e - s > 8 * 86400000) return res.status(400).json({ error: 'Bad start/end.' });
  try {
    const headers = { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` };
    const apRes = await fetch(`${SUPABASE_URL}/rest/v1/appointments?start_time=gte.${encodeURIComponent(s.toISOString())}&start_time=lte.${encodeURIComponent(e.toISOString())}&deleted_at=is.null&order=start_time.asc&limit=500`, { headers });
    const appts = await apRes.json();
    if (!apRes.ok) throw new Error(JSON.stringify(appts));
    const seeAll = hasPermission(req.doctor, 'view_other_patients') && !isOwnOnly(req.doctor);
    const myName = String(req.doctor.name || req.doctor.email || '').trim().toLowerCase();
    const myColor = req.doctor.color || null;
    const now = Date.now();
    const grace = req.query.soon === '1' ? 5 * 60000 : 0;
    const due = (Array.isArray(appts) ? appts : []).filter(a => {
      if (a.status === 'cancelled') return false;
      if (new Date(a.start_time).getTime() > now + grace) return false; // hasn't happened yet (the NOW card also wants the visit starting in the next 5 minutes)
      if (seeAll) return true;
      return String(a.doctor_name || '').trim().toLowerCase() === myName || (myColor && a.doctor_color === myColor);
    });
    if (due.length === 0) return res.json([]);
    const sesRes = await fetch(`${SUPABASE_URL}/rest/v1/sessions?select=patient_name,created_at,updated_at,note,transcript&updated_at=gte.${encodeURIComponent(s.toISOString())}&limit=3000`, { headers });
    const ses = sesRes.ok ? await sesRes.json() : [];
    // A blank file that was auto-created when the patient was booked (no note, no transcript) is NOT documentation.
    const hasContent = (x) => !!(String(x.note || '').trim() || (Array.isArray(x.transcript) ? x.transcript.length > 0 : (x.transcript && typeof x.transcript === 'object' ? Object.keys(x.transcript).length > 0 : !!String(x.transcript || '').trim())));
    const documented = new Set((Array.isArray(ses) ? ses : []).filter(hasContent).map(x => String(x.patient_name || '').trim().toLowerCase()));
    res.json(due
      .filter(a => !documented.has(String(a.patient_name || '').trim().toLowerCase()))
      .map(a => ({ id: a.id, patient_name: a.patient_name, start_time: a.start_time, end_time: a.end_time || null, visit_type: a.visit_type || null, doctor_name: a.doctor_name || null, arrived_at: a.arrived_at || null })));
  } catch (err) {
    console.error('Undocumented visits error:', err);
    res.status(500).json({ error: 'Failed: ' + err.message });
  }
});

// ---- POST /api/packages/:id/start-date ---- (correct the package's start date shown to the patient; date null = go back to the automatic one)
app.post('/api/packages/:id/start-date', requireApprovedAny, ownPkgGuard, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  const date = req.body && req.body.date ? String(req.body.date) : null;
  if (date && !/^\d{4}-\d{2}-\d{2}$/.test(date)) return res.status(400).json({ error: 'Date must look like 2026-10-05.' });
  try {
    const patchRes = await fetch(`${SUPABASE_URL}/rest/v1/packages?id=eq.${encodeURIComponent(req.params.id)}`, {
      method: 'PATCH',
      headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`, 'Content-Type': 'application/json', Prefer: 'return=representation' },
      body: JSON.stringify({ start_date: date }),
    });
    const updated = await patchRes.json();
    if (!patchRes.ok) throw new Error(JSON.stringify(updated));
    res.json(Array.isArray(updated) ? updated[0] : updated);
  } catch (err) {
    console.error('Package start-date error:', err);
    res.status(500).json({ error: 'Failed: ' + err.message });
  }
});

// ---- POST /api/packages/:id/share-link ---- (creates, once, a private link the patient can open to see their own remaining sessions and balance)
app.post('/api/packages/:id/share-link', requireApprovedAny, ownPkgGuard, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  try {
    const headers = { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`, 'Content-Type': 'application/json' };
    const getRes = await fetch(`${SUPABASE_URL}/rest/v1/packages?id=eq.${encodeURIComponent(req.params.id)}&select=id,share_token`, { headers });
    const rows = await getRes.json();
    if (!getRes.ok) throw new Error(JSON.stringify(rows));
    if (!Array.isArray(rows) || !rows[0]) return res.status(404).json({ error: 'Package not found.' });
    let token = rows[0].share_token;
    const markSent = !!(req.body && req.body.markSent);
    // Short links (8 characters). Older long links are replaced by a short one the next time the button is used.
    if (!token || token.length > 10) {
      const alphabet = 'abcdefghjkmnpqrstuvwxyz23456789';
      token = Array.from(crypto.randomBytes(8)).map(b => alphabet[b % alphabet.length]).join('');
      const patchRes = await fetch(`${SUPABASE_URL}/rest/v1/packages?id=eq.${encodeURIComponent(req.params.id)}`, {
        method: 'PATCH', headers: { ...headers, Prefer: 'return=minimal' }, body: JSON.stringify({ share_token: token }),
      });
      if (!patchRes.ok) throw new Error(await patchRes.text());
    }
    if (markSent) {
      await fetch(`${SUPABASE_URL}/rest/v1/packages?id=eq.${encodeURIComponent(req.params.id)}`, {
        method: 'PATCH', headers: { ...headers, Prefer: 'return=minimal' }, body: JSON.stringify({ share_sent_at: new Date().toISOString() }),
      }).catch(() => {});
    }
    res.json({ url: `${PUBLIC_BASE_URL}/e/${token}` });
  } catch (err) {
    console.error('Package share-link error:', err);
    res.status(500).json({ error: 'Failed: ' + err.message });
  }
});

// ---- GET /p/:token ---- (PUBLIC page for the patient: sessions left + money left on their own package, nothing else)
// Package validity from the clinic policy: 6 sessions = 3 weeks, 9 = 1 month, 12 = 6 weeks, counted from the first session.
function packageValidity(totalSessions, startYmd) {
  if (!startYmd) return null;
  const [y, m, d] = startYmd.split('-').map(Number);
  const start = new Date(Date.UTC(y, m - 1, d));
  let end = null;
  if (totalSessions === 6) end = new Date(start.getTime() + 21 * 86400000);
  else if (totalSessions === 12) end = new Date(start.getTime() + 42 * 86400000);
  else if (totalSessions === 9) {
    end = new Date(Date.UTC(y, m, d));
    if (end.getUTCMonth() !== (m % 12)) end = new Date(Date.UTC(y, m + 1, 0)); // clamp, e.g. 31 Jan + 1 month
  }
  return end ? { endYmd: end.toISOString().slice(0, 10) } : null;
}
// Date (Cairo) of the patient's first non-cancelled visit on or after the day the package was bought.
async function packageStartYmd(p, headers) {
  const cairoYmd = iso => new Date(iso).toLocaleDateString('en-CA', { timeZone: 'Africa/Cairo' });
  try {
    const from = new Date(new Date(p.created_at).getTime() - 12 * 3600000).toISOString();
    const nameLike = String(p.patient_name || '').trim().replace(/[*%_,()]/g, '_');
    const ar = await fetch(`${SUPABASE_URL}/rest/v1/appointments?select=patient_name,start_time,status&patient_name=ilike.${encodeURIComponent(nameLike)}&deleted_at=is.null&start_time=gte.${encodeURIComponent(from)}&order=start_time.asc&limit=30`, { headers });
    const rows = ar.ok ? await ar.json() : [];
    const mine = (Array.isArray(rows) ? rows : []).filter(a => a.status !== 'cancelled' && a.status !== 'no_show' && String(a.patient_name || '').trim().toLowerCase() === String(p.patient_name || '').trim().toLowerCase());
    return mine[0] ? cairoYmd(mine[0].start_time) : cairoYmd(p.created_at);
  } catch (e) {
    return p.created_at ? cairoYmd(p.created_at) : null;
  }
}

const CLINIC_LOGO_PNG = Buffer.from('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', 'base64');
app.get('/clinic-logo.png', async (req, res) => {
  try {
    const c = await getClinicConfig();
    const m = /^data:(image\/(?:png|jpeg|webp));base64,(.+)$/.exec(c.logo || '');
    if (m) return res.set({ 'Content-Type': m[1], 'Cache-Control': 'public, max-age=300' }).send(Buffer.from(m[2], 'base64'));
    if (/empower/i.test(c.name || '')) return res.set({ 'Content-Type': 'image/png', 'Cache-Control': 'public, max-age=300' }).send(CLINIC_LOGO_PNG);
    const nm = clinicEsc(String(c.name || 'Clinic'));
    const fs = Math.max(26, Math.min(64, Math.floor(540 / Math.max(6, nm.length * 0.62))));
    res.set({ 'Content-Type': 'image/svg+xml', 'Cache-Control': 'public, max-age=300' }).send('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 600 160"><text x="300" y="98" text-anchor="middle" font-family="Georgia, serif" font-size="' + fs + '" font-weight="700" fill="#1f5c56">' + nm + '</text></svg>');
  } catch (e) { res.set('Content-Type', 'image/png').send(CLINIC_LOGO_PNG); }
});

app.get(['/e/:token', '/p/:token', '/empower/:token'], async (req, res) => {
  const CL = await getClinicConfig();
  const page = (body, status) => res.status(status || 200).set({ 'Content-Type': 'text/html; charset=utf-8', 'X-Robots-Tag': 'noindex, nofollow', 'Cache-Control': 'no-store' }).send(
    `<!doctype html><html lang="en" dir="ltr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow"><title>${clinicEsc(CL.name)} – My Package</title>` +
    `<style>body{margin:0;background:#f6f4ee;color:#12363a;font-family:-apple-system,'Segoe UI',Roboto,Arial,sans-serif;padding:20px}.c{max-width:420px;margin:24px auto;background:#fff;border:1px solid #dad6ca;border-radius:18px;padding:26px;text-align:center}` +
    `.brand{font-size:.78rem;letter-spacing:.14em;text-transform:uppercase;color:#b07a1f;font-weight:700;margin-bottom:10px}h1{font-size:1.15rem;margin:0 0 4px}.big{font-size:3.2rem;font-weight:800;color:#12363a;line-height:1.1;margin:14px 0 2px}.sub{color:#5c7478;font-size:.9rem}.bar{height:12px;background:#e7e3d8;border-radius:99px;overflow:hidden;margin:16px 0}.bar i{display:block;height:100%;background:#e8a33d}` +
    `.row{display:flex;justify-content:space-between;padding:10px 0;border-top:1px solid #eee;font-size:.95rem}.due{color:#b3261e;font-weight:700}.ok{color:#1b8a4a;font-weight:700}.f{margin-top:18px;font-size:.8rem;color:#8a938e}</style></head><body><div class="c"><img src="/clinic-logo.png" alt="${clinicEsc(CL.name)}" style="max-width:240px;width:80%;height:auto;display:block;margin:0 auto 14px">${body}</div></body></html>`);
  const bad = '<h1>Link not valid</h1><div class="sub">Please check the link or contact the clinic.</div>';
  const token = String(req.params.token || '');
  if (!/^[a-z0-9]{8,24}$/.test(token) || !SUPABASE_URL || !SUPABASE_SERVICE_KEY) return page(bad, 404);
  try {
    const pkgHeaders = { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` };
    let r = await fetch(`${SUPABASE_URL}/rest/v1/packages?share_token=eq.${token}&select=patient_name,total_sessions,used_sessions,total_price,amount_paid,created_at,start_date`, { headers: pkgHeaders });
    if (!r.ok) r = await fetch(`${SUPABASE_URL}/rest/v1/packages?share_token=eq.${token}&select=patient_name,total_sessions,used_sessions,total_price,amount_paid,created_at`, { headers: pkgHeaders });
    const rows = await r.json();
    if (!r.ok || !Array.isArray(rows) || !rows[0]) return page(bad, 404);
    const p = rows[0];
    const esc = s => String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
    const total = Number(p.total_sessions) || 0, used = Math.min(Number(p.used_sessions) || 0, total), left = Math.max(0, total - used);
    const pct = total ? Math.round(used / total * 100) : 0;
    const egp = n => Math.round(n).toLocaleString('en-US') + ' EGP';
    let money = '';
    if (p.total_price != null) {
      const due = Math.max(0, Math.round(Number(p.total_price) - Number(p.amount_paid || 0)));
      money = `<div class="row"><span>Package price</span><span>${egp(Number(p.total_price))}</span></div>` +
        `<div class="row"><span>Paid</span><span>${egp(Number(p.amount_paid || 0))}</span></div>` +
        `<div class="row"><span>Remaining balance</span><span class="${due > 0 ? 'due' : 'ok'}">${due > 0 ? egp(due) : 'Fully paid ✓'}</span></div>`;
    }
    // Start date = the manual date if set, else the first real visit on/after the package was bought. Not started until a session is used.
    let startYmd = null;
    if (p.start_date) startYmd = String(p.start_date).slice(0, 10);
    else if (used > 0) startYmd = await packageStartYmd(p, pkgHeaders);
    const validity = packageValidity(total, startYmd);
    const dfmt = ymd => new Date(ymd + 'T12:00:00Z').toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric', timeZone: 'UTC' });
    let timing = '';
    if (startYmd) timing += `<div class="row"><span>Started</span><span>${dfmt(startYmd)}</span></div>`;
    else timing += `<div class="row"><span>Started</span><span>Not yet — starts with your first session</span></div>`;
    if (validity) {
      const left = Math.ceil((new Date(validity.endYmd + 'T23:59:59Z').getTime() - Date.now()) / 86400000);
      const state = left < 0 ? `<span class="due">Validity ended ${dfmt(validity.endYmd)}</span>` : (left <= 7 ? `<span class="due">${dfmt(validity.endYmd)} · ${left + 1 > 1 ? left + ' days left' : 'last day'}</span>` : `<span>${dfmt(validity.endYmd)} · ${left} days left</span>`);
      timing += `<div class="row"><span>Valid until</span>${state}</div>`;
    } else if (startYmd) {
      // no standard validity for this package size
    }
    const clinicPhone = process.env.CLINIC_PHONE || CL.phone || '';
    page(`<h1>Hello ${esc(p.patient_name)} 🌷</h1><div class="sub">Your package status</div>` +
      (left > 0 ? `<div class="big">${left}</div><div class="sub">${left === 1 ? 'session' : 'sessions'} remaining out of ${total}</div>` : `<div class="big" style="font-size:1.6rem">Package completed ✓</div><div class="sub">You used ${total} of ${total} sessions</div>`) +
      `<div class="bar"><i style="width:${pct}%"></i></div><div class="row"><span>Sessions used</span><span>${used} of ${total}</span></div>${timing}${money}` +
      `<div class="f">To book or ask a question, contact us: ${esc(clinicPhone)}</div>`);
  } catch (err) {
    console.error('Public package page error:', err);
    page('<h1>Something went wrong</h1><div class="sub">Please try again in a moment.</div>', 500);
  }
});

// ---- Patient link: ONE link a patient gets with the confirmation message ----
// /me/<token> shows their sessions + upcoming appointments (with Cancel), a button to book again
// and the intake form. The token is the patient's phone + an HMAC signature, so nothing is stored
// and it can't be guessed. Off unless the clinic has features.patientLink === true.
function plKey() { return crypto.createHash('sha256').update('patient-link:' + SUPABASE_SERVICE_KEY).digest(); }
function plSign(n) { return crypto.createHmac('sha256', plKey()).update(String(n)).digest('base64url').slice(0, 22); }
function patientLinkToken(phone) {
  const n = normalizeEgyptPhone(phone);
  if (!n || n.length < 8) return null;
  return Buffer.from(n).toString('base64url') + '.' + plSign(n);
}
function parsePatientToken(token) {
  try {
    const [a, sig] = String(token || '').split('.');
    if (!a || !sig) return null;
    const n = Buffer.from(a, 'base64url').toString();
    if (!/^\d{8,15}$/.test(n)) return null;
    const want = plSign(n);
    if (sig.length !== want.length || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(want))) return null;
    return n;
  } catch (e) { return null; }
}
async function plEnabled() {
  const CL = await getClinicConfig();
  return !!(CL && CL.features && CL.features.patientLink === true);
}
// All of this patient's recent + upcoming visits (matched by phone, whatever format it was typed in).
async function plAppointments(n) {
  const h = { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` };
  const since = new Date(Date.now() - 120 * 86400000).toISOString();
  const r = await fetch(`${SUPABASE_URL}/rest/v1/appointments?start_time=gte.${encodeURIComponent(since)}&deleted_at=is.null&patient_phone=not.is.null&select=id,patient_name,patient_phone,start_time,end_time,status,doctor_name,doctor_color,visit_type&order=start_time.desc&limit=3000`, { headers: h });
  const rows = await r.json();
  if (!r.ok || !Array.isArray(rows)) return [];
  return rows.filter(a => normalizeEgyptPhone(a.patient_phone) === n).sort((x, y) => new Date(x.start_time) - new Date(y.start_time));
}

app.post('/api/patient-links', requireApprovedAny, (req, res) => {
  const items = Array.isArray(req.body && req.body.phones) ? req.body.phones.slice(0, 300) : [];
  const out = {};
  for (const p of items) { const t = patientLinkToken(p); if (t) out[p] = t; }
  res.json({ tokens: out });
});

app.get('/me/:token', async (req, res) => {
  const CL = await getClinicConfig();
  const esc = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const send = (body, status) => res.status(status || 200).set({ 'Content-Type': 'text/html; charset=utf-8', 'X-Robots-Tag': 'noindex, nofollow', 'Cache-Control': 'no-store' }).send(
    `<!doctype html><html lang="en" dir="ltr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow"><title>${esc(CL.name)}</title>` +
    `<link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap" rel="stylesheet">` +
    `<style>*{box-sizing:border-box}body{margin:0;background:#F6F4EE;color:#1C2A28;font-family:'Plus Jakarta Sans',-apple-system,'Segoe UI',Roboto,Arial,sans-serif}.w{max-width:440px;margin:0 auto;padding:20px 16px 36px;display:flex;flex-direction:column;gap:10px}` +
    `.top{display:flex;align-items:center;gap:10px;padding:4px 4px 6px}.logo{width:40px;height:40px;border-radius:12px;background:#1F5C56;color:#F6F4EE;display:flex;align-items:center;justify-content:center;font-weight:800}.nm{font-size:16px;font-weight:800}.sb{font-size:12px;color:#566562}` +
    `.lab{font-size:12px;font-weight:800;letter-spacing:.6px;text-transform:uppercase;color:#566562;margin:6px 4px 0}.card{background:#fff;border-radius:20px;padding:16px;box-shadow:0 1px 2px rgba(28,42,40,.06);display:flex;flex-direction:column;gap:10px}` +
    `.ap{display:flex;align-items:center;gap:12px}.ic{width:44px;height:44px;border-radius:12px;background:#DCEFE8;display:flex;align-items:center;justify-content:center;flex:none}.t1{font-size:16px;font-weight:800}.t2{font-size:13px;color:#566562}` +
    `.btn{height:48px;border-radius:14px;display:flex;align-items:center;justify-content:center;font-size:15px;font-weight:800;border:0;width:100%;cursor:pointer;text-decoration:none;font-family:inherit}.p{background:#1F5C56;color:#F6F4EE}.o{border:1.5px solid #E1DDD1;color:#1C2A28;background:#fff}.d{border:1.5px solid #E7B5B0;color:#B3261E;background:#fff;height:44px}` +
    `.big{font-size:40px;font-weight:800;color:#1F5C56;line-height:1}.bar{height:10px;border-radius:6px;background:#ECE8DC;overflow:hidden}.bar i{display:block;height:100%;background:#1F5C56}.mut{font-size:13px;color:#566562}` +
    `.ov{position:fixed;inset:0;background:rgba(28,42,40,.45);display:none;align-items:flex-end;justify-content:center;z-index:9}.sh{background:#fff;border-radius:24px 24px 0 0;padding:20px 16px 24px;width:100%;max-width:440px;display:flex;flex-direction:column;gap:12px}` +
    `.msg{border-radius:14px;padding:12px 14px;font-size:14px;line-height:1.45}.ok{background:#E4F2EA;color:#1F4D38}.wn{background:#FBF0DA;color:#6B4A10}</style></head><body><div class="w">${body}</div></body></html>`);
  const bad = `<div class="card"><div class="t1">Link not valid</div><div class="mut">Please check the link or contact the clinic.</div></div>`;
  try {
    const n = parsePatientToken(req.params.token);
    if (!n || !SUPABASE_URL || !SUPABASE_SERVICE_KEY || !(await plEnabled())) return send(bad, 404);
    const appts = await plAppointments(n);
    const now = Date.now();
    const upcoming = appts.filter(a => a.status !== 'cancelled' && new Date(a.start_time).getTime() > now).sort((x, y) => new Date(x.start_time) - new Date(y.start_time)).slice(0, 8);
    const name = (appts.length ? appts[appts.length - 1].patient_name : '') || '';
    const fm = iso => new Date(iso).toLocaleString('en-GB', { weekday: 'short', day: 'numeric', month: 'short', hour: 'numeric', minute: '2-digit', hour12: true, timeZone: 'Africa/Cairo' }).replace(',', ' ·');
    let pkgHtml = '';
    if (name) {
      const h = { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` };
      // Match the package by name loosely (capitals, spaces, أ/ا, ة/ه...), using every name this patient was booked under.
      const keys = new Set(appts.map(a => bookNameKey(a.patient_name)).filter(Boolean));
      const pr = await fetch(`${SUPABASE_URL}/rest/v1/packages?select=patient_name,total_sessions,used_sessions,total_price,amount_paid,created_at&order=created_at.desc&limit=3000`, { headers: h });
      const pk = (pr.ok ? await pr.json() : []);
      const mine = Array.isArray(pk) ? pk.filter(x => keys.has(bookNameKey(x.patient_name))) : [];
      const p = mine.find(x => Number(x.used_sessions) < Number(x.total_sessions)) || mine[0] || null;
      if (p) {
        const total = Number(p.total_sessions) || 0, used = Math.min(Number(p.used_sessions) || 0, total), left = Math.max(0, total - used);
        const due = p.total_price != null ? Math.max(0, Math.round(Number(p.total_price) - Number(p.amount_paid || 0))) : null;
        pkgHtml = `<div class="lab">Your package</div><div class="card" style="border:2px solid #1F5C56">` +
          (left > 0 ? `<div style="display:flex;align-items:baseline;gap:8px"><span class="big">${left}</span><span style="font-size:15px;color:#566562">of ${total} sessions left</span></div>` : `<div class="t1">Package completed ✓</div>`) +
          `<div class="bar"><i style="width:${total ? Math.round(used / total * 100) : 0}%"></i></div>` +
          (due != null ? `<div class="mut">${due > 0 ? 'Remaining to pay: <b style="color:#1C2A28">' + due.toLocaleString('en-US') + ' EGP</b>' : 'Fully paid ✓'}</div>` : '') + `</div>`;
      }
    }
    const ic = '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#1F5C56" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="5" width="16" height="15" rx="3"/><path d="M8 3v4M16 3v4M4 10h16"/></svg>';
    const apptCard = a => `<div class="card"><div class="ap"><span class="ic">${ic}</span><div><div class="t1">${esc(fm(a.start_time))}</div><div class="t2">${esc(a.doctor_name || '')}</div></div></div>` +
      `<button class="btn d" data-id="${esc(a.id)}" data-start="${esc(a.start_time)}" data-label="${esc(fm(a.start_time))}${a.doctor_name ? ' · ' + esc(a.doctor_name) : ''}">Cancel this appointment</button></div>`;
    const upHtml = upcoming.length
      ? `<div class="lab">Next appointment</div>${apptCard(upcoming[0])}` + (upcoming.length > 1 ? `<div class="lab">Also coming</div>${upcoming.slice(1).map(apptCard).join('')}` : '')
      : `<div class="lab">Appointments</div><div class="card"><div class="t2">You have no upcoming appointments.</div></div>`;
    const clinicPhone = process.env.CLINIC_PHONE || CL.phone || '';
    const intakeHref = CL.intake_url || '/intake';
    const initials = esc(String(CL.name || 'C').split(/\s+/).map(w => w[0]).join('').slice(0, 2).toUpperCase());
    send(`<div style="padding:4px 4px 8px"><img src="/clinic-logo.png" alt="${esc(CL.name)}" style="display:block;max-width:100%;max-height:72px;object-fit:contain" onerror="this.style.display='none';document.getElementById('fb').style.display='flex'"><div class="top" id="fb" style="display:none"><span class="logo">${initials}</span><div class="nm">${esc(CL.name)}</div></div><div class="sb" style="margin-top:8px;font-size:14px">${name ? 'Hello ' + esc(name) : 'Your visit page'}</div></div>` +
      pkgHtml + upHtml +
      `<a class="btn p" href="/book">+ Book a new session</a>` +
      `<a class="btn o" href="${esc(intakeHref)}">Fill the intake form</a>` +
      (clinicPhone ? `<div class="mut" style="text-align:center;padding:4px">Need help? Contact the clinic: ${esc(clinicPhone)}</div>` : '') +
      `<div class="ov" id="ov"><div class="sh"><div style="width:40px;height:4px;border-radius:2px;background:#E1DDD1;align-self:center"></div><div class="t1" id="ttl" style="font-size:20px"></div><div style="font-size:15px;font-weight:700" id="lbl"></div><div class="msg" id="msg"></div><button class="btn" id="go"></button><button class="btn o" id="keep">Keep my appointment</button><div class="mut" id="err" style="color:#B3261E"></div></div></div>` +
      `<script>(function(){var ov=document.getElementById('ov'),cur=null;function $(i){return document.getElementById(i)}` +
      `document.querySelectorAll('button.d').forEach(function(b){b.onclick=function(){cur=b;var late=(new Date(b.dataset.start).getTime()-Date.now())<6*3600*1000;$('lbl').textContent=b.dataset.label;$('err').textContent='';` +
      `if(late){$('ttl').textContent='Less than 6 hours to go';$('msg').className='msg wn';$('msg').textContent='Cancelling now counts as a late cancellation, as agreed with the clinic. You can still cancel, or message the clinic first.';$('go').textContent='Cancel anyway';$('go').style.cssText='background:#8A5A12;color:#fff'}` +
      `else{$('ttl').textContent='Cancel this appointment?';$('msg').className='msg ok';$('msg').textContent='You are cancelling more than 6 hours ahead. It is free, and the time goes back to the clinic.';$('go').textContent='Yes, cancel it';$('go').style.cssText='background:#B3261E;color:#fff'}ov.style.display='flex'}});` +
      `$('keep').onclick=function(){ov.style.display='none'};` +
      `$('go').onclick=function(){$('go').disabled=true;fetch('/api/me/${esc(req.params.token)}/cancel',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id:cur.dataset.id})}).then(function(r){return r.json().then(function(j){return{ok:r.ok,j:j}})}).then(function(x){if(x.ok){location.reload()}else{$('go').disabled=false;$('err').textContent=x.j.error||'Could not cancel. Please contact the clinic.'}}).catch(function(){$('go').disabled=false;$('err').textContent='Connection problem. Please try again.'})};})();</script>`);
  } catch (err) {
    console.error('Patient link page error:', err);
    send('<div class="card"><div class="t1">Something went wrong</div><div class="mut">Please try again in a moment.</div></div>', 500);
  }
});

app.post('/api/me/:token/cancel', async (req, res) => {
  try {
    const n = parsePatientToken(req.params.token);
    if (!n || !SUPABASE_URL || !SUPABASE_SERVICE_KEY || !(await plEnabled())) return res.status(404).json({ error: 'Link not valid.' });
    const id = String((req.body && req.body.id) || '');
    if (!/^[A-Za-z0-9_.:-]{1,100}$/.test(id)) return res.status(400).json({ error: 'Bad request.' });
    const appt = (await plAppointments(n)).find(a => String(a.id) === id);
    if (!appt) return res.status(404).json({ error: 'Appointment not found.' });
    if (appt.status === 'cancelled') return res.json({ ok: true, already: true });
    const startMs = new Date(appt.start_time).getTime();
    if (!(startMs > Date.now())) return res.status(400).json({ error: 'This appointment has already started.' });
    const late = (startMs - Date.now()) < 6 * 3600 * 1000;
    const up = await fetch(`${SUPABASE_URL}/rest/v1/appointments?id=eq.${encodeURIComponent(id)}`, {
      method: 'PATCH',
      headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`, 'Content-Type': 'application/json', Prefer: 'return=minimal' },
      body: JSON.stringify({ status: 'cancelled', cancelled_at: new Date().toISOString() }),
    });
    if (!up.ok) return res.status(500).json({ error: 'Could not cancel. Please contact the clinic.' });
    res.json({ ok: true, late });
    pushAppointmentChange(late ? 'patient_cancelled_late' : 'patient_cancelled', appt, null).catch(e => console.error('Push alert failed:', e.message));
  } catch (err) {
    console.error('Patient cancel error:', err);
    res.status(500).json({ error: 'Could not cancel. Please contact the clinic.' });
  }
});

// ---- POST /api/packages/:id/policy-sent ---- (mark the package policy as sent, or pass sent:false to clear it)
app.post('/api/packages/:id/policy-sent', requireApprovedAny, ownPkgGuard, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  const sent = !(req.body && req.body.sent === false);
  try {
    const patchRes = await fetch(`${SUPABASE_URL}/rest/v1/packages?id=eq.${encodeURIComponent(req.params.id)}`, {
      method: 'PATCH',
      headers: {
        apikey: SUPABASE_SERVICE_KEY,
        Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
        'Content-Type': 'application/json',
        Prefer: 'return=representation',
      },
      body: JSON.stringify({ policy_sent_at: sent ? new Date().toISOString() : null }),
    });
    const updated = await patchRes.json();
    if (!patchRes.ok) throw new Error(JSON.stringify(updated));
    res.json(Array.isArray(updated) ? updated[0] : updated);
  } catch (err) {
    console.error('Package policy-sent error:', err);
    res.status(500).json({ error: 'Failed: ' + err.message });
  }
});

// ---- POST /api/packages/:id/set-used ---- (correct how many sessions the package has used — e.g. free sessions or a visit that belonged to the previous package were counted by mistake)
app.post('/api/packages/:id/set-used', requireApprovedAny, ownPkgGuard, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  if (req.doctor.role === 'doctor' && !hasPermission(req.doctor, 'register_packages')) {
    return res.status(403).json({ error: 'You don\'t have permission to change a package\'s session count — ask the clinic owner to grant it.' });
  }
  const value = parseInt(req.body && req.body.usedSessions, 10);
  if (!Number.isInteger(value) || value < 0) return res.status(400).json({ error: 'Missing or invalid usedSessions.' });
  try {
    const headers = { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` };
    const getRes = await fetch(`${SUPABASE_URL}/rest/v1/packages?id=eq.${encodeURIComponent(req.params.id)}`, { headers });
    const rows = await getRes.json();
    const pkg = Array.isArray(rows) && rows[0];
    if (!pkg) return res.status(404).json({ error: 'Package not found.' });
    if (value > pkg.total_sessions) return res.status(400).json({ error: `This package only has ${pkg.total_sessions} sessions.` });
    const patchRes = await fetch(`${SUPABASE_URL}/rest/v1/packages?id=eq.${encodeURIComponent(req.params.id)}`, {
      method: 'PATCH',
      headers: { ...headers, 'Content-Type': 'application/json', Prefer: 'return=representation' },
      body: JSON.stringify({ used_sessions: value }),
    });
    const updated = await patchRes.json();
    if (!patchRes.ok) throw new Error(JSON.stringify(updated));
    res.json(Array.isArray(updated) ? updated[0] : updated);
  } catch (err) {
    console.error('Package set-used error:', err);
    res.status(500).json({ error: 'Failed: ' + err.message });
  }
});

// ---- POST /api/packages/:id/set-paid ---- (correct how much of the package price counts as paid, WITHOUT recording any money — for payments already recorded on an appointment)
app.post('/api/packages/:id/set-paid', requireApprovedAny, ownPkgGuard, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  const value = Number(req.body && req.body.amountPaid);
  if (!isFinite(value) || value < 0) return res.status(400).json({ error: 'Missing or invalid amountPaid.' });
  try {
    const patchRes = await fetch(`${SUPABASE_URL}/rest/v1/packages?id=eq.${encodeURIComponent(req.params.id)}`, {
      method: 'PATCH',
      headers: {
        apikey: SUPABASE_SERVICE_KEY,
        Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
        'Content-Type': 'application/json',
        Prefer: 'return=representation',
      },
      body: JSON.stringify({ amount_paid: value }),
    });
    const updated = await patchRes.json();
    if (!patchRes.ok) throw new Error(JSON.stringify(updated));
    if (!Array.isArray(updated) || updated.length === 0) return res.status(404).json({ error: 'Package not found.' });
    res.json(updated[0]);
  } catch (err) {
    console.error('Package set-paid error:', err);
    res.status(500).json({ error: 'Failed: ' + err.message });
  }
});

// ---- POST /api/packages/:id/add-payment ---- (record another installment toward this package's total_price)
app.post('/api/packages/:id/add-payment', requireApprovedAny, ownPkgGuard, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  const { amount } = req.body || {};
  const add = Number(amount);
  if (!add || add <= 0) return res.status(400).json({ error: 'Missing or invalid amount.' });
  try {
    const getUrl = `${SUPABASE_URL}/rest/v1/packages?id=eq.${encodeURIComponent(req.params.id)}`;
    const getRes = await fetch(getUrl, { headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` } });
    const rows = await getRes.json();
    const pkg = Array.isArray(rows) && rows[0];
    if (!pkg) return res.status(404).json({ error: 'Package not found.' });
    const newPaid = Number(pkg.amount_paid || 0) + add;
    const patchRes = await fetch(getUrl, {
      method: 'PATCH',
      headers: {
        apikey: SUPABASE_SERVICE_KEY,
        Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
        'Content-Type': 'application/json',
        Prefer: 'return=representation',
      },
      body: JSON.stringify({ amount_paid: newPaid }),
    });
    const updated = await patchRes.json();
    if (!patchRes.ok) throw new Error(JSON.stringify(updated));
    res.json(Array.isArray(updated) ? updated[0] : updated);
  } catch (err) {
    console.error('Package add-payment error:', err);
    res.status(500).json({ error: 'Failed: ' + err.message });
  }
});

// ---- POST /api/packages/:id/use-session ---- (consume one session from the package)
app.post('/api/packages/:id/use-session', requireApprovedAny, ownPkgGuard, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  if (req.doctor.role === 'doctor' && !hasPermission(req.doctor, 'view_payments')) {
    return res.status(403).json({ error: 'You don\'t have permission to record payments — ask the clinic owner to grant it.' });
  }
  try {
    const getUrl = `${SUPABASE_URL}/rest/v1/packages?id=eq.${encodeURIComponent(req.params.id)}`;
    const getRes = await fetch(getUrl, { headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` } });
    const rows = await getRes.json();
    const pkg = Array.isArray(rows) && rows[0];
    if (!pkg) return res.status(404).json({ error: 'Package not found.' });
    const newUsed = pkg.used_sessions + 1;
    const patchRes = await fetch(getUrl, {
      method: 'PATCH',
      headers: {
        apikey: SUPABASE_SERVICE_KEY,
        Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
        'Content-Type': 'application/json',
        Prefer: 'return=representation',
      },
      body: JSON.stringify({ used_sessions: newUsed }),
    });
    const updated = await patchRes.json();
    if (!patchRes.ok) throw new Error(JSON.stringify(updated));
    res.json(Array.isArray(updated) ? updated[0] : updated);
  } catch (err) {
    console.error('Use-session error:', err);
    res.status(500).json({ error: 'Failed to update package: ' + err.message });
  }
});

// ---- GET /api/appointments/search-by-patient ----
// Free-text patient search across ALL dates (not scoped to a month) —
// powers the calendar's "find a patient" search box, letting the owner
// jump straight to whichever day their appointment is on.
app.get('/api/appointments/search-by-patient', requireApprovedAny, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  const { q } = req.query;
  if (!q || q.trim().length < 2) return res.status(400).json({ error: 'Search term must be at least 2 characters.' });
  try {
    const url = `${SUPABASE_URL}/rest/v1/appointments?patient_name=ilike.*${encodeURIComponent(q.trim())}*&deleted_at=is.null${isOwnOnly(req.doctor) ? '&doctor_name=eq.' + encodeURIComponent(ownDoctorName(req.doctor)) : ''}&order=start_time.desc&limit=30`;
    const upstream = await fetch(url, { headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` } });
    const data = await upstream.text();
    res.status(upstream.status).type('application/json').send(data);
  } catch (err) {
    console.error('Search-by-patient error:', err);
    res.status(500).json({ error: 'Search failed: ' + err.message });
  }
});

app.get('/api/appointments/unpaid-by-patient', requireApprovedAny, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  const { patientName } = req.query;
  if (!patientName) return res.status(400).json({ error: 'Missing patientName.' });
  try {
    const url = `${SUPABASE_URL}/rest/v1/appointments?patient_name=eq.${encodeURIComponent(patientName)}&paid=eq.false&status=neq.cancelled&deleted_at=is.null${isOwnOnly(req.doctor) ? '&doctor_name=eq.' + encodeURIComponent(ownDoctorName(req.doctor)) : ''}&order=start_time.desc&limit=20`;
    const upstream = await fetch(url, { headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` } });
    const data = await upstream.text();
    res.status(upstream.status).type('application/json').send(data);
  } catch (err) {
    console.error('Unpaid-by-patient GET error:', err);
    res.status(500).json({ error: 'Failed to load unpaid appointments: ' + err.message });
  }
});

// ---- DELETE /api/appointments/delete-day ---- (?start=ISO&end=ISO) owner-only.
// SOFT delete: sets deleted_at instead of removing rows, so it can be
// undone from the trash within 7 days.
app.delete('/api/appointments/delete-day', requireOwnerDoctor, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  const { start, end } = req.query;
  if (!start || !end) return res.status(400).json({ error: 'Missing start or end.' });
  try {
    const url = `${SUPABASE_URL}/rest/v1/appointments?start_time=gte.${encodeURIComponent(start)}&start_time=lte.${encodeURIComponent(end)}&deleted_at=is.null`;
    const delRes = await fetch(url, {
      method: 'PATCH',
      headers: {
        apikey: SUPABASE_SERVICE_KEY,
        Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
        'Content-Type': 'application/json',
        Prefer: 'return=representation',
      },
      body: JSON.stringify({ deleted_at: new Date().toISOString() }),
    });
    const data = await delRes.json();
    if (!delRes.ok) throw new Error(JSON.stringify(data));
    res.json({ ok: true, deleted: Array.isArray(data) ? data.length : 0 });
  } catch (err) {
    console.error('Delete-day error:', err);
    res.status(500).json({ error: 'Failed to delete: ' + err.message });
  }
});

// ---- GET /api/appointments/trash ---- owner-only, lists soft-deleted
// appointments from the last 7 days, grouped by the day they were on.
app.get('/api/appointments/trash', requireOwnerDoctor, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  try {
    const cutoff = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString();
    const url = `${SUPABASE_URL}/rest/v1/appointments?deleted_at=gte.${encodeURIComponent(cutoff)}&order=deleted_at.desc,start_time.asc`;
    const upstream = await fetch(url, { headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` } });
    const data = await upstream.text();
    res.status(upstream.status).type('application/json').send(data);
  } catch (err) {
    console.error('Trash GET error:', err);
    res.status(500).json({ error: 'Failed to load trash: ' + err.message });
  }
});

// ---- POST /api/appointments/restore-day ---- (?start=ISO&end=ISO) owner-only,
// undoes a delete-day within the 7-day window.
app.post('/api/appointments/restore-day', requireOwnerDoctor, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  const { start, end } = req.query;
  if (!start || !end) return res.status(400).json({ error: 'Missing start or end.' });
  try {
    const url = `${SUPABASE_URL}/rest/v1/appointments?start_time=gte.${encodeURIComponent(start)}&start_time=lte.${encodeURIComponent(end)}&deleted_at=not.is.null`;
    const restoreRes = await fetch(url, {
      method: 'PATCH',
      headers: {
        apikey: SUPABASE_SERVICE_KEY,
        Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
        'Content-Type': 'application/json',
        Prefer: 'return=representation',
      },
      body: JSON.stringify({ deleted_at: null }),
    });
    const data = await restoreRes.json();
    if (!restoreRes.ok) throw new Error(JSON.stringify(data));
    res.json({ ok: true, restored: Array.isArray(data) ? data.length : 0 });
  } catch (err) {
    console.error('Restore-day error:', err);
    res.status(500).json({ error: 'Failed to restore: ' + err.message });
  }
});

app.get('/api/appointments', requireApprovedAny, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  const { start, end } = req.query;
  if (!start || !end) return res.status(400).json({ error: 'Missing start or end query params.' });
  try {
    const url = `${SUPABASE_URL}/rest/v1/appointments?start_time=gte.${encodeURIComponent(start)}&start_time=lte.${encodeURIComponent(end)}&deleted_at=is.null${isOwnOnly(req.doctor) ? '&doctor_name=eq.' + encodeURIComponent(ownDoctorName(req.doctor)) : ''}&order=start_time.asc`;
    const upstream = await fetch(url, { headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` } });
    const data = await upstream.text();
    res.status(upstream.status).type('application/json').send(data);
  } catch (err) {
    console.error('Appointments GET error:', err);
    res.status(500).json({ error: 'Failed to load appointments: ' + err.message });
  }
});

app.post('/api/appointments', requireApprovedAny, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  const { patientName, startTime, endTime, doctorColor, doctorName, patientPhone, visitType } = req.body || {};
  if (!patientName || !startTime || !endTime) return res.status(400).json({ error: 'Missing patientName, startTime, or endTime.' });
  // Secretaries manage the whole schedule as their job; a plain doctor
  // needs the manage_other_appointments permission to book under someone
  // else's name — otherwise it's silently forced back to their own.
  let effectiveDoctorName = doctorName || req.doctor.name || req.doctor.email;
  const ownName = req.doctor.name || req.doctor.email;
  if (doctorName && doctorName !== ownName && req.doctor.role === 'doctor' && !hasPermission(req.doctor, 'manage_other_appointments')) {
    effectiveDoctorName = ownName;
  }
  try {
    const url = `${SUPABASE_URL}/rest/v1/appointments`;
    const upstream = await fetch(url, {
      method: 'POST',
      headers: {
        apikey: SUPABASE_SERVICE_KEY,
        Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
        'Content-Type': 'application/json',
        Prefer: 'return=representation',
      },
      body: JSON.stringify({
        patient_name: patientName,
        start_time: startTime,
        end_time: endTime,
        doctor_color: doctorColor || req.doctor.color || null,
        doctor_name: effectiveDoctorName,
        patient_phone: patientPhone || null,
        visit_type: visitType || 'session',
      }),
    });
    const data = await upstream.text();
    res.status(upstream.status).type('application/json').send(data);

    if (upstream.ok) {
      try {
        const rows = JSON.parse(data);
        const created = Array.isArray(rows) ? rows[0] : rows;
        pushAppointmentChange('new', created, req.doctor.email).catch(e => console.error('Push alert failed:', e.message));
      } catch (e) { /* the alert is optional */ }
    }

    // Give the patient a ready Documentation "file" under their assigned
    // doctor as soon as they're booked — best-effort, never blocks the
    // booking response above.
    if (upstream.ok) {
      try {
        const finalDoctorName = effectiveDoctorName;
        const checkUrl = `${SUPABASE_URL}/rest/v1/sessions?patient_name=eq.${encodeURIComponent(patientName)}&doctor_name=eq.${encodeURIComponent(finalDoctorName)}&select=id&limit=1`;
        const checkRes = await fetch(checkUrl, { headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` } });
        const existing = await checkRes.json();
        if (!Array.isArray(existing) || existing.length === 0) {
          await fetch(`${SUPABASE_URL}/rest/v1/sessions`, {
            method: 'POST',
            headers: {
              apikey: SUPABASE_SERVICE_KEY,
              Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
              'Content-Type': 'application/json',
            },
            body: JSON.stringify({
              id: crypto.randomUUID(),
              patient_name: patientName,
              doctor_name: finalDoctorName,
              session_date: new Date(startTime).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' }),
              session_type: 'assessment',
              updated_at: new Date().toISOString(),
            }),
          });
        }
      } catch (fileErr) {
        console.error('Auto-create documentation file failed (non-fatal):', fileErr);
      }
    }
  } catch (err) {
    console.error('Appointments POST error:', err);
    res.status(500).json({ error: 'Failed to book appointment: ' + err.message });
  }
});

// ---- Push notifications (off until PUSH_GATEWAY_SECRET is set) ----
// The web-push library is NOT used here on purpose. Notifications are sent by a separate
// gateway (Supabase Edge Function in the owner's musaed-support project). This server only
// makes a small best-effort HTTP call to it: it never awaits it before replying, has a short
// timeout, and swallows every error — so the gateway being down can never affect bookings.
const PUSH_GATEWAY_URL = process.env.PUSH_GATEWAY_URL || 'https://qprxyvvtqhtdzidzrcwi.supabase.co/functions/v1/push-gateway';
const PUSH_GATEWAY_SECRET = process.env.PUSH_GATEWAY_SECRET || '';
const PUSH_CLINIC_ID = (() => { try { return new URL(SUPABASE_URL).hostname; } catch (e) { return SUPABASE_URL || 'clinic'; } })();

async function pushGateway(body) {
  if (!PUSH_GATEWAY_SECRET) return null;
  const r = await fetch(PUSH_GATEWAY_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-push-secret': PUSH_GATEWAY_SECRET },
    body: JSON.stringify({ clinic: PUSH_CLINIC_ID, ...body }),
    signal: AbortSignal.timeout(6000),
  });
  return r.ok ? r.json().catch(() => ({})) : null;
}

// kind: 'new' | 'moved' | 'cancelled' | 'deleted'. The doctor who owns the visit is told,
// unless they are the one who made the change.
async function pushAppointmentChange(kind, appt, actorEmail) {
  if (!PUSH_GATEWAY_SECRET) return;
  if (!appt) { await pushGateway({ action: 'notify', emails: [], title: 'skipped:no-appt', body: String(kind) }).catch(() => {}); return; }
  const r = await fetch(`${SUPABASE_URL}/rest/v1/doctors?status=eq.approved&select=email,name,color,role`, {
    headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` },
    signal: AbortSignal.timeout(6000),
  });
  const docs = await r.json();
  // Diagnostics: when no alert goes out, leave a one-line reason in the gateway log (visible only to the Musaed owner).
  const diag = (why) => pushGateway({ action: 'notify', emails: [], title: 'skipped:' + why, body: `${kind} | doctor_name=${appt.doctor_name || ''} | actor=${actorEmail || ''}` }).catch(() => {});
  if (!Array.isArray(docs) || docs.length === 0) { await diag('no-doctors'); return; }
  const nm = String(appt.doctor_name || '').trim().toLowerCase();
  const byName = docs.find(d => String(d.name || '').trim().toLowerCase() === nm || String(d.email || '').trim().toLowerCase() === nm);
  const byColor = appt.doctor_color ? docs.filter(d => d.color === appt.doctor_color) : [];
  // Loose name match: ignore "Dr"/"دكتور", punctuation and spacing ("Dr Mostafa Farag" == "Mostafa Farag").
  const norm = x => String(x || '').toLowerCase().replace(/\b(dr|doctor)\b\.?|دكتور|د\./g, ' ').replace(/[^a-z0-9\u0600-\u06FF]+/g, ' ').trim();
  const nn = norm(appt.doctor_name);
  const byLoose = nn ? docs.filter(d => { const dn = norm(d.name); return dn && (dn === nn || dn.includes(nn) || nn.includes(dn)); }) : [];
  let doc = byName || (byColor.length === 1 ? byColor[0] : null) || (byLoose.length === 1 ? byLoose[0] : null);
  let emails = doc && doc.email ? [doc.email] : [];
  // Patient cancellations must never be lost: if the owning doctor can't be identified, tell every approved doctor.
  if (!emails.length && /^patient_cancelled/.test(kind)) emails = docs.map(d => d.email).filter(Boolean);
  if (!emails.length) { console.warn('Push: no doctor matched for', appt.doctor_name); await diag('no-match'); }
  // Clinic owners hear about every change in the clinic, not only their own visits (owner's decision, Nov 2026).
  emails = [...new Set([...emails, ...docs.filter(d => d.role === 'owner').map(d => d.email)]
    .filter(e => e && !/@empower\.local$/i.test(e)).map(e => String(e).toLowerCase()))];
  if (!emails.length) return;
  if (actorEmail) emails = emails.filter(e => String(e).toLowerCase() !== String(actorEmail).toLowerCase());
  if (!emails.length) { await diag('own-change'); return; }
  const when = appt.start_time
    ? new Date(appt.start_time).toLocaleString('en-GB', { weekday: 'short', day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit', timeZone: 'Africa/Cairo' })
    : '';
  const who = appt.patient_name || '';
  const titles = { new: 'حجز جديد', moved: 'اتغير ميعاد', cancelled: 'ميعاد اتلغى', deleted: 'ميعاد اتمسح', patient_cancelled: 'المريض لغى ميعاده', patient_cancelled_late: '⚠️ إلغاء متأخر من المريض' };
  await pushGateway({ action: 'notify', emails, title: titles[kind] || 'تحديث في المواعيد', body: [who, when, appt.doctor_name].filter(Boolean).join(' · '), tag: `appt-${kind}-${appt.id || ''}-${Date.now()}` }); // unique per alert: iPhone silently replaces an earlier notification that has the same tag
}

// Online bookings (booking page / patient page) have no signed-in actor, so pushAppointmentChange
// never ran for them: tell the visit's doctor AND every approved owner.
async function pushOnlineBooking(appt, doc, patientName, label, isPackage) {
  if (!PUSH_GATEWAY_SECRET || !appt) return;
  const r = await fetch(`${SUPABASE_URL}/rest/v1/doctors?status=eq.approved&role=eq.owner&select=email`, {
    headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` },
    signal: AbortSignal.timeout(6000),
  });
  const owners = await r.json().catch(() => []);
  const emails = [...new Set([doc && doc.email, ...(Array.isArray(owners) ? owners.map(o => o.email) : [])]
    .filter(e => e && !/@empower\.local$/i.test(e)).map(e => String(e).toLowerCase()))];
  if (!emails.length) return;
  const when = appt.start_time
    ? new Date(appt.start_time).toLocaleString('en-GB', { weekday: 'short', day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit', timeZone: 'Africa/Cairo' })
    : '';
  const body = [patientName || appt.patient_name || '', when, doc && doc.name, label, isPackage ? 'باكدج' : ''].filter(Boolean).join(' · ');
  await pushGateway({ action: 'notify', emails, title: 'حجز أونلاين جديد', body, tag: `appt-online-${appt.id || ''}-${Date.now()}` });
}

// The app sends the device's push subscription here; we hand it to the gateway under the doctor's email.
app.post('/api/push/subscribe', requireApprovedAny, async (req, res) => {
  if (!PUSH_GATEWAY_SECRET) return res.status(503).json({ error: 'Notifications are not switched on for this clinic yet.' });
  try {
    const subscription = req.body && req.body.subscription;
    if (!subscription || !subscription.endpoint) return res.status(400).json({ error: 'Missing subscription.' });
    const out = await pushGateway({ action: 'subscribe', email: req.doctor.email, subscription });
    if (!out) return res.status(502).json({ error: 'Notification service is not reachable right now.' });
    res.json({ ok: true });
  } catch (e) {
    res.status(502).json({ error: 'Notification service is not reachable right now.' });
  }
});

// ---- PATCH /api/appointments/:id ----
// Edits an existing booking — any subset of patientName, patientPhone,
// startTime, endTime, doctorColor, doctorName. Same access as booking
// (owner, doctor, or secretary), since secretaries manage the day-to-day
// calendar too.
app.patch('/api/appointments/:id', requireApprovedAny, ownApptGuard, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  const { patientName, patientPhone, startTime, endTime, doctorColor, doctorName, status, paid, visitType, isFree, arrived, ownPatient } = req.body || {};
  const ownName = req.doctor.name || req.doctor.email;

  // Cancelling / restoring / no-show requires edit_cancel_appointments
  // (owner and secretary always allowed — cancelling is core to running
  // the schedule day-to-day).
  if (status !== undefined && req.doctor.role === 'doctor' && !hasPermission(req.doctor, 'edit_cancel_appointments')) {
    return res.status(403).json({ error: 'You don\'t have permission to cancel/restore appointments — ask the clinic owner to grant it.' });
  }
  if (ownPatient !== undefined && req.doctor.role !== 'owner') return res.status(403).json({ error: 'Only the owner can mark who brought the patient.' });
  // Marking paid/unpaid/free requires view_payments (owner/secretary exempt).
  if ((paid !== undefined || isFree !== undefined) && req.doctor.role === 'doctor' && !hasPermission(req.doctor, 'view_payments')) {
    return res.status(403).json({ error: 'You don\'t have permission to record payments — ask the clinic owner to grant it.' });
  }
  // Reassigning to a different doctor requires manage_other_appointments.
  let effectiveDoctorName = doctorName;
  if (doctorName !== undefined && doctorName !== ownName && req.doctor.role === 'doctor' && !hasPermission(req.doctor, 'manage_other_appointments')) {
    effectiveDoctorName = ownName;
  }

  const patch = {};
  if (patientName !== undefined) patch.patient_name = patientName;
  if (patientPhone !== undefined) patch.patient_phone = patientPhone || null;
  if (startTime !== undefined) patch.start_time = startTime;
  if (endTime !== undefined) patch.end_time = endTime;
  if (doctorColor !== undefined) patch.doctor_color = doctorColor || null;
  if (effectiveDoctorName !== undefined) patch.doctor_name = effectiveDoctorName || null;
  if (status !== undefined) patch.status = status;
  if (status === 'cancelled') patch.cancelled_at = new Date().toISOString();
  else if (status !== undefined) patch.cancelled_at = null; // restoring or any other status clears it
  if (paid !== undefined) patch.paid = paid;
  if (visitType !== undefined) patch.visit_type = visitType;
  if (ownPatient !== undefined) patch.own_patient = !!ownPatient;
  if (isFree !== undefined){ patch.is_free = isFree; if(isFree) patch.paid = true; }
  // Check-in: anyone signed in can mark a patient as arrived (or undo it) — no extra permission, the secretary does this all day.
  if (arrived !== undefined) patch.arrived_at = arrived ? new Date().toISOString() : null;
  if (Object.keys(patch).length === 0) return res.status(400).json({ error: 'Nothing to update.' });
  try {
    const url = `${SUPABASE_URL}/rest/v1/appointments?id=eq.${encodeURIComponent(req.params.id)}`;
    const upstream = await fetch(url, {
      method: 'PATCH',
      headers: {
        apikey: SUPABASE_SERVICE_KEY,
        Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
        'Content-Type': 'application/json',
        Prefer: 'return=representation',
      },
      body: JSON.stringify(patch),
    });
    const data = await upstream.text();
    res.status(upstream.status).type('application/json').send(data);

    if (upstream.ok && (status === 'cancelled' || startTime !== undefined || doctorName !== undefined)) {
      try {
        const rows = JSON.parse(data);
        const changed = Array.isArray(rows) ? rows[0] : rows;
        const kind = status === 'cancelled' ? 'cancelled' : 'moved';
        pushAppointmentChange(kind, changed, req.doctor.email).catch(e => console.error('Push alert failed:', e.message));
      } catch (e) { /* the alert is optional */ }
    }

    if (upstream.ok && arrived === true) {
      try {
        const rows = JSON.parse(data);
        const updatedAppt = Array.isArray(rows) ? rows[0] : rows;
        notifyDoctorArrivalTelegram(updatedAppt).catch(e => console.error('Telegram arrival alert failed:', e.message));
      } catch (e) { /* the alert is optional */ }
    }

    if (upstream.ok && (doctorName !== undefined || patientName !== undefined)) {
      try {
        const rows = JSON.parse(data);
        const updated = Array.isArray(rows) ? rows[0] : rows;
        if (updated && updated.patient_name && updated.doctor_name) {
          const checkUrl = `${SUPABASE_URL}/rest/v1/sessions?patient_name=eq.${encodeURIComponent(updated.patient_name)}&doctor_name=eq.${encodeURIComponent(updated.doctor_name)}&select=id&limit=1`;
          const checkRes = await fetch(checkUrl, { headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` } });
          const existing = await checkRes.json();
          if (!Array.isArray(existing) || existing.length === 0) {
            await fetch(`${SUPABASE_URL}/rest/v1/sessions`, {
              method: 'POST',
              headers: {
                apikey: SUPABASE_SERVICE_KEY,
                Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
                'Content-Type': 'application/json',
              },
              body: JSON.stringify({
                id: crypto.randomUUID(),
                patient_name: updated.patient_name,
                doctor_name: updated.doctor_name,
                session_date: updated.start_time ? new Date(updated.start_time).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' }) : null,
                session_type: 'assessment',
                updated_at: new Date().toISOString(),
              }),
            });
          }
        }
      } catch (fileErr) {
        console.error('Auto-create documentation file failed on edit (non-fatal):', fileErr);
      }
    }
  } catch (err) {
    console.error('Appointment PATCH error:', err);
    res.status(500).json({ error: 'Failed to update appointment: ' + err.message });
  }
});

// ---- DELETE /api/appointments/:id ----
app.delete('/api/appointments/:id', requireApprovedAny, ownApptGuard, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  try {
    let beforeDelete = null;
    if (PUSH_GATEWAY_SECRET) {
      try {
        const pr = await fetch(`${SUPABASE_URL}/rest/v1/appointments?id=eq.${encodeURIComponent(req.params.id)}&select=patient_name,start_time,doctor_name,doctor_color&limit=1`, { headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` }, signal: AbortSignal.timeout(4000) });
        const pj = pr.ok ? await pr.json() : [];
        beforeDelete = Array.isArray(pj) ? pj[0] : null;
      } catch (e) { /* optional */ }
    }
    const url = `${SUPABASE_URL}/rest/v1/appointments?id=eq.${encodeURIComponent(req.params.id)}`;
    const upstream = await fetch(url, {
      method: 'DELETE',
      headers: {
        apikey: SUPABASE_SERVICE_KEY,
        Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
      },
    });
    res.status(upstream.status).json({ ok: upstream.ok });
    if (upstream.ok && beforeDelete) pushAppointmentChange('deleted', beforeDelete, req.doctor.email).catch(e => console.error('Push alert failed:', e.message));
  } catch (err) {
    console.error('Appointment DELETE error:', err);
    res.status(500).json({ error: 'Failed to delete appointment: ' + err.message });
  }
});

// ---- WhatsApp webhook (Meta calls these directly, so no doctor-auth
// middleware here — protected by the verify token instead). ----
const META_WEBHOOK_VERIFY_TOKEN = process.env.META_WEBHOOK_VERIFY_TOKEN || 'empower_verify_2026';

app.get('/api/whatsapp/webhook', (req, res) => {
  const mode = req.query['hub.mode'];
  const token = req.query['hub.verify_token'];
  const challenge = req.query['hub.challenge'];
  if (mode === 'subscribe' && token === META_WEBHOOK_VERIFY_TOKEN) {
    res.status(200).send(challenge);
  } else {
    res.sendStatus(403);
  }
});

app.post('/api/whatsapp/webhook', (req, res) => {
  // Logs incoming messages/status updates for now (visible in Render logs).
  // This is the hook point for the payment-confirmation flow later: detect
  // whether a reply contains an image, and if not, resend the payment link.
  console.log('WhatsApp webhook event:', JSON.stringify(req.body));
  res.sendStatus(200);
});

// ---- WhatsApp Cloud API: reusable sender ----
function normalizeEgyptPhone(raw){
  const trimmed = String(raw || '').trim();
  const digits = trimmed.replace(/[^\d]/g, '');
  if(!digits) return digits;
  // Explicit international format ("+44…" or "0044…") — keep the country code as typed.
  if(trimmed.startsWith('+')) return digits;
  if(digits.startsWith('00')) return digits.slice(2);
  // Egyptian local format (01xxxxxxxxx, or a landline like 02xxxxxxxx).
  if(digits.startsWith('0')) return '20' + digits.slice(1);
  // Already Egyptian international (20 + 10 digits).
  if(digits.startsWith('20') && digits.length === 12) return digits;
  // Egyptian mobile typed without the leading 0 (1[0125] + 8 digits).
  if(/^1[0125]\d{8}$/.test(digits)) return '20' + digits;
  // Long enough to already carry a country code (e.g. 447762863623 typed without "+") — leave it alone.
  if(digits.length >= 11) return digits;
  // Short leftover: assume Egyptian.
  return '20' + digits;
}

// Meta requires an APPROVED template (not free-form text) for any message
// outside an active 24h customer-initiated window — the same whether you
// go direct or through a BSP. `params` is an array of plain strings for
// the template's {{1}} {{2}} {{3}}... body variables; pass an empty array
// for a template with no variables (package_policy, recovery_session_policy).
async function sendWhatsAppTemplate(phone, templateName, params) {
  const META_PHONE_NUMBER_ID = process.env.META_WHATSAPP_PHONE_NUMBER_ID || '';
  const META_ACCESS_TOKEN = process.env.META_WHATSAPP_ACCESS_TOKEN || '';
  if (!META_PHONE_NUMBER_ID || !META_ACCESS_TOKEN) {
    throw new Error('WhatsApp Business API is not set up — set META_WHATSAPP_PHONE_NUMBER_ID and META_WHATSAPP_ACCESS_TOKEN in Render.');
  }
  const normalizedPhone = normalizeEgyptPhone(phone);
  const url = `https://graph.facebook.com/v21.0/${META_PHONE_NUMBER_ID}/messages`;
  const template = { name: templateName, language: { code: 'en' } };
  if (params && params.length > 0) {
    template.components = [{ type: 'body', parameters: params.map(p => ({ type: 'text', text: String(p || '') })) }];
  }
  const payload = { messaging_product: 'whatsapp', to: normalizedPhone, type: 'template', template };
  const upstream = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${META_ACCESS_TOKEN}` },
    body: JSON.stringify(payload),
  });
  const data = await upstream.json();
  if (!upstream.ok) {
    throw new Error((data.error && data.error.message) || 'Failed to send WhatsApp message.');
  }
  return data.messages && data.messages[0] && data.messages[0].id;
}

app.post('/api/whatsapp/send-reminder', requireApprovedAny, async (req, res) => {
  const { patientPhone, patientName, appointmentTime, appointmentDate, templateName } = req.body || {};
  if (!patientPhone) return res.status(400).json({ error: 'Missing patientPhone.' });
  const finalTemplate = templateName || 'appointment_confirmation';
  // Static (no-variable) templates vs. the two that take name/date/time.
  const noVariableTemplates = ['package_policy', 'recovery_session_policy', 'instapay_payment'];
  const params = noVariableTemplates.includes(finalTemplate)
    ? []
    : [patientName || '', appointmentDate || '', appointmentTime || ''];
  try {
    const messageId = await sendWhatsAppTemplate(patientPhone, finalTemplate, params);
    res.json({ ok: true, messageId });
  } catch (err) {
    console.error('Meta WhatsApp send failed:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ---- Sends "appointment_confirmation" to everyone booked on a given day ----
// Shared by the (currently disabled) midnight auto-scheduler and the
// manual "send now" button — same logic either way, just triggered
// differently. Returns a summary instead of just logging, so the manual
// trigger can show the owner exactly what happened.
async function sendConfirmationsForDate(targetDate, templateName) {
  const finalTemplate = templateName || 'appointment_confirmation';
  const noVariableTemplates = ['package_policy', 'recovery_session_policy'];
  const start = new Date(targetDate.getFullYear(), targetDate.getMonth(), targetDate.getDate(), 0, 0, 0);
  const end = new Date(targetDate.getFullYear(), targetDate.getMonth(), targetDate.getDate(), 23, 59, 59);
  const url = `${SUPABASE_URL}/rest/v1/appointments?start_time=gte.${encodeURIComponent(start.toISOString())}&start_time=lte.${encodeURIComponent(end.toISOString())}&status=neq.cancelled&deleted_at=is.null`;
  const res = await fetch(url, { headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` } });
  const appointments = await res.json();
  const summary = { total: 0, sent: 0, skippedNoPhone: 0, failed: [] };
  if (!Array.isArray(appointments)) return summary;
  summary.total = appointments.length;
  for (const appt of appointments) {
    if (!appt.patient_phone) { summary.skippedNoPhone++; continue; }
    const apptDate = new Date(appt.start_time);
    const dateLabel = apptDate.toLocaleDateString('en-GB', { timeZone: 'Africa/Cairo', weekday: 'long', day: 'numeric', month: 'long' });
    const timeLabel = apptDate.toLocaleTimeString('en-US', { timeZone: 'Africa/Cairo', hour: 'numeric', minute: '2-digit', hour12: true });
    const params = noVariableTemplates.includes(finalTemplate) ? [] : [appt.patient_name || '', dateLabel, timeLabel];
    try {
      await sendWhatsAppTemplate(appt.patient_phone, finalTemplate, params);
      summary.sent++;
    } catch (err) {
      summary.failed.push({ patient: appt.patient_name, error: err.message });
    }
    await new Promise(r => setTimeout(r, 1200)); // gentle pacing, avoid tripping Meta's rate limits
  }
  return summary;
}

// ---- POST /api/whatsapp/send-confirmations-now ----
// The manual "press whenever you need it" alternative to the disabled
// midnight scheduler. Defaults to tomorrow's appointments if no date is
// given (matches what the scheduler would have sent).
app.post('/api/whatsapp/send-confirmations-now', requireOwnerOrPermission('send_whatsapp'), async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  try {
    const { date, templateName } = req.body || {};
    let targetDate;
    if (date) {
      const [y, m, d] = date.split('-').map(Number);
      targetDate = new Date(y, m - 1, d);
    } else {
      const nowCairo = new Date(new Date().toLocaleString('en-US', { timeZone: 'Africa/Cairo' }));
      targetDate = new Date(nowCairo.getFullYear(), nowCairo.getMonth(), nowCairo.getDate() + 1);
    }
    const summary = await sendConfirmationsForDate(targetDate, templateName);
    res.json(summary);
  } catch (err) {
    console.error('Manual send-confirmations error:', err);
    res.status(500).json({ error: 'Failed to send: ' + err.message });
  }
});

// ---- Automatic midnight sending ----
// Runs inside this same always-on process (kept awake by the UptimeRobot
// monitor) — no separate cron infrastructure needed. Checks every 5
// minutes; once per day, the first check that lands between 00:00 and
// 00:10 Cairo time fires the run and then waits for the date to change
// again before it can fire a second time.
let lastAutoSendDate = null;
async function runMidnightAutoConfirmations() {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return;
  const nowCairo = new Date(new Date().toLocaleString('en-US', { timeZone: 'Africa/Cairo' }));
  const todayKey = nowCairo.toISOString().slice(0, 10);
  const isMidnightWindow = nowCairo.getHours() === 0 && nowCairo.getMinutes() < 10;
  if (!isMidnightWindow || lastAutoSendDate === todayKey) return;
  lastAutoSendDate = todayKey;
  console.log(`[auto-confirm] Running for ${todayKey}`);
  try {
    const tomorrow = new Date(nowCairo.getFullYear(), nowCairo.getMonth(), nowCairo.getDate() + 1);
    const summary = await sendConfirmationsForDate(tomorrow);
    console.log(`[auto-confirm] Done — ${summary.sent}/${summary.total} sent, ${summary.failed.length} failed.`);
  } catch (err) {
    console.error('[auto-confirm] Run failed:', err);
  }
}
// DISABLED for now — the Cloud API test showed "sent" without an actual
// delivery (likely needs Meta Business Verification / a recipient
// allow-list before it can message real numbers). Re-enable this line
// once a test message is confirmed actually arriving on WhatsApp.
// setInterval(runMidnightAutoConfirmations, 5 * 60 * 1000);

// ---- GET /api/appointments/:id/notes ----
app.get('/api/appointments/:id/notes', requireApprovedAny, ownApptGuard, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  try {
    const url = `${SUPABASE_URL}/rest/v1/appointments?id=eq.${encodeURIComponent(req.params.id)}&select=notes,patient_name`;
    const upstream = await fetch(url, {
      headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` },
    });
    const rows = await upstream.json();
    const row = Array.isArray(rows) && rows.length > 0 ? rows[0] : null;
    res.json({ patientName: row ? row.patient_name : null, notes: (row && row.notes) || [] });
  } catch (err) {
    console.error('Appointment notes GET error:', err);
    res.status(500).json({ error: 'Failed to load notes: ' + err.message });
  }
});

// ---- DELETE /api/appointments/:id/notes ---- (remove one note by its timestamp)
app.delete('/api/appointments/:id/notes', requireApprovedAny, ownApptGuard, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  const { at } = req.query;
  if (!at) return res.status(400).json({ error: 'Missing at (note timestamp).' });
  try {
    const getUrl = `${SUPABASE_URL}/rest/v1/appointments?id=eq.${encodeURIComponent(req.params.id)}&select=notes`;
    const getRes = await fetch(getUrl, {
      headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` },
    });
    const rows = await getRes.json();
    const existingNotes = (Array.isArray(rows) && rows[0] && rows[0].notes) || [];
    const updatedNotes = existingNotes.filter(n => n.at !== at);
    const patchUrl = `${SUPABASE_URL}/rest/v1/appointments?id=eq.${encodeURIComponent(req.params.id)}`;
    const patchRes = await fetch(patchUrl, {
      method: 'PATCH',
      headers: {
        apikey: SUPABASE_SERVICE_KEY,
        Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ notes: updatedNotes }),
    });
    if (!patchRes.ok) {
      const errBody = await patchRes.text();
      throw new Error(errBody);
    }
    res.json({ notes: updatedNotes });
  } catch (err) {
    console.error('Appointment notes DELETE error:', err);
    res.status(500).json({ error: 'Failed to delete note: ' + err.message });
  }
});

// ---- POST /api/appointments/:id/notes ---- (append one note)
app.post('/api/appointments/:id/notes', requireApprovedAny, ownApptGuard, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  const { text } = req.body || {};
  if (!text || !text.trim()) return res.status(400).json({ error: 'Missing note text.' });
  try {
    const getUrl = `${SUPABASE_URL}/rest/v1/appointments?id=eq.${encodeURIComponent(req.params.id)}&select=notes`;
    const getRes = await fetch(getUrl, {
      headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` },
    });
    const rows = await getRes.json();
    const existingNotes = (Array.isArray(rows) && rows[0] && rows[0].notes) || [];
    const newNote = {
      text: text.trim(),
      author: req.doctor.name || req.doctor.email,
      at: new Date().toISOString(),
    };
    const updatedNotes = [...existingNotes, newNote];
    const patchUrl = `${SUPABASE_URL}/rest/v1/appointments?id=eq.${encodeURIComponent(req.params.id)}`;
    const patchRes = await fetch(patchUrl, {
      method: 'PATCH',
      headers: {
        apikey: SUPABASE_SERVICE_KEY,
        Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ notes: updatedNotes }),
    });
    if (!patchRes.ok) {
      const errBody = await patchRes.text();
      throw new Error(errBody);
    }
    res.json({ notes: updatedNotes });
  } catch (err) {
    console.error('Appointment notes POST error:', err);
    res.status(500).json({ error: 'Failed to add note: ' + err.message });
  }
});

// ---- PATCH /api/sessions/rename-doctor ----
// A session's doctor_name is a snapshot taken when it was saved (same
// idea as appointments' doctor_color/doctor_name) — it doesn't
// automatically follow later renames or account merges. This lets the
// owner fix the sidebar showing the same person's sessions split across
// several name spellings, by bulk-renaming every session under fromName
// to toName in one go.
// ---- POST /api/sessions/merge ---- combine two session "files" into one
app.post('/api/sessions/merge', requireApprovedDoctor, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  const { keepId, removeId } = req.body || {};
  if (!keepId || !removeId) return res.status(400).json({ error: 'Missing keepId or removeId.' });
  try {
    const headers = { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` };
    const [keepRes, removeRes] = await Promise.all([
      fetch(`${SUPABASE_URL}/rest/v1/sessions?id=eq.${encodeURIComponent(keepId)}`, { headers }),
      fetch(`${SUPABASE_URL}/rest/v1/sessions?id=eq.${encodeURIComponent(removeId)}`, { headers }),
    ]);
    const [keepRows, removeRows] = await Promise.all([keepRes.json(), removeRes.json()]);
    const keepSession = Array.isArray(keepRows) && keepRows[0];
    const removeSession = Array.isArray(removeRows) && removeRows[0];
    if (!keepSession || !removeSession) return res.status(404).json({ error: 'One or both sessions not found.' });

    const mergedNote = [keepSession.note, removeSession.note].filter(Boolean).join('\n\n---\n\n');
    const mergedTranscript = [...(keepSession.transcript || []), ...(removeSession.transcript || [])];

    const patchRes = await fetch(`${SUPABASE_URL}/rest/v1/sessions?id=eq.${encodeURIComponent(keepId)}`, {
      method: 'PATCH',
      headers: { ...headers, 'Content-Type': 'application/json', Prefer: 'return=representation' },
      body: JSON.stringify({ note: mergedNote, transcript: mergedTranscript, updated_at: new Date().toISOString() }),
    });
    if (!patchRes.ok) throw new Error(await patchRes.text());

    await fetch(`${SUPABASE_URL}/rest/v1/sessions?id=eq.${encodeURIComponent(removeId)}`, {
      method: 'DELETE',
      headers,
    });

    const updated = await patchRes.json();
    res.json(Array.isArray(updated) ? updated[0] : updated);
  } catch (err) {
    console.error('Session merge error:', err);
    res.status(500).json({ error: 'Failed to merge sessions: ' + err.message });
  }
});

// ---- PATCH /api/sessions/rename-patient ---- merges a misspelled patient
// name's sessions into the correct one (same trimmed-match approach as
// rename-doctor above).
app.patch('/api/sessions/rename-patient', requireApprovedDoctor, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  const { fromName, toName } = req.body || {};
  if (!fromName || !toName) return res.status(400).json({ error: 'Missing fromName or toName.' });
  try {
    const allRes = await fetch(`${SUPABASE_URL}/rest/v1/sessions?select=id,patient_name`, {
      headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` },
    });
    const allSessions = await allRes.json();
    if (!allRes.ok) {
      console.error('Session rename-patient: could not list sessions', allRes.status, allSessions);
      return res.status(500).json({ error: 'Could not read sessions to merge.' });
    }
    const target = fromName.trim().toLowerCase();
    const matchingIds = (allSessions || [])
      .filter(s => (s.patient_name || '').trim().toLowerCase() === target)
      .map(s => s.id);
    if (matchingIds.length === 0) {
      return res.status(404).json({ error: `No sessions found under "${fromName}" (nothing to merge).` });
    }
    const idList = matchingIds.map(id => `"${id}"`).join(',');
    const updateRes = await fetch(`${SUPABASE_URL}/rest/v1/sessions?id=in.(${idList})`, {
      method: 'PATCH',
      headers: {
        apikey: SUPABASE_SERVICE_KEY,
        Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
        'Content-Type': 'application/json',
        Prefer: 'return=representation',
      },
      body: JSON.stringify({ patient_name: toName.trim() }),
    });
    const data = await updateRes.json();
    if (!updateRes.ok) {
      console.error('Session rename-patient failed:', updateRes.status, data);
      return res.status(500).json({ error: 'Failed to merge sessions.' });
    }
    res.json({ ok: true, count: Array.isArray(data) ? data.length : 0 });
  } catch (err) {
    console.error('Session rename-patient error:', err);
    res.status(500).json({ error: 'Failed to merge sessions: ' + err.message });
  }
});

app.patch('/api/sessions/rename-doctor', requireOwnerDoctor, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  const { fromName, toName } = req.body || {};
  if (!fromName || !toName) return res.status(400).json({ error: 'Missing fromName or toName.' });
  try {
    // Fetch every session and match by TRIMMED name in JS, rather than an
    // exact eq. filter against the raw column — a stray leading/trailing
    // space in the stored value (invisible in the UI, which trims for
    // display) would otherwise make the filter match zero rows while the
    // endpoint still reports success, so nothing visibly changes.
    const allRes = await fetch(`${SUPABASE_URL}/rest/v1/sessions?select=id,doctor_name`, {
      headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` },
    });
    const allSessions = await allRes.json();
    if (!allRes.ok) {
      console.error('Session rename-doctor: could not list sessions', allRes.status, allSessions);
      return res.status(500).json({ error: 'Could not read sessions to merge.' });
    }
    const target = fromName.trim().toLowerCase();
    const matchingIds = (allSessions || [])
      .filter(s => (s.doctor_name || '').trim().toLowerCase() === target)
      .map(s => s.id);
    if (matchingIds.length === 0) {
      return res.status(404).json({ error: `No sessions found under "${fromName}" (nothing to merge).` });
    }
    const idList = matchingIds.map(id => `"${id}"`).join(',');
    const updateRes = await fetch(`${SUPABASE_URL}/rest/v1/sessions?id=in.(${idList})`, {
      method: 'PATCH',
      headers: {
        apikey: SUPABASE_SERVICE_KEY,
        Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
        'Content-Type': 'application/json',
        Prefer: 'return=representation',
      },
      body: JSON.stringify({ doctor_name: toName.trim() }),
    });
    const data = await updateRes.json();
    if (!updateRes.ok) {
      console.error('Session rename-doctor failed:', updateRes.status, data);
      return res.status(500).json({ error: 'Failed to rename sessions.' });
    }
    res.json({ ok: true, count: Array.isArray(data) ? data.length : 0 });
  } catch (err) {
    console.error('Session rename-doctor error:', err);
    res.status(500).json({ error: 'Failed to rename sessions: ' + err.message });
  }
});

app.post('/api/sessions', requireApprovedDoctor, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  const { id, patientName, sessionDate, sessionType, transcript, note } = req.body || {};
  if (!id || !patientName) return res.status(400).json({ error: 'Missing id or patientName.' });
  try {
    // If this note already exists, keep its original author: someone else
    // editing it must not move it to their own list.
    let keepDoctor = null;
    try {
      const er = await fetch(`${SUPABASE_URL}/rest/v1/sessions?id=eq.${encodeURIComponent(id)}&select=doctor_name&limit=1`, { headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` } });
      const er2 = await er.json();
      if (Array.isArray(er2) && er2[0] && er2[0].doctor_name) keepDoctor = er2[0].doctor_name;
    } catch (e) { /* fall back to the editor's name */ }
    const url = `${SUPABASE_URL}/rest/v1/sessions?on_conflict=id`;
    const upstream = await fetch(url, {
      method: 'POST',
      headers: {
        apikey: SUPABASE_SERVICE_KEY,
        Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
        'Content-Type': 'application/json',
        Prefer: 'resolution=merge-duplicates,return=representation',
      },
      body: JSON.stringify({
        id,
        patient_name: patientName,
        session_date: sessionDate || null,
        session_type: sessionType || null,
        transcript: transcript || null,
        note: note || null,
        doctor_name: keepDoctor || req.doctor.name || req.doctor.email,
        updated_at: new Date().toISOString(),
      }),
    });
    const data = await upstream.text();
    res.status(upstream.status).type('application/json').send(data);
  } catch (err) {
    console.error('Sessions POST error:', err);
    res.status(500).json({ error: 'Failed to save session: ' + err.message });
  }
});

app.get('/api/sessions', requireApprovedDoctor, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  try {
    const { patientName, order } = req.query;
    let url = `${SUPABASE_URL}/rest/v1/sessions?order=${order === 'asc' ? 'created_at.asc' : 'created_at.desc'}`;
    if (patientName) {
      url += `&patient_name=ilike.${encodeURIComponent('%' + patientName + '%')}`;
    }
    // Without view_other_patients, a doctor only sees their OWN patients'
    // files — not the whole clinic's.
    const sbHeaders = { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` };
    if (!hasPermission(req.doctor, 'view_other_patients') || isOwnOnly(req.doctor)) {
      // A patient's file belongs to the PATIENT, not to whoever typed the note.
      // So a doctor sees (a) notes they wrote, plus (b) EVERY note, by anyone,
      // for patients they have appointments with.
      const me = req.doctor.name || req.doctor.email;
      const ar = await fetch(`${SUPABASE_URL}/rest/v1/appointments?select=patient_name&deleted_at=is.null&doctor_name=eq.${encodeURIComponent(me)}&limit=10000`, { headers: sbHeaders });
      const arows = await ar.json();
      const myPatients = new Set((Array.isArray(arows) ? arows : []).map(r => String(r.patient_name || '').trim().toLowerCase()).filter(Boolean));
      const lr = await fetch(`${SUPABASE_URL}/rest/v1/sessions?select=id,patient_name,doctor_name&limit=20000`, { headers: sbHeaders });
      const lrows = await lr.json();
      if (!lr.ok || !Array.isArray(lrows)) return res.status(500).json({ error: 'Failed to load sessions.' });
      const ids = lrows
        .filter(r => r.doctor_name === me || myPatients.has(String(r.patient_name || '').trim().toLowerCase()))
        .filter(r => !patientName || String(r.patient_name || '').toLowerCase().includes(String(patientName).toLowerCase()))
        .map(r => r.id);
      const out = [];
      for (let i = 0; i < ids.length; i += 40) {
        const chunk = ids.slice(i, i + 40).map(x => '"' + String(x).replace(/"/g, '') + '"').join(',');
        const cr = await fetch(`${SUPABASE_URL}/rest/v1/sessions?id=in.(${encodeURIComponent(chunk)})&order=${order === 'asc' ? 'created_at.asc' : 'created_at.desc'}`, { headers: sbHeaders });
        const crows = await cr.json();
        if (!cr.ok || !Array.isArray(crows)) return res.status(500).json({ error: 'Failed to load sessions.' });
        out.push(...crows);
      }
      out.sort((a, b) => (order === 'asc' ? 1 : -1) * (new Date(a.created_at) - new Date(b.created_at)));
      return res.json(out);
    }
    const upstream = await fetch(url, { headers: sbHeaders });
    const data = await upstream.text();
    res.status(upstream.status).type('application/json').send(data);
  } catch (err) {
    console.error('Sessions GET error:', err);
    res.status(500).json({ error: 'Failed to load sessions: ' + err.message });
  }
});

// ---- Session images (Supabase Storage — cross-device, unlike the old
// device-only IndexedDB storage) ----
const IMAGE_BUCKET = 'session-images';

app.post('/api/sessions/:id/images', requireApprovedDoctor, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  const { base64Data, mimeType, filename } = req.body || {};
  if (!base64Data || !mimeType) return res.status(400).json({ error: 'Missing base64Data or mimeType.' });
  try {
    const bytes = Buffer.from(base64Data, 'base64');
    const ext = (mimeType.split('/')[1] || 'jpg').replace(/[^a-z0-9]/gi, '');
    const safeName = (filename || 'image').replace(/[^a-zA-Z0-9._-]/g, '_');
    const path = `${req.params.id}/${Date.now()}_${safeName}.${ext}`;
    const uploadUrl = `${SUPABASE_URL}/storage/v1/object/${IMAGE_BUCKET}/${path}`;
    const upstream = await fetch(uploadUrl, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
        'Content-Type': mimeType,
        'x-upsert': 'false',
      },
      body: bytes,
    });
    const data = await upstream.json();
    if (!upstream.ok) {
      console.error('Image upload failed:', data);
      return res.status(500).json({ error: data.message || 'Failed to upload image.' });
    }
    res.json({ ok: true, path });
  } catch (err) {
    console.error('Image upload error:', err);
    res.status(500).json({ error: 'Failed to upload image: ' + err.message });
  }
});

// Videos go in the same private bucket as the images (so the existing gallery,
// signed links and delete all work for them). The browser sends the raw file;
// 50 MB is Supabase's default per-file limit on the free plan.
const VIDEO_MAX_BYTES = 50 * 1024 * 1024;
const VIDEO_EXT = { 'video/mp4': 'mp4', 'video/quicktime': 'mov', 'video/webm': 'webm', 'video/x-m4v': 'm4v', 'video/3gpp': '3gp', 'video/x-matroska': 'mkv' };
app.post('/api/sessions/:id/videos', requireApprovedDoctor, express.raw({ type: () => true, limit: VIDEO_MAX_BYTES }), async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  const mimeType = String(req.headers['content-type'] || '').split(';')[0].trim().toLowerCase();
  if (!mimeType.startsWith('video/')) return res.status(400).json({ error: 'That file is not a video.' });
  if (!Buffer.isBuffer(req.body) || req.body.length === 0) return res.status(400).json({ error: 'Empty video.' });
  try {
    const ext = VIDEO_EXT[mimeType] || 'mp4';
    const base = String(req.query.filename || 'video').replace(/\.[^.]+$/, '').replace(/[^a-zA-Z0-9_-]/g, '_').slice(0, 60) || 'video';
    const path = `${req.params.id}/${Date.now()}_${base}.${ext}`;
    const upstream = await fetch(`${SUPABASE_URL}/storage/v1/object/${IMAGE_BUCKET}/${path}`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`, 'Content-Type': mimeType, 'x-upsert': 'false' },
      body: req.body,
    });
    const data = await upstream.json().catch(() => ({}));
    if (!upstream.ok) {
      console.error('Video upload failed:', data);
      return res.status(500).json({ error: data.message || 'Failed to upload video (check the storage bucket allows video files and the size limit).' });
    }
    res.json({ ok: true, path });
  } catch (err) {
    console.error('Video upload error:', err);
    res.status(500).json({ error: 'Failed to upload video: ' + err.message });
  }
});

app.get('/api/sessions/:id/images', requireApprovedDoctor, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  try {
    const listUrl = `${SUPABASE_URL}/storage/v1/object/list/${IMAGE_BUCKET}`;
    const listRes = await fetch(listUrl, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ prefix: `${req.params.id}/`, limit: 200, sortBy: { column: 'created_at', order: 'asc' } }),
    });
    const files = await listRes.json();
    if (!listRes.ok) {
      console.error('Image list failed:', files);
      return res.status(500).json({ error: 'Failed to list images.' });
    }
    if (!Array.isArray(files) || files.length === 0) return res.json([]);
    // Batch-sign all paths in one call rather than one request per image.
    const signUrl = `${SUPABASE_URL}/storage/v1/object/sign/${IMAGE_BUCKET}`;
    const signRes = await fetch(signUrl, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        expiresIn: 3600,
        paths: files.map(f => `${req.params.id}/${f.name}`),
      }),
    });
    const signed = await signRes.json();
    if (!signRes.ok) {
      console.error('Image sign failed:', signed);
      return res.status(500).json({ error: 'Failed to sign image URLs.' });
    }
    const result = files.map((f, i) => ({
      path: `${req.params.id}/${f.name}`,
      filename: f.name,
      url: signed[i] && signed[i].signedURL ? `${SUPABASE_URL}/storage/v1${signed[i].signedURL}` : null,
      createdAt: f.created_at,
    }));
    res.json(result);
  } catch (err) {
    console.error('Image list error:', err);
    res.status(500).json({ error: 'Failed to list images: ' + err.message });
  }
});

app.delete('/api/sessions/:id/images', requireApprovedDoctor, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  const { path } = req.body || {};
  if (!path || !path.startsWith(`${req.params.id}/`)) return res.status(400).json({ error: 'Invalid or missing path.' });
  try {
    const deleteUrl = `${SUPABASE_URL}/storage/v1/object/${IMAGE_BUCKET}`;
    const upstream = await fetch(deleteUrl, {
      method: 'DELETE',
      headers: {
        Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ prefixes: [path] }),
    });
    if (!upstream.ok) {
      const errData = await upstream.json();
      console.error('Image delete failed:', errData);
      return res.status(500).json({ error: 'Failed to delete image.' });
    }
    res.json({ ok: true });
  } catch (err) {
    console.error('Image delete error:', err);
    res.status(500).json({ error: 'Failed to delete image: ' + err.message });
  }
});

app.post('/api/sessions/:id/request-delete', requireApprovedDoctor, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  try {
    const url = `${SUPABASE_URL}/rest/v1/sessions?id=eq.${encodeURIComponent(req.params.id)}`;
    const upstream = await fetch(url, {
      method: 'PATCH',
      headers: {
        apikey: SUPABASE_SERVICE_KEY,
        Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
        'Content-Type': 'application/json',
        Prefer: 'return=representation',
      },
      body: JSON.stringify({
        delete_requested: true,
        delete_requested_by: req.doctor.name || req.doctor.email,
        delete_requested_at: new Date().toISOString(),
      }),
    });
    const data = await upstream.text();
    res.status(upstream.status).type('application/json').send(data);
  } catch (err) {
    console.error('Request-delete error:', err);
    res.status(500).json({ error: 'Failed to request delete: ' + err.message });
  }
});

app.get('/api/sessions/pending-deletes', requireOwnerDoctor, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  try {
    const url = `${SUPABASE_URL}/rest/v1/sessions?delete_requested=eq.true&order=delete_requested_at.desc`;
    const upstream = await fetch(url, { headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` } });
    const data = await upstream.text();
    res.status(upstream.status).type('application/json').send(data);
  } catch (err) {
    console.error('Pending-deletes GET error:', err);
    res.status(500).json({ error: 'Failed to load pending deletes: ' + err.message });
  }
});

app.post('/api/sessions/:id/approve-delete', requireOwnerDoctor, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  try {
    const url = `${SUPABASE_URL}/rest/v1/sessions?id=eq.${encodeURIComponent(req.params.id)}`;
    const upstream = await fetch(url, {
      method: 'DELETE',
      headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` },
    });
    res.status(upstream.status).json({ ok: upstream.ok });
  } catch (err) {
    console.error('Approve-delete error:', err);
    res.status(500).json({ error: 'Failed to delete session: ' + err.message });
  }
});

app.post('/api/sessions/:id/reject-delete', requireOwnerDoctor, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  try {
    const url = `${SUPABASE_URL}/rest/v1/sessions?id=eq.${encodeURIComponent(req.params.id)}`;
    const upstream = await fetch(url, {
      method: 'PATCH',
      headers: {
        apikey: SUPABASE_SERVICE_KEY,
        Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ delete_requested: false, delete_requested_by: null, delete_requested_at: null }),
    });
    res.status(upstream.status).json({ ok: upstream.ok });
  } catch (err) {
    console.error('Reject-delete error:', err);
    res.status(500).json({ error: 'Failed to reject delete: ' + err.message });
  }
});

// ---- POST /api/doctors/checkin ----
app.post('/api/doctors/checkin', async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  const token = extractBearerToken(req);
  // Distinguish "resuming with our own session token" (no new session
  // needed) from "a real Google token came in" (issue a fresh 30-day app
  // session, this is a first sign-in on this device).
  const existingSession = await lookupAppSession(token);
  const email = existingSession ? existingSession.email : await verifyGoogleToken(token);
  if (!email) return res.status(401).json({ error: 'Invalid or expired Google token.' });
  const newSessionToken = existingSession ? null : await createAppSession(email);
  logActivity(req, existingSession ? 'open' : 'google', email);
  const { name } = req.body || {};
  try {
    const existing = await lookupDoctor(email);
    if (existing) return res.json(newSessionToken ? { ...existing, session_token: newSessionToken } : existing);

    // No row for this exact Google email yet — check whether the owner
    // already added this person manually (by name) before they ever
    // signed in. If so, link this Google email into that existing row
    // (keeping their color/status/history) instead of creating a new one.
    const manualMatch = await lookupManualDoctorByName(name);
    if (manualMatch) {
      const linkUrl = `${SUPABASE_URL}/rest/v1/doctors?email=eq.${encodeURIComponent(manualMatch.email)}`;
      const linkRes = await fetch(linkUrl, {
        method: 'PATCH',
        headers: {
          apikey: SUPABASE_SERVICE_KEY,
          Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
          'Content-Type': 'application/json',
          Prefer: 'return=representation',
        },
        body: JSON.stringify({ email }),
      });
      const linked = await linkRes.json();
      if (!linkRes.ok) {
        console.error('Doctor auto-link failed:', linkRes.status, linked);
        return res.status(500).json({ error: 'Could not link your account: ' + (linked.message || JSON.stringify(linked)).slice(0, 300) });
      }
      const linkedRow = Array.isArray(linked) ? linked[0] : linked;
      return res.json(newSessionToken ? { ...linkedRow, session_token: newSessionToken } : linkedRow);
    }

    const insertRes = await fetch(`${SUPABASE_URL}/rest/v1/doctors`, {
      method: 'POST',
      headers: {
        apikey: SUPABASE_SERVICE_KEY,
        Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
        'Content-Type': 'application/json',
        Prefer: 'return=representation',
      },
      body: JSON.stringify({ email, name: name || email, status: 'pending' }),
    });
    const inserted = await insertRes.json();
    if (!insertRes.ok) {
      console.error('Doctor insert failed:', insertRes.status, inserted);
      return res.status(500).json({ error: 'Could not create doctor record: ' + (inserted.message || JSON.stringify(inserted)).slice(0, 300) });
    }
    const doctorRow = Array.isArray(inserted) ? inserted[0] : inserted;
    if (!doctorRow || !doctorRow.email) {
      console.error('Doctor insert returned unexpected shape:', inserted);
      return res.status(500).json({ error: 'Doctor record was created but the server response was malformed.' });
    }
    res.json(newSessionToken ? { ...doctorRow, session_token: newSessionToken } : doctorRow);
  } catch (err) {
    console.error('Doctor checkin error:', err);
    res.status(500).json({ error: 'Check-in failed: ' + err.message });
  }
});

// ---- POST /api/doctors/me/name ----
// Lets a signed-in doctor (any status — pending or approved) set their own
// display name at any time, so they're never stuck showing as their raw
// email. The email itself is taken from the verified token, never from
// client input, so nobody can rename another doctor's row.
app.post('/api/doctors/me/name', async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  const token = extractBearerToken(req);
  const email = await verifyGoogleToken(token);
  if (!email) return res.status(401).json({ error: 'Sign in with Google required.' });
  const { name } = req.body || {};
  if (!name || !name.trim()) return res.status(400).json({ error: 'Missing name.' });
  try {
    const existing = await lookupDoctor(email);
    if (!existing) return res.status(404).json({ error: 'You are not registered at this clinic yet — sign in first.' });
    const url = `${SUPABASE_URL}/rest/v1/doctors?email=eq.${encodeURIComponent(email)}`;
    const upstream = await fetch(url, {
      method: 'PATCH',
      headers: {
        apikey: SUPABASE_SERVICE_KEY,
        Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
        'Content-Type': 'application/json',
        Prefer: 'return=representation',
      },
      body: JSON.stringify({ name: name.trim() }),
    });
    const data = await upstream.json();
    if (!upstream.ok) {
      console.error('Name update failed:', upstream.status, data);
      return res.status(500).json({ error: 'Could not update name.' });
    }
    res.json(Array.isArray(data) ? data[0] : data);
  } catch (err) {
    console.error('Doctor name update error:', err);
    res.status(500).json({ error: 'Failed to update name: ' + err.message });
  }
});

// ---- POST /api/doctors/me/color ----
// Lets a signed-in doctor set their own calendar color (the "Your color
// on the clinic calendar" swatches in Settings). Previously that picker
// only saved to the device — it never told the server, so the doctors
// table (and anything reading from it) kept showing the old color. This
// also cascades the new color onto that doctor's own upcoming
// appointments, same as the owner/secretary color-panel endpoint does.
app.post('/api/doctors/me/color', async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  const token = extractBearerToken(req);
  const email = await verifyGoogleToken(token);
  if (!email) return res.status(401).json({ error: 'Sign in with Google required.' });
  const { color } = req.body || {};
  if (!color) return res.status(400).json({ error: 'Missing color.' });
  try {
    const existing = await lookupDoctor(email);
    if (!existing) return res.status(404).json({ error: 'You are not registered at this clinic yet — sign in first.' });
    const url = `${SUPABASE_URL}/rest/v1/doctors?email=eq.${encodeURIComponent(email)}`;
    const upstream = await fetch(url, {
      method: 'PATCH',
      headers: {
        apikey: SUPABASE_SERVICE_KEY,
        Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
        'Content-Type': 'application/json',
        Prefer: 'return=representation',
      },
      body: JSON.stringify({ color }),
    });
    const data = await upstream.json();
    if (!upstream.ok) {
      console.error('Self color update failed:', upstream.status, data);
      return res.status(500).json({ error: 'Could not update color.' });
    }
    if (existing.name) {
      const nowIso = new Date().toISOString();
      const cascadeUrl = `${SUPABASE_URL}/rest/v1/appointments?doctor_name=eq.${encodeURIComponent(existing.name)}&start_time=gte.${encodeURIComponent(nowIso)}`;
      const cascadeRes = await fetch(cascadeUrl, {
        method: 'PATCH',
        headers: {
          apikey: SUPABASE_SERVICE_KEY,
          Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ doctor_color: color }),
      });
      if (!cascadeRes.ok) {
        console.error('Self color cascade to appointments failed:', cascadeRes.status, await cascadeRes.text());
      }
    }
    res.json(Array.isArray(data) ? data[0] : data);
  } catch (err) {
    console.error('Self color update error:', err);
    res.status(500).json({ error: 'Failed to update color: ' + err.message });
  }
});

// ---- POST /api/auth/logout ----
// Revokes just the session token used for this request (normal sign-out).
app.post('/api/auth/logout', async (req, res) => {
  const token = extractBearerToken(req);
  if (!token) return res.json({ ok: true });
  try {
    await fetch(`${SUPABASE_URL}/rest/v1/app_sessions?token=eq.${encodeURIComponent(token)}`, {
      method: 'DELETE',
      headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` },
    });
    res.json({ ok: true });
  } catch (err) {
    console.error('Logout error:', err);
    res.json({ ok: true }); // don't block sign-out on the client either way
  }
});

// ---- POST /api/auth/logout-all ----
// Revokes EVERY session for the signed-in doctor (all devices) — for a
// lost or stolen phone, so old sessions stop working immediately rather
// than waiting out the 30-day expiry.
app.post('/api/auth/logout-all', requireApprovedAny, async (req, res) => {
  try {
    await fetch(`${SUPABASE_URL}/rest/v1/app_sessions?email=eq.${encodeURIComponent(req.doctor.email)}`, {
      method: 'DELETE',
      headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` },
    });
    res.json({ ok: true });
  } catch (err) {
    console.error('Logout-all error:', err);
    res.status(500).json({ error: 'Failed to revoke sessions: ' + err.message });
  }
});

app.post('/api/doctors/bootstrap-owner', async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  if (!OWNER_SECRET) return res.status(500).json({ error: 'Server is missing OWNER_SECRET.' });
  const provided = req.header('x-owner-secret');
  if (provided !== OWNER_SECRET) return res.status(401).json({ error: 'Invalid owner secret.' });
  const token = extractBearerToken(req);
  const email = await verifyGoogleToken(token);
  if (!email) return res.status(401).json({ error: 'Sign in with Google required.' });
  const { name } = req.body || {};
  try {
    const existing = await lookupDoctor(email);
    const url = existing
      ? `${SUPABASE_URL}/rest/v1/doctors?email=eq.${encodeURIComponent(email)}`
      : `${SUPABASE_URL}/rest/v1/doctors`;
    const upstream = await fetch(url, {
      method: existing ? 'PATCH' : 'POST',
      headers: {
        apikey: SUPABASE_SERVICE_KEY,
        Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
        'Content-Type': 'application/json',
        Prefer: 'return=representation',
      },
      body: JSON.stringify({
        email,
        name: name || email,
        role: 'owner',
        status: 'approved',
        approved_at: new Date().toISOString(),
      }),
    });
    const data = await upstream.json();
    res.json(Array.isArray(data) ? data[0] : data);
  } catch (err) {
    console.error('Bootstrap-owner error:', err);
    res.status(500).json({ error: 'Bootstrap failed: ' + err.message });
  }
});

// ---- POST /api/doctors/manual ----
// Owner adds a real clinic team member (name + color) who hasn't signed
// into the app with Google yet. This is a normal, fully-approved doctor
// row from day one — not a "pending" placeholder — it just carries a
// synthetic @empower.local email until she signs in for real, at which
// point /api/doctors/checkin links her Google account into this same row.
// ---- Email + password login (alternative to Google Sign-In) ----
// Same doctors table, same email as identity — this just adds a second
// way to prove you're that email besides a Google token, since the
// Google popup/redirect flow turned out to be unreliable from an
// "Add to Home Screen" icon. Password hashing uses Node's built-in
// scrypt (no extra npm dependency needed).
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}
function verifyPassword(password, stored) {
  if (!stored || !stored.includes(':')) return false;
  const [salt, hash] = stored.split(':');
  const check = crypto.scryptSync(password, salt, 64).toString('hex');
  try {
    return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(check, 'hex'));
  } catch (e) {
    return false;
  }
}

// ---- POST /api/auth/login ----
app.post('/api/auth/login', async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'Missing email or password.' });
  try {
    const doctor = await lookupDoctor(email.trim().toLowerCase());
    if (!doctor || !doctor.password_hash || !verifyPassword(password, doctor.password_hash)) {
      logActivity(req, 'failed', email.trim().toLowerCase(), 'wrong password');
      return res.status(401).json({ error: 'Wrong email or password.' });
    }
    logActivity(req, 'login', doctor.email);
    const sessionToken = await createAppSession(doctor.email);
    const { password_hash, ...safeDoctor } = doctor;
    res.json({ ...safeDoctor, session_token: sessionToken });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Login failed: ' + err.message });
  }
});

// ---- POST /api/doctors/:email/set-password ----
// Owner sets or resets a team member's password — the normal way someone
// gets onboarded onto password login, or recovers a forgotten one.
app.post('/api/doctors/:email/set-password', requireOwnerDoctor, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  const { password } = req.body || {};
  if (!password || password.length < 4) return res.status(400).json({ error: 'Password must be at least 4 characters.' });
  try {
    const url = `${SUPABASE_URL}/rest/v1/doctors?email=eq.${encodeURIComponent(req.params.email)}`;
    const upstream = await fetch(url, {
      method: 'PATCH',
      headers: {
        apikey: SUPABASE_SERVICE_KEY,
        Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ password_hash: hashPassword(password) }),
    });
    res.status(upstream.status).json({ ok: upstream.ok });
  } catch (err) {
    console.error('Set-password error:', err);
    res.status(500).json({ error: 'Failed to set password: ' + err.message });
  }
});

// ---- POST /api/auth/change-password ----
// Self-service: a signed-in doctor changes their own password.
app.post('/api/auth/change-password', requireApprovedAny, async (req, res) => {
  const { newPassword } = req.body || {};
  if (!newPassword || newPassword.length < 4) return res.status(400).json({ error: 'Password must be at least 4 characters.' });
  try {
    const url = `${SUPABASE_URL}/rest/v1/doctors?email=eq.${encodeURIComponent(req.doctor.email)}`;
    await fetch(url, {
      method: 'PATCH',
      headers: {
        apikey: SUPABASE_SERVICE_KEY,
        Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ password_hash: hashPassword(newPassword) }),
    });
    res.json({ ok: true });
  } catch (err) {
    console.error('Change-password error:', err);
    res.status(500).json({ error: 'Failed to change password: ' + err.message });
  }
});

app.post('/api/doctors/manual', requireOwnerOrPermission('manage_team'), async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  const { name, color, email, role } = req.body || {};
  if (!name || !name.trim()) return res.status(400).json({ error: 'Missing doctor name.' });
  const finalRole = role === 'secretary' ? 'secretary' : 'doctor';
  try {
    const already = await lookupManualDoctorByName(name);
    if (already) return res.status(409).json({ error: 'A doctor with that name is already on the roster.' });
    let finalEmail;
    if (email && email.trim()) {
      // Owner already knows this person's real email — use it directly.
      // No placeholder, no later merge needed: Google sign-in AND
      // password login both work immediately against this same row.
      finalEmail = email.trim().toLowerCase();
      const existing = await lookupDoctor(finalEmail);
      if (existing) return res.status(409).json({ error: 'A doctor with that email already exists on the roster.' });
    } else {
      const slug = name.trim().toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '') || 'doctor';
      finalEmail = `manual-${slug}-${Date.now().toString(36)}@empower.local`;
    }
    const insertRes = await fetch(`${SUPABASE_URL}/rest/v1/doctors`, {
      method: 'POST',
      headers: {
        apikey: SUPABASE_SERVICE_KEY,
        Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
        'Content-Type': 'application/json',
        Prefer: 'return=representation',
      },
      body: JSON.stringify({
        email: finalEmail,
        name: name.trim(),
        role: finalRole,
        status: 'approved',
        color: color || null,
        approved_at: new Date().toISOString(),
      }),
    });
    const inserted = await insertRes.json();
    if (!insertRes.ok) {
      console.error('Manual doctor insert failed:', insertRes.status, inserted);
      return res.status(500).json({ error: 'Could not add doctor: ' + (inserted.message || JSON.stringify(inserted)).slice(0, 300) });
    }
    res.json(Array.isArray(inserted) ? inserted[0] : inserted);
  } catch (err) {
    console.error('Manual doctor add error:', err);
    res.status(500).json({ error: 'Failed to add doctor: ' + err.message });
  }
});

// ---- POST /api/doctors/merge ----
// Fixes the "same person ended up as two rows" problem — usually a
// manually-added doctor (placeholder @empower.local email) whose real
// Google sign-in didn't auto-link because the name didn't match closely
// enough, so it created a second row instead. Owner picks which row to
// KEEP (its name/color/history survive) and which to REMOVE; whichever
// of the two has a real email (not @empower.local) becomes the surviving
// row's email, so future sign-ins map correctly.
app.post('/api/doctors/merge', requireOwnerOrPermission('manage_team'), async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  const { keepEmail, removeEmail } = req.body || {};
  if (!keepEmail || !removeEmail || keepEmail === removeEmail) {
    return res.status(400).json({ error: 'Need two different doctor emails: keepEmail and removeEmail.' });
  }
  try {
    const keepRow = await lookupDoctor(keepEmail);
    const removeRow = await lookupDoctor(removeEmail);
    if (!keepRow || !removeRow) return res.status(404).json({ error: 'One of those doctors was not found.' });

    const isPlaceholder = (email) => email.endsWith('@empower.local');
    let finalEmail = keepEmail;
    if (isPlaceholder(keepEmail) && !isPlaceholder(removeEmail)) finalEmail = removeEmail;

    // Delete the row being removed first — if finalEmail === removeEmail,
    // that address needs to be free before we can move it onto keepRow.
    await fetch(`${SUPABASE_URL}/rest/v1/doctors?email=eq.${encodeURIComponent(removeEmail)}`, {
      method: 'DELETE',
      headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` },
    });

    if (finalEmail !== keepEmail) {
      const patchRes = await fetch(`${SUPABASE_URL}/rest/v1/doctors?email=eq.${encodeURIComponent(keepEmail)}`, {
        method: 'PATCH',
        headers: {
          apikey: SUPABASE_SERVICE_KEY,
          Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
          'Content-Type': 'application/json',
          Prefer: 'return=representation',
        },
        body: JSON.stringify({ email: finalEmail }),
      });
      const patched = await patchRes.json();
      if (!patchRes.ok) {
        console.error('Merge email update failed:', patchRes.status, patched);
        return res.status(500).json({ error: 'Merged, but could not update the email on the kept record.' });
      }
    }

    // Also fold any push notification subscriptions from the removed
    // email over to the surviving email, so notifications keep working.
    if (finalEmail !== removeEmail) {
      await fetch(`${SUPABASE_URL}/rest/v1/push_subscriptions?email=eq.${encodeURIComponent(removeEmail)}`, {
        method: 'PATCH',
        headers: {
          apikey: SUPABASE_SERVICE_KEY,
          Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ email: finalEmail }),
      }).catch(() => {});
    }

    res.json({ ok: true, email: finalEmail, name: keepRow.name });
  } catch (err) {
    console.error('Doctor merge error:', err);
    res.status(500).json({ error: 'Failed to merge: ' + err.message });
  }
});

app.get('/api/doctors', requireOwnerOrPermission('manage_team'), async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  try {
    const url = `${SUPABASE_URL}/rest/v1/doctors?order=requested_at.desc`;
    const upstream = await fetch(url, { headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` } });
    const rows = await upstream.json();
    if (!upstream.ok) return res.status(upstream.status).json(rows);
    res.json((Array.isArray(rows) ? rows : []).map(({ password_hash, ...rest }) => rest));
  } catch (err) {
    console.error('Doctors GET error:', err);
    res.status(500).json({ error: 'Failed to load doctors: ' + err.message });
  }
});

// Lighter-weight roster for color assignment — owner OR secretary, and
// only exposes approved doctors/owners (not pending/removed accounts).
app.get('/api/doctors/colors', requireApprovedAny, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  try {
    const url = `${SUPABASE_URL}/rest/v1/doctors?status=eq.approved&role=in.(doctor,owner)&order=name.asc&select=name,email,color,role`;
    const upstream = await fetch(url, { headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` } });
    const data = await upstream.text();
    res.status(upstream.status).type('application/json').send(data);
  } catch (err) {
    console.error('Doctor colors GET error:', err);
    res.status(500).json({ error: 'Failed to load doctor colors: ' + err.message });
  }
});

// ---- POST /api/doctors/:email/dashboard-access ----
// Owner grants/revokes a specific team member's access to the Dashboard
// (stats view with payment/confirmation numbers) — not tied to role, so
// the owner can, say, give a trusted secretary access without making
// them an owner, or keep it from a doctor who shouldn't see clinic-wide
// financials.
// ---- Telegram arrival alerts ----
// When the secretary marks a patient as arrived, the assigned doctor gets a
// Telegram message automatically (works with the phone locked and the app
// closed). Uses plain HTTPS calls to the Telegram Bot API — no extra
// package, so nothing new can break the server at startup.
//
// One-time setup: create a bot with @BotFather, set TELEGRAM_BOT_TOKEN on
// the server, then press "Connect Telegram bot" in Manage Doctors (owner).
// Each doctor then opens their own link once and taps Start.
const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN || '';
const PUBLIC_BASE_URL = (process.env.PUBLIC_BASE_URL || 'https://pt-script-backend.onrender.com').replace(/\/+$/, '');
let telegramBotUsername = '';

function telegramWebhookSecret() {
  return crypto.createHash('sha256').update('tg-webhook:' + TELEGRAM_BOT_TOKEN).digest('hex').slice(0, 32);
}
// A doctor's personal link code is derived from their email — nothing to store.
function telegramLinkCode(email) {
  return crypto.createHmac('sha256', TELEGRAM_BOT_TOKEN).update(String(email).trim().toLowerCase()).digest('hex').slice(0, 12);
}

async function telegramApi(method, body) {
  const r = await fetch(`https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/${method}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body || {}),
  });
  const j = await r.json().catch(() => ({}));
  if (!j.ok) throw new Error(j.description || `Telegram error ${r.status}`);
  return j.result;
}
function telegramSend(chatId, text) { return telegramApi('sendMessage', { chat_id: chatId, text }); }
async function getTelegramBotUsername() {
  if (telegramBotUsername) return telegramBotUsername;
  const me = await telegramApi('getMe');
  telegramBotUsername = me.username || '';
  return telegramBotUsername;
}

const ARRIVAL_AR_NAMES = { youssef: 'يوسف', yousef: 'يوسف', marwa: 'مروة', mostafa: 'مصطفى', mustafa: 'مصطفى', omnia: 'أمنية', omnya: 'أمنية', menna: 'منة', zeinab: 'زينب' };
const ARRIVAL_FEMALE = new Set(['marwa','omnia','omnya','menna','zeinab','vara','nada','mona','sara','salma','nour','hana','doaa','dina','rana','yara','mariam','maryam','eman','asmaa','esraa','aya','heba','nermin','noha','rania','shaimaa','shahd','rawan']);
const ARRIVAL_MALE = new Set(['mostafa','mustafa','youssef','yousef','joseph','ahmed','mohamed','mahmoud','omar','ali','ibrahim','hassan','khaled','karim','amr','tarek','sherif','hesham','osama']);

function buildArrivalMessage(appt, doctorName) {
  const rawName = String(doctorName || appt.doctor_name || '').trim();
  const tokens = rawName.split(/\s+/).filter(t => !/^(dr\.?|doctor|د\.?|دكتور|دكتورة)$/i.test(t));
  const first = (tokens[0] || rawName).trim();
  const key = first.toLowerCase();
  const title = ARRIVAL_FEMALE.has(key) ? 'دكتورة' : (ARRIVAL_MALE.has(key) ? 'دكتور' : 'د.');
  const nameAr = ARRIVAL_AR_NAMES[key] || first;
  const fmt = iso => new Date(iso).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', timeZone: 'Africa/Cairo' });
  const typeAr = appt.visit_type === 'checkup' ? 'كشف' : (appt.visit_type === 'recovery' ? 'ريكفري' : 'جلسة');
  return `${title} ${nameAr} 👋\nالعيان ${appt.patient_name || ''} وصل العيادة دلوقتي (${fmt(appt.arrived_at)}) ✅\nالموعد: ${appt.start_time ? fmt(appt.start_time) : ''} · ${typeAr}`;
}

async function notifyDoctorArrivalTelegram(appt) {
  if (!TELEGRAM_BOT_TOKEN || !appt || !appt.arrived_at) return;
  const r = await fetch(`${SUPABASE_URL}/rest/v1/doctors?status=eq.approved&telegram_chat_id=not.is.null`, {
    headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` },
  });
  const docs = await r.json();
  if (!Array.isArray(docs) || docs.length === 0) return;
  const nm = String(appt.doctor_name || '').trim().toLowerCase();
  const byName = docs.find(d => String(d.name || '').trim().toLowerCase() === nm);
  const byColor = appt.doctor_color ? docs.filter(d => d.color === appt.doctor_color) : [];
  const doc = byName || (byColor.length === 1 ? byColor[0] : null);
  if (!doc) return;
  await telegramSend(doc.telegram_chat_id, buildArrivalMessage(appt, doc.name));
}

app.post('/api/telegram/setup', requireOwnerDoctor, async (req, res) => {
  if (!TELEGRAM_BOT_TOKEN) return res.status(400).json({ error: 'TELEGRAM_BOT_TOKEN is not set on the server yet.' });
  try {
    const username = await getTelegramBotUsername();
    await telegramApi('setWebhook', { url: `${PUBLIC_BASE_URL}/api/telegram/webhook/${telegramWebhookSecret()}`, allowed_updates: ['message'] });
    res.json({ ok: true, botUsername: username });
  } catch (err) {
    console.error('Telegram setup error:', err);
    res.status(500).json({ error: 'Telegram setup failed: ' + err.message });
  }
});

app.get('/api/telegram/link/:email', requireOwnerOrPermission('manage_team'), async (req, res) => {
  if (!TELEGRAM_BOT_TOKEN) return res.status(400).json({ error: 'TELEGRAM_BOT_TOKEN is not set on the server yet.' });
  try {
    const username = await getTelegramBotUsername();
    res.json({ botUsername: username, url: `https://t.me/${username}?start=${telegramLinkCode(req.params.email)}` });
  } catch (err) {
    res.status(500).json({ error: 'Could not reach Telegram: ' + err.message });
  }
});

app.post('/api/telegram/test/:email', requireOwnerOrPermission('manage_team'), async (req, res) => {
  if (!TELEGRAM_BOT_TOKEN) return res.status(400).json({ error: 'TELEGRAM_BOT_TOKEN is not set on the server yet.' });
  try {
    const r = await fetch(`${SUPABASE_URL}/rest/v1/doctors?email=eq.${encodeURIComponent(req.params.email)}&select=name,telegram_chat_id`, {
      headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` },
    });
    const rows = await r.json();
    const doc = Array.isArray(rows) && rows[0];
    if (!doc || !doc.telegram_chat_id) return res.status(400).json({ error: 'This doctor has not linked Telegram yet.' });
    await telegramSend(doc.telegram_chat_id, '✅ رسالة تجربة من عيادة ' + (await getClinicConfig()).name + ' — تنبيهات وصول العيانين شغّالة.');
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: 'Could not send the test message: ' + err.message });
  }
});

// Telegram calls this when someone messages the bot. The secret in the path
// is derived from the bot token, so only Telegram (which we gave the URL to)
// can reach it.
app.post('/api/telegram/webhook/:secret', async (req, res) => {
  if (!TELEGRAM_BOT_TOKEN || req.params.secret !== telegramWebhookSecret()) return res.sendStatus(404);
  res.sendStatus(200);
  try {
    const msg = req.body && req.body.message;
    if (!msg || !msg.chat || msg.chat.type !== 'private' || typeof msg.text !== 'string') return;
    const m = msg.text.trim().match(/^\/start(?:@\w+)?(?:\s+(\S+))?$/);
    if (!m) return;
    const code = m[1];
    if (!code) {
      await telegramSend(msg.chat.id, 'أهلاً 👋 اطلب من العيادة لينك الربط الخاص بيك، وادوس عليه عشان توصلك تنبيهات وصول العيانين.');
      return;
    }
    const headers = { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` };
    const r = await fetch(`${SUPABASE_URL}/rest/v1/doctors?status=eq.approved&select=email,name`, { headers });
    const docs = await r.json();
    const doc = (Array.isArray(docs) ? docs : []).find(d => telegramLinkCode(d.email) === code);
    if (!doc) {
      await telegramSend(msg.chat.id, 'اللينك ده مش صح أو قديم ❌ اطلب من العيادة لينك جديد.');
      return;
    }
    await fetch(`${SUPABASE_URL}/rest/v1/doctors?email=eq.${encodeURIComponent(doc.email)}`, {
      method: 'PATCH',
      headers: { ...headers, 'Content-Type': 'application/json' },
      body: JSON.stringify({ telegram_chat_id: msg.chat.id }),
    });
    await telegramSend(msg.chat.id, `تم الربط ✅ يا ${doc.name || 'دكتور'}\nهتوصلك هنا رسالة أول ما عيان من عيانينك يوصل العيادة.`);
  } catch (err) {
    console.error('Telegram webhook error:', err.message);
  }
});

// ---- POST /api/doctors/:email/phone ----
// Saves a team member's WhatsApp number (used for the "patient arrived" message).
app.post('/api/doctors/:email/phone', requireOwnerOrPermission('manage_team'), async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  const raw = String((req.body && req.body.phone) || '').trim();
  if (raw && !/^[+\d][\d\s\-()]{6,20}$/.test(raw)) return res.status(400).json({ error: 'That does not look like a phone number.' });
  try {
    const patchRes = await fetch(`${SUPABASE_URL}/rest/v1/doctors?email=eq.${encodeURIComponent(req.params.email)}`, {
      method: 'PATCH',
      headers: {
        apikey: SUPABASE_SERVICE_KEY,
        Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
        'Content-Type': 'application/json',
        Prefer: 'return=representation',
      },
      body: JSON.stringify({ phone: raw || null }),
    });
    const updated = await patchRes.json();
    if (!patchRes.ok) throw new Error(JSON.stringify(updated));
    if (!Array.isArray(updated) || updated.length === 0) return res.status(404).json({ error: 'Doctor not found.' });
    res.json({ ok: true, phone: updated[0].phone });
  } catch (err) {
    console.error('Set-phone error:', err);
    res.status(500).json({ error: 'Failed to save the number: ' + err.message });
  }
});

// ---- POST /api/doctors/:email/permissions ----
// Owner sets the granular permissions object for a team member. Body is
// the full set of booleans, e.g. { view_payments: true, send_whatsapp:
// false, ... } — always replaces the whole object (simpler than partial
// patches, and the frontend always sends the complete checklist anyway).
app.post('/api/doctors/:email/permissions', requireOwnerDoctor, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  const { permissions } = req.body || {};
  if (!permissions || typeof permissions !== 'object') return res.status(400).json({ error: 'Missing permissions object.' });
  try {
    const url = `${SUPABASE_URL}/rest/v1/doctors?email=eq.${encodeURIComponent(req.params.email)}`;
    const upstream = await fetch(url, {
      method: 'PATCH',
      headers: {
        apikey: SUPABASE_SERVICE_KEY,
        Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ permissions }),
    });
    res.status(upstream.status).json({ ok: upstream.ok });
  } catch (err) {
    console.error('Set-permissions error:', err);
    res.status(500).json({ error: 'Failed to update permissions: ' + err.message });
  }
});

app.post('/api/doctors/:email/dashboard-access', requireOwnerDoctor, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  const { canView } = req.body || {};
  try {
    const url = `${SUPABASE_URL}/rest/v1/doctors?email=eq.${encodeURIComponent(req.params.email)}`;
    const upstream = await fetch(url, {
      method: 'PATCH',
      headers: {
        apikey: SUPABASE_SERVICE_KEY,
        Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ can_view_dashboard: !!canView }),
    });
    res.status(upstream.status).json({ ok: upstream.ok });
  } catch (err) {
    console.error('Dashboard-access toggle error:', err);
    res.status(500).json({ error: 'Failed to update dashboard access: ' + err.message });
  }
});

app.post('/api/doctors/:email/color', requireOwnerOrSecretary, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  const { color } = req.body || {};
  if (!color) return res.status(400).json({ error: 'Missing color.' });
  try {
    const doctor = await lookupDoctor(req.params.email);
    const url = `${SUPABASE_URL}/rest/v1/doctors?email=eq.${encodeURIComponent(req.params.email)}`;
    const upstream = await fetch(url, {
      method: 'PATCH',
      headers: {
        apikey: SUPABASE_SERVICE_KEY,
        Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ color }),
    });

    // Cascade the new color onto this doctor's upcoming appointments —
    // they were booked with the old color baked in (doctor_color is
    // stored per-appointment, not looked up live), so without this a
    // color change wouldn't show up on anything already on the calendar.
    // Past appointments are left alone; only start_time >= now is touched.
    if (upstream.ok && doctor && doctor.name) {
      const nowIso = new Date().toISOString();
      const cascadeUrl = `${SUPABASE_URL}/rest/v1/appointments?doctor_name=eq.${encodeURIComponent(doctor.name)}&start_time=gte.${encodeURIComponent(nowIso)}`;
      const cascadeRes = await fetch(cascadeUrl, {
        method: 'PATCH',
        headers: {
          apikey: SUPABASE_SERVICE_KEY,
          Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ doctor_color: color }),
      });
      if (!cascadeRes.ok) {
        console.error('Color cascade to appointments failed:', cascadeRes.status, await cascadeRes.text());
      }
    }

    res.status(upstream.status).json({ ok: upstream.ok });
  } catch (err) {
    console.error('Doctor color update error:', err);
    res.status(500).json({ error: 'Failed to update color: ' + err.message });
  }
});

app.post('/api/doctors/:email/approve', requireOwnerOrPermission('manage_team'), async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  const { role } = req.body || {};
  const assignedRole = role === 'secretary' ? 'secretary' : role === 'owner' ? 'owner' : 'doctor';
  try {
    const url = `${SUPABASE_URL}/rest/v1/doctors?email=eq.${encodeURIComponent(req.params.email)}`;
    const upstream = await fetch(url, {
      method: 'PATCH',
      headers: {
        apikey: SUPABASE_SERVICE_KEY,
        Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ status: 'approved', role: assignedRole, approved_at: new Date().toISOString() }),
    });
    res.status(upstream.status).json({ ok: upstream.ok });
  } catch (err) {
    console.error('Doctor approve error:', err);
    res.status(500).json({ error: 'Failed to approve: ' + err.message });
  }
});

app.post('/api/doctors/:email/reject', requireOwnerOrPermission('manage_team'), async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  try {
    const url = `${SUPABASE_URL}/rest/v1/doctors?email=eq.${encodeURIComponent(req.params.email)}`;
    const upstream = await fetch(url, {
      method: 'PATCH',
      headers: {
        apikey: SUPABASE_SERVICE_KEY,
        Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ status: 'removed' }),
    });
    res.status(upstream.status).json({ ok: upstream.ok });
  } catch (err) {
    console.error('Doctor reject error:', err);
    res.status(500).json({ error: 'Failed to reject: ' + err.message });
  }
});

app.get('/', (req, res) => {
  res.send('Qalam PT Scribe backend is running.');
});

const PORT = process.env.PORT || 3000;

// =====================================================================
// ---- Training applicants (public application form + owner-only list) ----
// Public:  GET /apply (the form page)   POST /api/apply (submit, no login)
// Owner:   GET /api/applicants, PATCH /api/applicants/:id, GET /api/applicants/:id/cv, DELETE /api/applicants/:id
// CV files live in a PRIVATE Supabase storage bucket "applicant-cvs".
// =====================================================================
const APPLICANT_BUCKET = 'applicant-cvs';
const CV_MAX_BYTES = 6 * 1024 * 1024;
const CV_TYPES = { 'application/pdf': 'pdf', 'application/msword': 'doc', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document': 'docx', 'image/jpeg': 'jpg', 'image/png': 'png' };
const applyHits = new Map(); // ip -> [timestamps]
function applyRateLimited(ip) {
  const now = Date.now();
  const arr = (applyHits.get(ip) || []).filter(t => now - t < 3600 * 1000);
  if (arr.length >= 8) { applyHits.set(ip, arr); return true; }
  arr.push(now); applyHits.set(ip, arr); return false;
}
const APPLY_AREAS = ['Rehab', 'Tagamoa', 'Shorouk', 'Madinaty', 'Other'];

const APPLY_PAGE = String.raw`<!doctype html><html lang="en" dir="ltr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow"><title>Empower - Training Application</title>
<style>
*{box-sizing:border-box}body{margin:0;background:#f6f4ee;color:#12363a;font-family:-apple-system,'Segoe UI',Roboto,Arial,sans-serif;padding:16px}
.c{max-width:560px;margin:12px auto;background:#fff;border:1px solid #e4dfd0;border-radius:14px;padding:22px}
.brand{font-size:.78rem;letter-spacing:.14em;text-transform:uppercase;color:#b07a1f;font-weight:700;margin-bottom:8px}
h1{font-size:1.25rem;margin:0 0 6px}.sub{color:#5b6863;font-size:.9rem;margin-bottom:18px;line-height:1.6}
label{display:block;font-weight:600;font-size:.9rem;margin:16px 0 6px}label small{font-weight:400;color:#7a857f}
input[type=text],input[type=tel],select,textarea{width:100%;padding:11px 12px;border:1px solid #cfd6d2;border-radius:10px;font-size:1rem;background:#fff;color:#12363a;font-family:inherit}
textarea{min-height:80px;resize:vertical}.opts{display:flex;flex-wrap:wrap;gap:8px}
.opt{display:flex;align-items:center;gap:6px;border:1px solid #cfd6d2;border-radius:10px;padding:9px 12px;font-weight:500;cursor:pointer;margin:0}
.opt input{margin:0}button{margin-top:22px;width:100%;padding:14px;border:0;border-radius:10px;background:#12363a;color:#fff;font-size:1rem;font-weight:700;cursor:pointer}
button:disabled{opacity:.6}.err{color:#b3261e;font-size:.85rem;margin-top:10px;min-height:1.2em}.ok{text-align:center;padding:30px 0}
.warn{background:#fff6e0;border:1px solid #e8cf8a;border-radius:10px;padding:12px 14px;font-size:.92rem;line-height:1.7;margin-bottom:6px}
.logo{display:block;max-width:220px;width:60%;height:auto;margin:0 auto 14px}
.hp{position:absolute;left:-9999px;height:0;overflow:hidden}.hide{display:none}
</style></head><body><div class="c" id="card">
<img class="logo" src="/clinic-logo.png" alt="Empower">
<h1>Training Application</h1>
<div class="sub">Fill in your details and upload your CV. We review every application and contact shortlisted candidates on WhatsApp.</div>
<div class="warn"><strong>Important before you apply:</strong> the training is <strong>intensive: one full week, 6 days in a row with no rest day in between</strong>. Apply only if you can commit to all of those days.</div>
<form id="f" novalidate>
<div class="hp"><label>Website<input type="text" id="website" tabindex="-1" autocomplete="off"></label></div>
<label>Full name *</label><input type="text" id="fullName" maxlength="120" autocomplete="name">
<label>WhatsApp number *</label><input type="tel" id="phone" maxlength="20" inputmode="tel" autocomplete="tel">
<label>Graduation year *</label><select id="gradYear"><option value="">Select</option></select>
<label>University</label><input type="text" id="university" maxlength="120">
<label>Where do you live? *</label>
<div class="opts" id="areaOpts"></div>
<div id="areaOtherWrap" class="hide"><label>Write your area</label><input type="text" id="areaOther" maxlength="80"></div>
<label>Can you easily reach the training location? <small>(it is located between Rehab, Tagamoa, Shorouk and Madinaty)</small></label>
<select id="commute"><option value="">Select</option><option value="yes">Yes, easily</option><option value="hard">Possible, but difficult</option><option value="no">No</option></select>
<label>Do you currently work at another clinic or center? *</label>
<div class="opts"><label class="opt"><input type="radio" name="works" value="yes"> Yes</label><label class="opt"><input type="radio" name="works" value="no"> No</label></div>
<div id="worksWrap" class="hide"><label>Where, and what are your working days and hours?</label><textarea id="worksDetails" maxlength="500"></textarea></div>
<label>Years of experience in physical therapy</label>
<select id="experience"><option value="">Select</option><option>Less than 1 year</option><option>1 - 2 years</option><option>3 - 5 years</option><option>More than 5 years</option></select>
<label>Can you commit to the training <strong>6 days in a row for one week</strong>? *</label>
<div class="opts"><label class="opt"><input type="radio" name="commit6" value="yes"> Yes, I can commit to all the days</label><label class="opt"><input type="radio" name="commit6" value="no"> No, I cannot</label></div>
<label>Your preferred hours, and anything that might prevent you <small>(optional)</small></label><textarea id="availability" maxlength="500"></textarea>
<label>Upload your CV * <small>(PDF, Word or image - max 6 MB)</small></label>
<input type="file" id="cv" accept=".pdf,.doc,.docx,.jpg,.jpeg,.png,application/pdf,image/jpeg,image/png">
<div class="err" id="err"></div>
<button type="submit" id="btn">Submit application</button>
</form></div>
<script>
(function(){
  var $=function(i){return document.getElementById(i)};
  var AREAS=[['Rehab','Rehab'],['Tagamoa','Tagamoa'],['Shorouk','Shorouk'],['Madinaty','Madinaty'],['Other','Somewhere else']];
  var y=new Date().getFullYear();for(var i=y;i>=y-30;i--){var o=document.createElement('option');o.value=i;o.textContent=i;$('gradYear').appendChild(o);}
  AREAS.forEach(function(a){var l=document.createElement('label');l.className='opt';l.innerHTML='<input type="radio" name="area" value="'+a[0]+'"> '+a[1];$('areaOpts').appendChild(l);});
  function sel(n){var e=document.querySelector('input[name='+n+']:checked');return e?e.value:'';}
  document.addEventListener('change',function(){$('areaOtherWrap').className=sel('area')==='Other'?'':'hide';$('worksWrap').className=sel('works')==='yes'?'':'hide';});
  function fail(m){$('err').textContent=m;$('btn').disabled=false;$('btn').textContent='Submit application';}
  $('f').addEventListener('submit',function(ev){
    ev.preventDefault();$('err').textContent='';
    var name=$('fullName').value.trim(),phone=$('phone').value.replace(/[^0-9+]/g,''),grad=$('gradYear').value,area=sel('area'),works=sel('works'),commit=sel('commit6'),file=$('cv').files[0];
    if(name.length<3)return fail('Please enter your full name.');
    if(phone.replace(/\D/g,'').length<10)return fail('Please enter a valid WhatsApp number.');
    if(!grad)return fail('Please select your graduation year.');
    if(!area)return fail('Please select where you live.');
    if(area==='Other'&&!$('areaOther').value.trim())return fail('Please write your area.');
    if(!works)return fail('Please tell us if you work at another clinic.');
    if(!commit)return fail('Please answer the 6-day commitment question.');
    if(!file)return fail('Please upload your CV.');
    if(file.size>6*1024*1024)return fail('The file is larger than 6 MB.');
    $('btn').disabled=true;$('btn').textContent='Sending...';
    var rd=new FileReader();
    rd.onerror=function(){fail('Could not read the file. Try another file.')};
    rd.onload=function(){
      var b64=String(rd.result).split(',')[1]||'';
      var body={fullName:name,phone:phone,graduationYear:grad,university:$('university').value.trim(),area:area,areaOther:$('areaOther').value.trim(),commute:$('commute').value,worksElsewhere:works==='yes',commit6:commit==='yes',worksDetails:$('worksDetails').value.trim(),experience:$('experience').value,availability:$('availability').value.trim(),website:$('website').value,cvName:file.name,cvType:file.type,cvBase64:b64};
      fetch('/api/apply',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)})
      .then(function(r){return r.json().catch(function(){return{}}).then(function(j){return{ok:r.ok,j:j}})})
      .then(function(x){if(!x.ok)return fail(x.j.error||'Something went wrong. Please try again.');
        $('card').innerHTML='<div class="ok"><img class="logo" src="/clinic-logo.png" alt="Empower"><h1>We received your application. Thank you!</h1><div class="sub">We will review all applications and contact shortlisted candidates on WhatsApp.</div></div>';})
      .catch(function(){fail('No internet connection. Please try again.')});
    };
    rd.readAsDataURL(file);
  });
})();
</script></body></html>`;

app.get('/apply', async (req, res) => {
  logActivity(req, 'page', null, 'apply');
  res.set({ 'Content-Type': 'text/html; charset=utf-8', 'X-Robots-Tag': 'noindex, nofollow', 'Cache-Control': 'no-store' }).send(renderClinicPage(APPLY_PAGE, await getClinicConfig()));
});

app.post('/api/apply', async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is not ready. Please try later.' });
  const ip = String(req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
  if (applyRateLimited(ip)) return res.status(429).json({ error: 'Too many attempts. Please try again later.' });
  const b = req.body || {};
  if (b.website) return res.json({ ok: true }); // honeypot: pretend success
  const clean = (v, n) => String(v == null ? '' : v).replace(/[\u0000-\u001f]/g, ' ').trim().slice(0, n);
  const fullName = clean(b.fullName, 120);
  const phone = clean(b.phone, 20).replace(/[^0-9+]/g, '');
  const gradYear = parseInt(b.graduationYear, 10);
  const area = APPLY_AREAS.includes(b.area) ? b.area : '';
  if (fullName.length < 3 || phone.replace(/\D/g, '').length < 10 || !gradYear || gradYear < 1990 || gradYear > new Date().getFullYear() + 1 || !area || typeof b.worksElsewhere !== 'boolean' || typeof b.commit6 !== 'boolean')
    return res.status(400).json({ error: 'Some details are missing or wrong. Please check the form.' });
  const ext = CV_TYPES[String(b.cvType || '').toLowerCase()];
  if (!ext || !b.cvBase64) return res.status(400).json({ error: 'File type not accepted. Upload a PDF, Word file or image.' });
  const bytes = Buffer.from(String(b.cvBase64), 'base64');
  if (bytes.length < 200 || bytes.length > CV_MAX_BYTES) return res.status(400).json({ error: 'File size is not valid (max 6 MB).' });
  try {
    const headers = { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` };
    const cvPath = `${Date.now()}_${Math.random().toString(36).slice(2, 10)}/cv.${ext}`;
    const up = await fetch(`${SUPABASE_URL}/storage/v1/object/${APPLICANT_BUCKET}/${cvPath}`, { method: 'POST', headers: { ...headers, 'Content-Type': String(b.cvType), 'x-upsert': 'false' }, body: bytes });
    if (!up.ok) { console.error('Applicant CV upload failed:', up.status, await up.text().catch(() => '')); return res.status(500).json({ error: 'Could not save the file. Please try again.' }); }
    const row = {
      full_name: fullName, phone, graduation_year: gradYear, university: clean(b.university, 120) || null,
      area, area_other: clean(b.areaOther, 80) || null, commute: ['yes', 'hard', 'no'].includes(b.commute) ? b.commute : null,
      works_elsewhere: b.worksElsewhere, can_commit_6_days: b.commit6, works_details: clean(b.worksDetails, 500) || null, experience: clean(b.experience, 40) || null,
      availability: clean(b.availability, 500) || null,
      cv_path: cvPath, cv_name: clean(b.cvName, 150) || null,
    };
    const ins = await fetch(`${SUPABASE_URL}/rest/v1/training_applicants`, { method: 'POST', headers: { ...headers, 'Content-Type': 'application/json', Prefer: 'return=minimal' }, body: JSON.stringify(row) });
    if (!ins.ok) { console.error('Applicant insert failed:', ins.status, await ins.text().catch(() => '')); return res.status(500).json({ error: 'Could not save your application. Please try again.' }); }
    res.json({ ok: true });
  } catch (err) {
    console.error('Apply error:', err);
    res.status(500).json({ error: 'Something went wrong. Please try again.' });
  }
});

app.get('/api/applicants', requireOwnerOrPermission('view_applicants'), async (req, res) => {
  try {
    const r = await fetch(`${SUPABASE_URL}/rest/v1/training_applicants?order=created_at.desc&limit=2000`, { headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` } });
    const data = await r.json();
    if (!r.ok) return res.status(500).json({ error: (data && data.message) || 'Failed to load applicants.' });
    res.json(data);
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

app.patch('/api/applicants/:id', requireOwnerOrPermission('view_applicants'), async (req, res) => {
  const b = req.body || {};
  const patch = {};
  if (b.status !== undefined) { if (!['new', 'shortlisted', 'interview', 'accepted', 'rejected'].includes(b.status)) return res.status(400).json({ error: 'Bad status.' }); patch.status = b.status; }
  if (b.rating !== undefined) { const n = b.rating === null ? null : parseInt(b.rating, 10); if (n !== null && !(n >= 1 && n <= 5)) return res.status(400).json({ error: 'Bad rating.' }); patch.rating = n; }
  if (b.owner_notes !== undefined) patch.owner_notes = String(b.owner_notes || '').slice(0, 2000);
  if (b.train_slot !== undefined) {
    if (b.train_slot === null || b.train_slot === '') { patch.train_start = null; patch.train_end = null; patch.train_shift = null; patch.train_days = null; patch.confirm_sent_at = null; patch.remind_for = null; }
    else {
      const m = /^(\d{4}-\d{2}-\d{2})\|(\d{4}-\d{2}-\d{2})\|(morning|evening)$/.exec(String(b.train_slot));
      if (!m) return res.status(400).json({ error: 'Bad slot.' });
      patch.train_start = m[1]; patch.train_end = m[2]; patch.train_shift = m[3];
    }
  }
  if (b.train_days !== undefined) {
    if (b.train_days === null || b.train_days === '') patch.train_days = null;
    else if (/^[0-6](,[0-6]){0,6}$/.test(String(b.train_days))) patch.train_days = String(b.train_days);
    else return res.status(400).json({ error: 'Bad days.' });
  }
  if (b.confirm_sent === true) patch.confirm_sent_at = new Date().toISOString();
  if (b.remind_for !== undefined) { if (b.remind_for !== null && !/^\d{4}-\d{2}-\d{2}$/.test(String(b.remind_for))) return res.status(400).json({ error: 'Bad date.' }); patch.remind_for = b.remind_for; }
  if (!Object.keys(patch).length) return res.status(400).json({ error: 'Nothing to update.' });
  try {
    const r = await fetch(`${SUPABASE_URL}/rest/v1/training_applicants?id=eq.${encodeURIComponent(req.params.id)}`, { method: 'PATCH', headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`, 'Content-Type': 'application/json', Prefer: 'return=minimal' }, body: JSON.stringify(patch) });
    if (!r.ok) return res.status(500).json({ error: 'Update failed.' });
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

app.get('/api/applicants/:id/cv', requireOwnerOrPermission('view_applicants'), async (req, res) => {
  try {
    const headers = { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` };
    const r = await fetch(`${SUPABASE_URL}/rest/v1/training_applicants?id=eq.${encodeURIComponent(req.params.id)}&select=cv_path&limit=1`, { headers });
    const rows = await r.json();
    const p = rows && rows[0] && rows[0].cv_path;
    if (!p) return res.status(404).json({ error: 'No CV.' });
    const s = await fetch(`${SUPABASE_URL}/storage/v1/object/sign/${APPLICANT_BUCKET}/${p}`, { method: 'POST', headers: { ...headers, 'Content-Type': 'application/json' }, body: JSON.stringify({ expiresIn: 900 }) });
    const j = await s.json();
    if (!s.ok || !j.signedURL) return res.status(500).json({ error: 'Could not open the CV.' });
    res.json({ url: `${SUPABASE_URL}/storage/v1${j.signedURL}` });
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

app.delete('/api/applicants/:id', requireOwnerDoctor, async (req, res) => {
  try {
    const headers = { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` };
    const r = await fetch(`${SUPABASE_URL}/rest/v1/training_applicants?id=eq.${encodeURIComponent(req.params.id)}&select=cv_path&limit=1`, { headers });
    const rows = await r.json();
    const p = rows && rows[0] && rows[0].cv_path;
    if (p) await fetch(`${SUPABASE_URL}/storage/v1/object/${APPLICANT_BUCKET}`, { method: 'DELETE', headers: { ...headers, 'Content-Type': 'application/json' }, body: JSON.stringify({ prefixes: [p] }) }).catch(() => {});
    const d = await fetch(`${SUPABASE_URL}/rest/v1/training_applicants?id=eq.${encodeURIComponent(req.params.id)}`, { method: 'DELETE', headers });
    if (!d.ok) return res.status(500).json({ error: 'Delete failed.' });
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});


// =====================================================================
// ---- Friday event duty: who covers the Friday event, + Telegram reminder 3 days before ----
// Table: friday_duty (duty_date date PK, doctor_email, doctor_name, reminder_sent_at, reminder_error)
// The reminder goes out once, 3 days before (Tuesday for a Friday), from 9 AM Cairo time.
// If the server was asleep then, it sends as soon as it wakes (any time up to the duty day).
// =====================================================================
function cairoTodayYmd() { return new Date().toLocaleDateString('en-CA', { timeZone: 'Africa/Cairo' }); }
function cairoHourNow() { return parseInt(new Date().toLocaleString('en-US', { timeZone: 'Africa/Cairo', hour: 'numeric', hour12: false }), 10) % 24; }
function ymdDiffDays(aYmd, bYmd) { return Math.round((Date.parse(bYmd + 'T00:00:00Z') - Date.parse(aYmd + 'T00:00:00Z')) / 86400000); }
function isFridayYmd(ymd) { return /^\d{4}-\d{2}-\d{2}$/.test(ymd) && new Date(ymd + 'T00:00:00Z').getUTCDay() === 5; }
const DUTY_HEADERS = () => ({ apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` });
// A Friday can carry a second event (American football) with its own doctor: table friday_duty_football (same columns).
// The first event keeps the original table, so nothing existing changes.
const DUTY_EVENTS = {
  main: { table: 'friday_duty', ar: 'الإيفنت بتاع الجمعة', ownerAr: 'إيفنت' },
  football: { table: 'friday_duty_football', ar: 'ماتش الأمريكان فوتبول', ownerAr: 'ماتش الأمريكان فوتبول' },
};
function dutyEventKey(req) { const k = String((req.query && req.query.event) || 'main'); return DUTY_EVENTS[k] ? k : null; }

function buildDutyReminderMessage(doctorName, dutyYmd, daysLeft, evKey = 'main') {
  const rawName = String(doctorName || '').trim();
  const tokens = rawName.split(/\s+/).filter(t => !/^(dr\.?|doctor|د\.?|دكتور|دكتورة)$/i.test(t));
  const first = (tokens[0] || rawName).trim();
  const key = first.toLowerCase();
  const title = ARRIVAL_FEMALE.has(key) ? 'دكتورة' : (ARRIVAL_MALE.has(key) ? 'دكتور' : 'د.');
  const nameAr = ARRIVAL_AR_NAMES[key] || first;
  const dateAr = new Date(dutyYmd + 'T12:00:00Z').toLocaleDateString('ar-EG', { weekday: 'long', day: 'numeric', month: 'long', timeZone: 'UTC' });
  const when = daysLeft <= 0 ? 'النهاردة' : (daysLeft === 1 ? 'بكرة' : `كمان ${daysLeft} أيام`);
  return `${title} ${nameAr} 👋\nتذكير: ${when} (${dateAr}) دورك تغطي ${DUTY_EVENTS[evKey].ar} ✅\nلو في أي ظرف يمنعك، قول لدكتور مصطفى من دلوقتي عشان نظبط البديل.`;
}

async function sendDutyReminder(duty, evKey = 'main') {
  if (!TELEGRAM_BOT_TOKEN) throw new Error('Telegram bot is not set up on the server.');
  const r = await fetch(`${SUPABASE_URL}/rest/v1/doctors?email=eq.${encodeURIComponent(duty.doctor_email)}&select=name,telegram_chat_id&limit=1`, { headers: DUTY_HEADERS() });
  const rows = await r.json();
  const doc = Array.isArray(rows) && rows[0];
  if (!doc || !doc.telegram_chat_id) throw new Error('This doctor has not linked Telegram yet.');
  const daysLeft = ymdDiffDays(cairoTodayYmd(), String(duty.duty_date).slice(0, 10));
  await telegramSend(doc.telegram_chat_id, buildDutyReminderMessage(doc.name || duty.doctor_name, String(duty.duty_date).slice(0, 10), daysLeft, evKey));
}
async function markDuty(date, patch, evKey = 'main') {
  await fetch(`${SUPABASE_URL}/rest/v1/${DUTY_EVENTS[evKey].table}?duty_date=eq.${date}`, { method: 'PATCH', headers: { ...DUTY_HEADERS(), 'Content-Type': 'application/json', Prefer: 'return=minimal' }, body: JSON.stringify(patch) });
}

let dutyRunnerBusy = false;
async function runFridayDutyReminders() {
  if (dutyRunnerBusy || !SUPABASE_URL || !SUPABASE_SERVICE_KEY || !TELEGRAM_BOT_TOKEN) return;
  if (cairoHourNow() < 9) return;
  dutyRunnerBusy = true;
  try {
    const today = cairoTodayYmd();
    for (const evKey of Object.keys(DUTY_EVENTS)) {
    const r = await fetch(`${SUPABASE_URL}/rest/v1/${DUTY_EVENTS[evKey].table}?duty_date=gte.${today}&duty_date=lte.${new Date(Date.parse(today + 'T00:00:00Z') + 3 * 86400000).toISOString().slice(0, 10)}&order=duty_date.asc`, { headers: DUTY_HEADERS() });
    const rows = await r.json();
    if (!r.ok || !Array.isArray(rows)) continue;
    for (const duty of rows) {
      const date = String(duty.duty_date).slice(0, 10);
      let tgOk = !!duty.reminder_sent_at;
      if (!duty.reminder_sent_at && !(duty.reminder_error && duty.reminder_error.startsWith('tried:' + today))) {
        try {
          await sendDutyReminder(duty, evKey);
          await markDuty(date, { reminder_sent_at: new Date().toISOString(), reminder_error: null }, evKey);
          tgOk = true;
          console.log(`[friday-duty] reminder sent for ${date} to ${duty.doctor_email}`);
        } catch (err) {
          await markDuty(date, { reminder_error: `tried:${today} ${String(err.message || err).slice(0, 200)}` }, evKey);
          console.error('[friday-duty] reminder failed:', err.message);
        }
      }
      // Nudge the owner(s) once on Telegram to also send the WhatsApp message by hand.
      if (!duty.owner_nudged_at && !duty.whatsapp_sent_at) {
        try {
          const orows = await (await fetch(`${SUPABASE_URL}/rest/v1/doctors?role=eq.owner&status=eq.approved&telegram_chat_id=not.is.null&select=telegram_chat_id`, { headers: DUTY_HEADERS() })).json();
          const dateAr = new Date(date + 'T12:00:00Z').toLocaleDateString('ar-EG', { weekday: 'long', day: 'numeric', month: 'long', timeZone: 'UTC' });
          let sent = 0;
          for (const o of (Array.isArray(orows) ? orows : [])) {
            await telegramSend(o.telegram_chat_id, `📌 فكّر ${duty.doctor_name || 'الدكتور'} على واتساب كمان: دوره في ${DUTY_EVENTS[evKey].ownerAr} ${dateAr}.\n${tgOk ? 'التليجرام اتبعت له ✅' : 'التليجرام ماوصلوش ⚠ (يمكن مش رابط)'}\nافتح مساعد ← Dashboard ← Team ← Friday event duty ← "Send on WhatsApp".`);
            sent++;
          }
          if (sent) await markDuty(date, { owner_nudged_at: new Date().toISOString() }, evKey);
        } catch (err) { console.error('[friday-duty] owner nudge failed:', err.message); }
      }
    }
    }
  } catch (err) {
    console.error('[friday-duty] runner error:', err.message);
  } finally {
    dutyRunnerBusy = false;
  }
}
setInterval(runFridayDutyReminders, 10 * 60 * 1000);
setTimeout(runFridayDutyReminders, 45 * 1000);

app.get('/api/friday-duty', requireOwnerDoctor, async (req, res) => {
  try {
    const since = new Date(Date.now() - 7 * 86400000).toISOString().slice(0, 10);
    const [dr, pr, fr] = await Promise.all([
      fetch(`${SUPABASE_URL}/rest/v1/friday_duty?duty_date=gte.${since}&order=duty_date.asc&limit=200`, { headers: DUTY_HEADERS() }),
      fetch(`${SUPABASE_URL}/rest/v1/doctors?status=eq.approved&role=in.(doctor,owner)&select=email,name,phone,telegram_chat_id&order=name.asc`, { headers: DUTY_HEADERS() }),
      fetch(`${SUPABASE_URL}/rest/v1/friday_duty_football?duty_date=gte.${since}&order=duty_date.asc&limit=200`, { headers: DUTY_HEADERS() }),
    ]);
    // The football table is optional: a clinic that never ran its SQL simply doesn't see the second event.
    const fduties = fr.ok ? await fr.json().catch(() => []) : [];
    const duties = await dr.json();
    const docs = await pr.json();
    if (!dr.ok) return res.status(500).json({ error: 'Could not load duties. Did you run the friday_duty SQL?' });
    const withText = (list, evKey) => (Array.isArray(list) ? list : []).map(d => {
      const date = String(d.duty_date).slice(0, 10);
      return { ...d, whatsapp_text: buildDutyReminderMessage(d.doctor_name, date, Math.max(0, ymdDiffDays(cairoTodayYmd(), date)), evKey) };
    });
    res.json({
      football_ready: fr.ok,
      football_duties: withText(fduties, 'football'),
      telegram_ready: !!TELEGRAM_BOT_TOKEN,
      duties: (Array.isArray(duties) ? duties : []).map(d => {
        const date = String(d.duty_date).slice(0, 10);
        return { ...d, whatsapp_text: buildDutyReminderMessage(d.doctor_name, date, Math.max(0, ymdDiffDays(cairoTodayYmd(), date))) };
      }),
      doctors: (Array.isArray(docs) ? docs : []).map(d => ({ email: d.email, name: d.name, phone: d.phone || null, telegram_linked: !!d.telegram_chat_id })),
    });
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

app.put('/api/friday-duty/:date', requireOwnerDoctor, async (req, res) => {
  const evKey = dutyEventKey(req); if (!evKey) return res.status(400).json({ error: 'Unknown event.' });
  const date = String(req.params.date || '');
  if (!isFridayYmd(date)) return res.status(400).json({ error: 'That date is not a Friday.' });
  const email = String((req.body && req.body.doctorEmail) || '').trim().toLowerCase();
  if (!email) return res.status(400).json({ error: 'Pick a doctor.' });
  try {
    const pr = await fetch(`${SUPABASE_URL}/rest/v1/doctors?email=eq.${encodeURIComponent(email)}&status=eq.approved&select=email,name&limit=1`, { headers: DUTY_HEADERS() });
    const rows = await pr.json();
    const doc = Array.isArray(rows) && rows[0];
    if (!doc) return res.status(400).json({ error: 'Doctor not found.' });
    const up = await fetch(`${SUPABASE_URL}/rest/v1/${DUTY_EVENTS[evKey].table}?on_conflict=duty_date`, {
      method: 'POST',
      headers: { ...DUTY_HEADERS(), 'Content-Type': 'application/json', Prefer: 'resolution=merge-duplicates,return=minimal' },
      body: JSON.stringify({ duty_date: date, doctor_email: doc.email, doctor_name: doc.name, reminder_sent_at: null, reminder_error: null, owner_nudged_at: null, whatsapp_sent_at: null }),
    });
    if (!up.ok) { console.error('friday_duty upsert failed', up.status, await up.text().catch(() => '')); return res.status(500).json({ error: 'Could not save. Did you run the friday_duty SQL?' }); }
    res.json({ ok: true });
    setTimeout(runFridayDutyReminders, 1500); // if it is already inside the 3-day window, remind right away
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

app.delete('/api/friday-duty/:date', requireOwnerDoctor, async (req, res) => {
  const evKey = dutyEventKey(req); if (!evKey) return res.status(400).json({ error: 'Unknown event.' });
  const date = String(req.params.date || '');
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) return res.status(400).json({ error: 'Bad date.' });
  try {
    const d = await fetch(`${SUPABASE_URL}/rest/v1/${DUTY_EVENTS[evKey].table}?duty_date=eq.${date}`, { method: 'DELETE', headers: DUTY_HEADERS() });
    if (!d.ok) return res.status(500).json({ error: 'Delete failed.' });
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

app.post('/api/friday-duty/:date/whatsapp-sent', requireOwnerDoctor, async (req, res) => {
  const evKey = dutyEventKey(req); if (!evKey) return res.status(400).json({ error: 'Unknown event.' });
  const date = String(req.params.date || '');
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) return res.status(400).json({ error: 'Bad date.' });
  try { await markDuty(date, { whatsapp_sent_at: new Date().toISOString() }, evKey); res.json({ ok: true }); }
  catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

app.post('/api/friday-duty/:date/send-reminder', requireOwnerDoctor, async (req, res) => {
  const evKey = dutyEventKey(req); if (!evKey) return res.status(400).json({ error: 'Unknown event.' });
  const date = String(req.params.date || '');
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) return res.status(400).json({ error: 'Bad date.' });
  try {
    const r = await fetch(`${SUPABASE_URL}/rest/v1/${DUTY_EVENTS[evKey].table}?duty_date=eq.${date}&limit=1`, { headers: DUTY_HEADERS() });
    const rows = await r.json();
    const duty = Array.isArray(rows) && rows[0];
    if (!duty) return res.status(404).json({ error: 'Nobody is assigned that Friday.' });
    await sendDutyReminder(duty, evKey);
    await markDuty(date, { reminder_sent_at: new Date().toISOString(), reminder_error: null }, evKey);
    res.json({ ok: true });
  } catch (err) { res.status(400).json({ error: String(err.message || err) }); }
});


// =====================================================================
// ---- Online booking (public page /book) ----
// Patients pick a doctor + time from the doctor's open hours, pay half the
// fee as a non-refundable InstaPay deposit (upload the screenshot) and the
// visit lands in the calendar straight away. Patients who already have an
// active package skip the deposit. Tables: booking_settings, booking_deposits.
// =====================================================================
const BOOKING_BUCKET = 'booking-deposits';
const SHOT_TYPES = { 'image/jpeg': 'jpg', 'image/png': 'png', 'image/webp': 'webp' };
const SHOT_MAX_BYTES = 4 * 1024 * 1024;
const BOOKING_DEFAULTS = {
  enabled: false, compact: true, instapay: '', note: '', slot_minutes: 30, min_lead_hours: 2, max_days_ahead: 30,
  types: [
    { key: 'checkup', label: 'Check-up', label_ar: 'Check-up — كشف (جلسة تقييمية)', price: 0, visit_type: 'checkup' },
    { key: 'session1', label: 'Session - 1 body part', label_ar: 'جلسة — على مكان واحد (عضو واحد)', price: 500, visit_type: 'session' },
    { key: 'session2', label: 'Session - 2 body parts', label_ar: 'جلسة — على أكتر من مكان (عضوين)', price: 750, visit_type: 'session' },
    { key: 'recovery_half', label: 'Recovery - Half Body', label_ar: 'Recovery - Half Body', price: 900, visit_type: 'recovery' },
    { key: 'recovery_full', label: 'Recovery - Full Body', label_ar: 'Recovery - Full Body', price: 1500, visit_type: 'recovery' },
  ],
  hours: {},
  docs: {},
};
const bookHits = new Map();
function bookRateLimited(ip, kind, max, windowMs) {
  const k = kind + '|' + ip, now = Date.now();
  const arr = (bookHits.get(k) || []).filter(t => now - t < windowMs);
  if (arr.length >= max) { bookHits.set(k, arr); return true; }
  arr.push(now); bookHits.set(k, arr); return false;
}
const bookHeaders = () => ({ apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` });
// ---- Clinic settings (name, address, links, message texts, payroll rules) ----
// Stored in booking_settings row id=2 so no new table is needed. Every clinic
// that installs the app fills these in from Settings > Clinic.
const CLINIC_DEFAULTS = { name: 'Your Clinic', name_ar: '', address: '', address_ar: '', map_url: '', phone: '', instapay_url: '', instapay_handle: '', review_url: '', intake_url: '', tagline: '', logo: '', stamp: '', fixed_costs: [], hr_staff: [], hr_start: '', links: [], templates: {}, payroll_rules: [] };
let clinicCache = null, clinicCacheAt = 0;
async function getClinicConfig(force) {
  if (!force && clinicCache && Date.now() - clinicCacheAt < 60000) return clinicCache;
  let data = {};
  try {
    const r = await fetch(`${SUPABASE_URL}/rest/v1/booking_settings?id=eq.2&select=data&limit=1`, { headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` } });
    const rows = await r.json();
    if (Array.isArray(rows) && rows[0] && rows[0].data) data = rows[0].data;
  } catch (e) { if (clinicCache) return clinicCache; }
  const c = { ...CLINIC_DEFAULTS, ...data };
  c.templates = data.templates && typeof data.templates === 'object' ? data.templates : {};
  c.payroll_rules = Array.isArray(data.payroll_rules) ? data.payroll_rules : [];
  c.links = Array.isArray(data.links) ? data.links : [];
  c.fixed_costs = cleanFixedCosts(data.fixed_costs);
  c.hr_staff = cleanHrStaff(data.hr_staff);
  c.hr_start = /^\d{4}-\d{2}-\d{2}$/.test(String(data.hr_start || '')) ? data.hr_start : '';
  if (!String(c.name || '').trim()) c.name = CLINIC_DEFAULTS.name;
  clinicCache = c; clinicCacheAt = Date.now();
  PAYROLL_RULES = c.payroll_rules;
  return c;
}
const clinicEsc = (v) => String(v == null ? '' : v).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
const clinicJs = (v) => JSON.stringify(String(v == null ? '' : v)).slice(1, -1).replace(/</g, '\\u003c').replace(/'/g, "\\'");
function renderClinicPage(html, c) {
  return html.replace(/__ADDR_EN__/g, clinicJs(clinicEsc(c.address))).replace(/__ADDR_AR__/g, clinicJs(clinicEsc(c.address_ar || c.address)))
    .replace(/__MAP_URL__/g, clinicEsc(c.map_url || '#')).replace(/Empower/g, clinicEsc(c.name));
}
const safeLinkUrl = (u) => { const t = String(u == null ? '' : u).trim().slice(0, 300); return /^(https?:\/\/|tel:|mailto:)/i.test(t) ? t : ''; };
const cleanLinks = (arr) => (Array.isArray(arr) ? arr : []).slice(0, 12).map((l) => ({ label: clinicText(l && l.label, 60).trim(), url: safeLinkUrl(l && l.url) })).filter((l) => l.label && l.url);
const clinicText = (v, n) => String(v == null ? '' : v).replace(/[\u0000-\u0009\u000b-\u001f]/g, ' ').slice(0, n);
app.get('/api/clinic-config', requireApprovedAny, async (req, res) => {
  try {
    const c = await getClinicConfig(true);
    const out = { ...c };
    if (!req.doctor || (req.doctor.role !== 'owner' && !(req.doctor.permissions && req.doctor.permissions.view_payroll))) { delete out.payroll_rules; }
    res.json(out);
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});
const cleanFixedCosts = (arr) => (Array.isArray(arr) ? arr : []).slice(0, 30).map((f) => {
  const name = clinicText(f && f.name, 60).trim(); const amount = parseFloat(f && f.amount);
  if (!name || !Number.isFinite(amount) || amount <= 0) return null;
  return { name, amount: Math.round(amount * 100) / 100, method: f.method === 'instapay' ? 'instapay' : 'cash' };
}).filter(Boolean);
const cleanHrStaff = (arr) => (Array.isArray(arr) ? arr : []).slice(0, 40).map((x) => {
  const label = clinicText(x && x.label, 60).trim(), keyword = clinicText(x && x.keyword, 40).trim().toLowerCase();
  if (!label || !keyword) return null;
  const days = [...new Set((Array.isArray(x.days) ? x.days : []).map((d) => parseInt(d, 10)).filter((d) => d >= 0 && d <= 6))].sort();
  const allowance = Math.max(0, Math.min(366, parseFloat(x.allowance) || 0));
  const shifts = {};
  if (x.shifts && typeof x.shifts === 'object') {
    for (const [k, v] of Object.entries(x.shifts)) {
      const d = parseInt(k, 10);
      if (!(d >= 0 && d <= 6) || !Array.isArray(v)) continue;
      const a = String(v[0] || ''), b = String(v[1] || '');
      if (/^\d{2}:\d{2}$/.test(a) && /^\d{2}:\d{2}$/.test(b) && a < b) { shifts[d] = [a, b]; if (!days.includes(d)) days.push(d); }
    }
    days.sort();
  }
  const kind = x.kind === 'secretary' ? 'secretary' : 'doctor';
  const case_rate = Math.max(0, Math.min(100000, parseFloat(x.case_rate) || 0));
  return { label, keyword, kind, days, shifts, allowance, case_rate };
}).filter(Boolean);
const cleanDataImg = (v) => { const t = String(v || ''); return t.length <= 400000 && /^data:image\/(png|jpeg|webp);base64,[A-Za-z0-9+\/=]+$/.test(t) ? t : ''; };
app.put('/api/clinic-config', requireOwnerDoctor, async (req, res) => {
  const b = req.body || {};
  const num = (v, lo, hi) => { const n = parseFloat(v); return Number.isFinite(n) ? Math.min(hi, Math.max(lo, n)) : null; };
  const rules = (Array.isArray(b.payroll_rules) ? b.payroll_rules : []).slice(0, 40).map((r) => {
    const kind = ['partner', 'revenue_share', 'fixed_plus_rate'].includes(r.kind) ? r.kind : null;
    const keyword = clinicText(r.keyword, 40).trim().toLowerCase(); const label = clinicText(r.label, 60).trim();
    if (!kind || !keyword || !label) return null;
    const out = { keyword, kind, label };
    if (kind === 'fixed_plus_rate') { out.fixed = num(r.fixed, 0, 10000000) || 0; out.rate = num(r.rate, 0, 1000000) || 0; }
    else { const sh = num(r.share, 0, 1); if (sh != null) out.share = sh; if (kind === 'revenue_share') { const os = num(r.own_share, 0, 1); if (os != null && r.own_share !== '' && r.own_share !== null) out.own_share = os; } }
    return out;
  }).filter(Boolean);
  const templates = {};
  for (const k of ['confirmation', 'elevator', 'package_policy', 'recovery_session_policy', 'instapay_payment', 'intake_form', 'package_last_session']) {
    const t = clinicText(b.templates && b.templates[k], 4000).trim();
    if (t) templates[k] = t;
  }
  const data = {
    name: clinicText(b.name, 80).trim() || CLINIC_DEFAULTS.name, name_ar: clinicText(b.name_ar, 80).trim(),
    address: clinicText(b.address, 200).trim(), address_ar: clinicText(b.address_ar, 200).trim(), map_url: clinicText(b.map_url, 300).trim(),
    phone: clinicText(b.phone, 30).trim(), instapay_url: clinicText(b.instapay_url, 300).trim(), instapay_handle: clinicText(b.instapay_handle, 100).trim(),
    review_url: clinicText(b.review_url, 300).trim(), intake_url: clinicText(b.intake_url, 300).trim(), tagline: clinicText(b.tagline, 120).trim(), logo: cleanDataImg(b.logo), stamp: cleanDataImg(b.stamp), fixed_costs: cleanFixedCosts(b.fixed_costs), hr_staff: cleanHrStaff(b.hr_staff), hr_start: /^\d{4}-\d{2}-\d{2}$/.test(String(b.hr_start || '')) ? b.hr_start : '', links: cleanLinks(b.links), templates, payroll_rules: rules,
  };
  try { const cur = await getClinicConfig(true); if (cur && cur.features && typeof cur.features === 'object') data.features = cur.features; } catch (e) { /* keep going */ }
  try {
    const r = await fetch(`${SUPABASE_URL}/rest/v1/booking_settings?on_conflict=id`, { method: 'POST', headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`, 'Content-Type': 'application/json', Prefer: 'resolution=merge-duplicates,return=minimal' }, body: JSON.stringify({ id: 2, data, updated_at: new Date().toISOString() }) });
    if (!r.ok) { console.error('clinic config save failed', r.status, await r.text().catch(() => '')); return res.status(500).json({ error: 'Could not save.' }); }
    await getClinicConfig(true);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

const bookClean = (v, n) => String(v == null ? '' : v).replace(/[\u0000-\u001f]/g, ' ').trim().slice(0, n);

async function getBookingSettings() {
  let data = {};
  try {
    const r = await fetch(`${SUPABASE_URL}/rest/v1/booking_settings?id=eq.1&select=data&limit=1`, { headers: bookHeaders() });
    const rows = await r.json();
    if (Array.isArray(rows) && rows[0] && rows[0].data) data = rows[0].data;
  } catch (e) { /* defaults */ }
  return {
    ...BOOKING_DEFAULTS, ...data,
    types: Array.isArray(data.types) && data.types.length ? data.types : BOOKING_DEFAULTS.types,
    hours: data.hours && typeof data.hours === 'object' ? data.hours : {},
    docs: data.docs && typeof data.docs === 'object' ? data.docs : {},
  };
}

function cairoWall(ms) {
  const p = new Intl.DateTimeFormat('en-CA', { timeZone: 'Africa/Cairo', hourCycle: 'h23', year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' })
    .formatToParts(new Date(ms)).reduce((a, x) => (a[x.type] = x.value, a), {});
  return Date.UTC(+p.year, +p.month - 1, +p.day, +p.hour, +p.minute);
}
function cairoToDate(ymd, hm) {
  const [y, m, d] = ymd.split('-').map(Number), [h, mi] = hm.split(':').map(Number);
  const target = Date.UTC(y, m - 1, d, h, mi);
  let ms = target;
  for (let i = 0; i < 3; i++) ms += target - cairoWall(ms);
  return new Date(ms);
}
const hmToMin = hm => { const [h, m] = hm.split(':').map(Number); return h * 60 + m; };
const minToHm = n => String(Math.floor(n / 60)).padStart(2, '0') + ':' + String(n % 60).padStart(2, '0');
const bookDocToken = email => crypto.createHmac('sha256', SUPABASE_SERVICE_KEY || 'x').update(String(email).toLowerCase()).digest('hex').slice(0, 12);

async function bookableDoctors(settings) {
  const r = await fetch(`${SUPABASE_URL}/rest/v1/doctors?status=eq.approved&role=in.(doctor,owner)&select=email,name,color,telegram_chat_id&order=name.asc`, { headers: bookHeaders() });
  const rows = await r.json();
  return (Array.isArray(rows) ? rows : []).filter(d => {
    const h = settings.hours[d.email];
    return h && Object.values(h).some(v => Array.isArray(v) && v.length);
  });
}

async function computeBookingSlots(settings, doc, ymd) {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(ymd)) return [];
  const diff = ymdDiffDays(cairoTodayYmd(), ymd);
  if (diff < 0 || diff > settings.max_days_ahead) return [];
  const wd = String(new Date(ymd + 'T12:00:00Z').getUTCDay());
  const ranges = ((settings.hours[doc.email] || {})[wd]) || [];
  if (!ranges.length) return [];
  const step = settings.slot_minutes;
  const dayStart = cairoToDate(ymd, '00:00');
  const dayEnd = new Date(dayStart.getTime() + 25 * 3600000);
  const r = await fetch(`${SUPABASE_URL}/rest/v1/appointments?doctor_name=eq.${encodeURIComponent(doc.name)}&start_time=gte.${encodeURIComponent(dayStart.toISOString())}&start_time=lt.${encodeURIComponent(dayEnd.toISOString())}&deleted_at=is.null&select=start_time,end_time,status`, { headers: bookHeaders() });
  const appts = await r.json();
  const busy = (Array.isArray(appts) ? appts : []).filter(a => a.status !== 'cancelled').map(a => [new Date(a.start_time).getTime(), new Date(a.end_time || new Date(a.start_time).getTime() + 30 * 60000).getTime()]);
  const earliest = Date.now() + settings.min_lead_hours * 3600000;
  // "Keep the day together" (on unless the clinic turns it off): once the doctor has visits that day,
  // patients only see times inside that block (gaps between visits) or the slot right before the first
  // / right after the last one. When that slot fills, the next one opens. An empty day shows every time.
  let near = null;
  if (settings.compact !== false && busy.length) {
    const first = Math.min(...busy.map(b => b[0])), last = Math.max(...busy.map(b => b[1]));
    near = [first - step * 60000, last + step * 60000];
  }
  const out = [];
  for (const [from, to] of ranges) {
    for (let t = hmToMin(from); t + step <= hmToMin(to); t += step) {
      const hm = minToHm(t);
      const s = cairoToDate(ymd, hm).getTime(), e = s + step * 60000;
      if (s < earliest) continue;
      if (busy.some(([bs, be]) => s < be && e > bs)) continue;
      if (near && (e <= near[0] || s >= near[1])) continue;
      if (!out.includes(hm)) out.push(hm);
    }
  }
  return out.sort();
}

const bookRule = (settings, email) => (settings.docs && settings.docs[email]) || {};
const bookBlockedByGender = (settings, email, gender) => bookRule(settings, email).gender === 'female' && gender === 'male';
const bookPhoneKey = p => String(p || '').replace(/\D/g, '').slice(-10);
// Same person written slightly differently (capitals, extra spaces, أ/ا, ة/ه, ى/ي, "Mr/Mrs") still matches.
const bookNameKey = n => String(n || '').toLowerCase()
  .replace(/[\u064B-\u0652\u0640]/g, '').replace(/[أإآ]/g, 'ا').replace(/ة/g, 'ه').replace(/ى/g, 'ي')
  .replace(/[^a-z0-9\u0600-\u06FF]+/g, ' ').replace(/\b(mr|mrs|ms|miss|dr)\b/g, ' ').replace(/\s+/g, ' ').trim();
async function hasActivePackageByPhone(phone) {
  const key = bookPhoneKey(phone);
  if (key.length < 10) return false;
  const pr = await fetch(`${SUPABASE_URL}/rest/v1/packages?select=patient_name,total_sessions,used_sessions&order=created_at.desc&limit=2000`, { headers: bookHeaders() });
  const pk = await pr.json();
  const names = new Set((Array.isArray(pk) ? pk : []).filter(p => p.used_sessions < p.total_sessions).map(p => bookNameKey(p.patient_name)).filter(Boolean));
  if (!names.size) return false;
  const ar = await fetch(`${SUPABASE_URL}/rest/v1/appointments?select=patient_name,patient_phone&patient_phone=not.is.null&deleted_at=is.null&order=start_time.desc&limit=5000`, { headers: bookHeaders() });
  const rows = await ar.json();
  return (Array.isArray(rows) ? rows : []).some(a => bookPhoneKey(a.patient_phone) === key && names.has(bookNameKey(a.patient_name)));
}

app.get('/api/book/config', async (req, res) => {
  try {
    const s = await getBookingSettings();
    const docs = s.enabled ? await bookableDoctors(s) : [];
    const pg = ['male', 'female'].includes(String(req.query.gender || '')) ? String(req.query.gender) : '';
    const gotInfo = !!pg && bookClean(req.query.name, 120).length >= 3 && String(req.query.phone || '').replace(/\D/g, '').length >= 10;
    if (!gotInfo) return res.set('Cache-Control', 'no-store').json({ enabled: !!s.enabled && docs.length > 0, locked: true });
    if (s.enabled && docs.length) {
      const ip = String(req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
      if (!bookRateLimited(ip, 'lead', 15, 3600000)) {
        fetch(`${SUPABASE_URL}/rest/v1/booking_leads?on_conflict=phone_key`, {
          method: 'POST', headers: { ...bookHeaders(), 'Content-Type': 'application/json', Prefer: 'resolution=merge-duplicates,return=minimal' },
          body: JSON.stringify({ phone_key: bookPhoneKey(req.query.phone), name: bookClean(req.query.name, 120), phone: bookClean(req.query.phone, 20).replace(/[^0-9+]/g, ''), last_seen: new Date().toISOString() }),
        }).catch(() => {});
      }
    }
    const pkg = s.enabled && docs.length ? await hasActivePackageByPhone(req.query.phone).catch(() => false) : false;
    res.set('Cache-Control', 'no-store').json({
      enabled: !!s.enabled && docs.length > 0, pkg, instapay: s.instapay, note: s.note, max_days_ahead: s.max_days_ahead,
      types: s.types.filter(t => t.price > 0).map(t => ({ key: t.key, label: t.label, label_ar: t.label_ar || '', visit_type: t.visit_type || 'session', price: t.price, deposit: Math.round(t.price / 2) })),
      doctors: docs.filter(d => !bookBlockedByGender(s, d.email, pg)).map(d => ({ id: bookDocToken(d.email), name: d.name, checkups: bookRule(s, d.email).checkups !== false })),
    });
  } catch (err) { res.status(500).json({ error: 'Booking is not available right now.' }); }
});

app.get('/api/book/slots', async (req, res) => {
  const ip = String(req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
  if (bookRateLimited(ip, 'slots', 120, 600000)) return res.status(429).json({ error: 'Too many requests. Please wait a moment.' });
  try {
    if (String(req.query.phone || '').replace(/\D/g, '').length < 10) return res.json({ times: [] });
    const s = await getBookingSettings();
    if (!s.enabled) return res.json({ times: [] });
    const doc = (await bookableDoctors(s)).find(d => bookDocToken(d.email) === String(req.query.doctor || ''));
    if (!doc || bookBlockedByGender(s, doc.email, String(req.query.gender || ''))) return res.json({ times: [] });
    res.set('Cache-Control', 'no-store').json({ times: await computeBookingSlots(s, doc, String(req.query.date || '')) });
  } catch (err) { res.status(500).json({ error: 'Could not load times.' }); }
});

app.get('/api/book/availability', async (req, res) => {
  const ip = String(req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
  if (bookRateLimited(ip, 'avail', 40, 600000)) return res.status(429).json({ error: 'Too many requests. Please wait a moment.' });
  try {
    if (String(req.query.phone || '').replace(/\D/g, '').length < 10) return res.json({ days: [] });
    const s = await getBookingSettings();
    if (!s.enabled) return res.json({ days: [] });
    const doc = (await bookableDoctors(s)).find(d => bookDocToken(d.email) === String(req.query.doctor || ''));
    if (!doc || bookBlockedByGender(s, doc.email, String(req.query.gender || ''))) return res.json({ days: [] });
    const base = new Date(cairoTodayYmd() + 'T12:00:00Z');
    const n = Math.min(Number(s.max_days_ahead) || 14, 14);
    const list = [];
    for (let i = 0; i <= n; i++) list.push(new Date(base.getTime() + i * 86400000).toISOString().slice(0, 10));
    const all = await Promise.all(list.map(async d => ({ date: d, times: await computeBookingSlots(s, doc, d).catch(() => []) })));
    res.set('Cache-Control', 'no-store').json({ days: all.filter(x => x.times.length) });
  } catch (err) { res.status(500).json({ error: 'Could not load times.' }); }
});

app.post('/api/book', async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Booking is not available right now.' });
  const ip = String(req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
  if (bookRateLimited(ip, 'book', 6, 3600000)) return res.status(429).json({ error: 'Too many attempts. Please try again later.' });
  const b = req.body || {};
  if (b.website) return res.json({ ok: true }); // honeypot
  try {
    const s = await getBookingSettings();
    if (!s.enabled) return res.status(400).json({ error: 'Online booking is closed right now.' });
    const name = bookClean(b.name, 120), phone = bookClean(b.phone, 20).replace(/[^0-9+]/g, '');
    if (name.length < 3 || phone.replace(/\D/g, '').length < 10) return res.status(400).json({ error: 'Please enter your full name and a valid phone number.' });
    const type = s.types.find(t => t.key === b.type && t.price > 0);
    const doc = (await bookableDoctors(s)).find(d => bookDocToken(d.email) === String(b.doctor || ''));
    if (!type || !doc) return res.status(400).json({ error: 'Please choose a visit type and a doctor.' });
    const gender = ['male', 'female'].includes(String(b.gender || '')) ? String(b.gender) : '';
    if (!gender) return res.status(400).json({ error: 'Please choose your gender.' });
    if (bookBlockedByGender(s, doc.email, gender)) return res.status(400).json({ error: 'This doctor is not available for your booking. Please choose another doctor.' });
    if (type.visit_type === 'checkup' && bookRule(s, doc.email).checkups === false) return res.status(400).json({ error: 'This doctor does not take check-ups. Please choose another doctor.' });
    const date = String(b.date || ''), time = String(b.time || '');
    const times = await computeBookingSlots(s, doc, date);
    if (!/^\d{2}:\d{2}$/.test(time) || !times.includes(time)) return res.status(409).json({ error: 'Sorry, that time is no longer available. Please pick another one.' });

    const pkg = await hasActivePackageByPhone(phone);
    const deposit = pkg ? 0 : Math.round(type.price / 2);
    let shotPath = null;
    if (!pkg) {
      const ext = SHOT_TYPES[String(b.shotType || '').toLowerCase()];
      if (!ext || !b.shotBase64) return res.status(400).json({ error: 'Please upload the InstaPay transfer screenshot to confirm your booking.' });
      const bytes = Buffer.from(String(b.shotBase64), 'base64');
      if (bytes.length < 500 || bytes.length > SHOT_MAX_BYTES) return res.status(400).json({ error: 'The screenshot is not valid (max 4 MB).' });
      shotPath = `${Date.now()}_${Math.random().toString(36).slice(2, 10)}/deposit.${ext}`;
      const up = await fetch(`${SUPABASE_URL}/storage/v1/object/${BOOKING_BUCKET}/${shotPath}`, { method: 'POST', headers: { ...bookHeaders(), 'Content-Type': String(b.shotType), 'x-upsert': 'false' }, body: bytes });
      if (!up.ok) { console.error('Deposit upload failed:', up.status, await up.text().catch(() => '')); return res.status(500).json({ error: 'Could not save the screenshot. Please try again.' }); }
    }

    const start = cairoToDate(date, time), end = new Date(start.getTime() + s.slot_minutes * 60000);
    const noteText = pkg
      ? 'Online booking - patient has an active package, no deposit needed.'
      : `Online booking - deposit of ${deposit} EGP received by InstaPay (non-refundable). Deduct it from the fee. Screenshot is in Dashboard > Booking.`;
    const ins = await fetch(`${SUPABASE_URL}/rest/v1/appointments`, {
      method: 'POST', headers: { ...bookHeaders(), 'Content-Type': 'application/json', Prefer: 'return=representation' },
      body: JSON.stringify({
        patient_name: name, patient_phone: phone, start_time: start.toISOString(), end_time: end.toISOString(),
        doctor_name: doc.name, doctor_color: doc.color || null, visit_type: type.visit_type || 'session',
        notes: [{ text: noteText, author: 'Online booking', at: new Date().toISOString() }],
      }),
    });
    const created = await ins.json();
    if (!ins.ok || !Array.isArray(created) || !created[0]) { console.error('Online booking insert failed:', ins.status, JSON.stringify(created)); return res.status(500).json({ error: 'Could not save your booking. Please try again.' }); }
    const appt = created[0];

    // Two people tapping the same slot at the same moment: the earlier one keeps it.
    try {
      const same = await (await fetch(`${SUPABASE_URL}/rest/v1/appointments?doctor_name=eq.${encodeURIComponent(doc.name)}&start_time=eq.${encodeURIComponent(start.toISOString())}&deleted_at=is.null&status=neq.cancelled&select=id,created_at&order=created_at.asc`, { headers: bookHeaders() })).json();
      if (Array.isArray(same) && same.length > 1 && String(same[0].id) !== String(appt.id)) {
        await fetch(`${SUPABASE_URL}/rest/v1/appointments?id=eq.${encodeURIComponent(appt.id)}`, { method: 'PATCH', headers: { ...bookHeaders(), 'Content-Type': 'application/json' }, body: JSON.stringify({ status: 'cancelled' }) });
        return res.status(409).json({ error: 'Sorry, someone just took that time. Please pick another one. (Your screenshot was not used.)' });
      }
    } catch (e) { /* best effort */ }

    await fetch(`${SUPABASE_URL}/rest/v1/booking_deposits`, {
      method: 'POST', headers: { ...bookHeaders(), 'Content-Type': 'application/json', Prefer: 'return=minimal' },
      body: JSON.stringify({ appointment_id: String(appt.id), patient_name: name, phone, doctor_name: doc.name, visit_label: type.label, start_time: start.toISOString(), amount: deposit, package_booking: !!pkg, screenshot_path: shotPath }),
    }).catch(e => console.error('Deposit row insert failed:', e.message));

    fetch(`${SUPABASE_URL}/rest/v1/booking_leads?phone_key=eq.${bookPhoneKey(phone)}`, { method: 'PATCH', headers: { ...bookHeaders(), 'Content-Type': 'application/json' }, body: JSON.stringify({ completed: true }) }).catch(() => {});
    res.json({ ok: true, doctor: doc.name, date, time, label: type.label, deposit, package: !!pkg });

    // Tell the owner(s) and the doctor on Telegram (best effort).
    try {
      const dateAr = new Date(date + 'T12:00:00Z').toLocaleDateString('ar-EG', { weekday: 'long', day: 'numeric', month: 'long', timeZone: 'UTC' });
      const msg = `📅 حجز أونلاين جديد\n${name} · ${phone}\n${dateAr} الساعة ${time}\nمع ${doc.name} — ${type.label}\n${pkg ? 'عنده باكدج — من غير deposit' : `Deposit ${deposit} جنيه (InstaPay) — راجع الصورة من Dashboard ← Booking`}`;
      const owners = await (await fetch(`${SUPABASE_URL}/rest/v1/doctors?role=eq.owner&status=eq.approved&telegram_chat_id=not.is.null&select=telegram_chat_id`, { headers: bookHeaders() })).json();
      const chats = new Set((Array.isArray(owners) ? owners : []).map(o => o.telegram_chat_id));
      if (doc.telegram_chat_id) chats.add(doc.telegram_chat_id);
      for (const c of chats) await telegramSend(c, msg).catch(() => {});
    } catch (e) { /* ignore */ }
    // Phone notification + the in-app bell: the doctor of the visit and the clinic owner(s) (best effort).
    pushOnlineBooking(appt, doc, name, type.label, !!pkg).catch(e => console.error('Push alert failed:', e.message));
  } catch (err) {
    console.error('Online booking error:', err);
    res.status(500).json({ error: 'Something went wrong. Please try again.' });
  }
});

// ---- Owner side ----
app.get('/api/booking/settings', requireOwnerDoctor, async (req, res) => {
  try {
    const s = await getBookingSettings();
    const dr = await (await fetch(`${SUPABASE_URL}/rest/v1/doctors?status=eq.approved&role=in.(doctor,owner)&select=email,name&order=name.asc`, { headers: bookHeaders() })).json();
    res.json({ settings: s, doctors: Array.isArray(dr) ? dr : [] });
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

app.put('/api/booking/settings', requireOwnerDoctor, async (req, res) => {
  const b = req.body || {};
  const num = (v, lo, hi, d) => { const n = parseInt(v, 10); return Number.isFinite(n) ? Math.min(hi, Math.max(lo, n)) : d; };
  const types = (Array.isArray(b.types) ? b.types : []).slice(0, 8).map((t, i) => ({
    key: bookClean(t.key, 30).replace(/[^a-z0-9_-]/gi, '') || ('type' + (i + 1)),
    label: bookClean(t.label, 60), label_ar: bookClean(t.label_ar, 90), price: num(t.price, 0, 100000, 0),
    visit_type: ['session', 'checkup', 'recovery'].includes(t.visit_type) ? t.visit_type : 'session',
  })).filter(t => t.label);
  const hours = {};
  for (const [email, days] of Object.entries(b.hours && typeof b.hours === 'object' ? b.hours : {})) {
    if (typeof email !== 'string' || email.length > 120 || !days || typeof days !== 'object') continue;
    for (const wd of ['0', '1', '2', '3', '4', '5', '6']) {
      const ranges = (Array.isArray(days[wd]) ? days[wd] : []).slice(0, 3)
        .filter(r => Array.isArray(r) && /^\d{2}:\d{2}$/.test(r[0]) && /^\d{2}:\d{2}$/.test(r[1]) && hmToMin(r[0]) < hmToMin(r[1]))
        .map(r => [r[0], r[1]]);
      if (ranges.length) { (hours[email] = hours[email] || {})[wd] = ranges; }
    }
  }
  const docsRules = {};
  for (const [email, r] of Object.entries(b.docs && typeof b.docs === 'object' ? b.docs : {})) {
    if (typeof email !== 'string' || email.length > 120 || !r || typeof r !== 'object') continue;
    docsRules[email] = { gender: ['male', 'female'].includes(r.gender) ? r.gender : '', checkups: r.checkups !== false };
  }
  const data = { enabled: !!b.enabled, compact: b.compact !== false, docs: docsRules, instapay: bookClean(b.instapay, 200), note: bookClean(b.note, 600), slot_minutes: num(b.slot_minutes, 15, 120, 30), min_lead_hours: num(b.min_lead_hours, 0, 72, 2), max_days_ahead: num(b.max_days_ahead, 1, 90, 30), types, hours };
  try {
    const r = await fetch(`${SUPABASE_URL}/rest/v1/booking_settings?on_conflict=id`, { method: 'POST', headers: { ...bookHeaders(), 'Content-Type': 'application/json', Prefer: 'resolution=merge-duplicates,return=minimal' }, body: JSON.stringify({ id: 1, data, updated_at: new Date().toISOString() }) });
    if (!r.ok) { console.error('booking_settings save failed', r.status, await r.text().catch(() => '')); return res.status(500).json({ error: 'Could not save. Did you run the booking SQL?' }); }
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

app.get('/api/login-log', requireOwnerDoctor, async (req, res) => {
  try {
    const r = await fetch(`${SUPABASE_URL}/rest/v1/login_log?order=created_at.desc&limit=300`, { headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` } });
    const rows = await r.json();
    if (!r.ok) return res.status(500).json({ error: 'Could not load. Did you run the login log SQL?' });
    res.json(rows);
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});
app.get('/api/booking/leads', requireOwnerOrSecretary, async (req, res) => {
  try {
    const r = await fetch(`${SUPABASE_URL}/rest/v1/booking_leads?completed=eq.false&order=last_seen.desc&limit=100`, { headers: bookHeaders() });
    const rows = await r.json();
    if (!r.ok) return res.status(500).json({ error: 'Could not load. Did you run the leads SQL?' });
    res.json(rows);
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});
app.delete('/api/booking/leads/:id', requireOwnerOrSecretary, async (req, res) => {
  try {
    await fetch(`${SUPABASE_URL}/rest/v1/booking_leads?id=eq.${encodeURIComponent(req.params.id)}`, { method: 'DELETE', headers: bookHeaders() });
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

app.get('/api/booking/deposits', requireOwnerOrSecretary, async (req, res) => {
  try {
    const r = await fetch(`${SUPABASE_URL}/rest/v1/booking_deposits?order=created_at.desc&limit=150`, { headers: bookHeaders() });
    const rows = await r.json();
    if (!r.ok) return res.status(500).json({ error: 'Could not load. Did you run the booking SQL?' });
    res.json(rows);
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

app.get('/api/booking/deposits/:id/shot', requireOwnerOrSecretary, async (req, res) => {
  try {
    const rows = await (await fetch(`${SUPABASE_URL}/rest/v1/booking_deposits?id=eq.${encodeURIComponent(req.params.id)}&select=screenshot_path&limit=1`, { headers: bookHeaders() })).json();
    const p = rows && rows[0] && rows[0].screenshot_path;
    if (!p) return res.status(404).json({ error: 'No screenshot.' });
    const s = await fetch(`${SUPABASE_URL}/storage/v1/object/sign/${BOOKING_BUCKET}/${p}`, { method: 'POST', headers: { ...bookHeaders(), 'Content-Type': 'application/json' }, body: JSON.stringify({ expiresIn: 600 }) });
    const j = await s.json();
    if (!s.ok || !j.signedURL) return res.status(500).json({ error: 'Could not open the screenshot.' });
    res.json({ url: `${SUPABASE_URL}/storage/v1${j.signedURL}` });
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

app.post('/api/booking/deposits/:id/review', requireOwnerOrSecretary, async (req, res) => {
  const status = req.body && req.body.status;
  if (!['ok', 'rejected'].includes(status)) return res.status(400).json({ error: 'Bad status.' });
  try {
    const rows = await (await fetch(`${SUPABASE_URL}/rest/v1/booking_deposits?id=eq.${encodeURIComponent(req.params.id)}&select=appointment_id&limit=1`, { headers: bookHeaders() })).json();
    const row = Array.isArray(rows) && rows[0];
    if (!row) return res.status(404).json({ error: 'Not found.' });
    await fetch(`${SUPABASE_URL}/rest/v1/booking_deposits?id=eq.${encodeURIComponent(req.params.id)}`, { method: 'PATCH', headers: { ...bookHeaders(), 'Content-Type': 'application/json' }, body: JSON.stringify({ status, reviewed_at: new Date().toISOString() }) });
    if (status === 'rejected' && row.appointment_id) {
      await fetch(`${SUPABASE_URL}/rest/v1/appointments?id=eq.${encodeURIComponent(row.appointment_id)}`, { method: 'PATCH', headers: { ...bookHeaders(), 'Content-Type': 'application/json' }, body: JSON.stringify({ status: 'cancelled' }) });
    }
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

const BOOK_PAGE = String.raw`<!doctype html><html lang="ar" dir="rtl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex"><meta name="theme-color" content="#f6f4ee"><title>Book an appointment - Empower</title>
<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin><link href="https://fonts.googleapis.com/css2?family=Cairo:wght@400;600;700&display=swap" rel="stylesheet">
<style>
:root{--ink:#12363a;--muted:#667570;--gold:#b07a1f;--bg:#f7f8f6;--line:#e6e9e4;--soft:#eef4f2;--tint:#fbf5e6}
*{box-sizing:border-box;-webkit-tap-highlight-color:transparent}
html{font-size:18px}
html{overflow-x:hidden}body{overflow-x:hidden;margin:0;background:var(--bg);color:var(--ink);font-family:'Cairo',-apple-system,'Segoe UI',Roboto,Arial,sans-serif;line-height:1.55;padding:0 0 40px}
.wrap{max-width:520px;margin:0 auto;padding:18px 16px}
.top{display:flex;align-items:center;justify-content:space-between;margin-bottom:6px}
.lang{border:1px solid var(--line);background:#fff;color:var(--ink);border-radius:999px;padding:6px 16px;font:600 .8rem 'Cairo',sans-serif;cursor:pointer}
.logo{display:block;width:210px;max-width:60%;margin:6px auto 8px}
h1{font-size:1.45rem;text-align:center;margin:6px 0 2px;font-weight:700}
.sub{text-align:center;color:var(--muted);font-size:.9rem;margin-bottom:18px}
.steps{display:flex;justify-content:center;gap:8px;margin:0 0 18px}
.dot{width:34px;height:5px;border-radius:5px;background:var(--line)}.dot.on{background:var(--gold)}
.card{background:#fff;border-radius:18px;padding:20px;box-shadow:0 2px 14px rgba(18,54,58,.06);margin-bottom:14px}
.card h2{font-size:1rem;margin:0 0 12px;font-weight:700}
label{display:block;font-size:.88rem;font-weight:600;margin:14px 0 6px;color:var(--ink)}
label:first-child{margin-top:0}
input[type=text],input[type=tel],input[type=date]{width:100%;padding:14px;border:1.5px solid var(--line);border-radius:12px;font:400 1rem 'Cairo',sans-serif;background:#fff;color:var(--ink);outline:none}
input:focus{border-color:var(--gold)}
.opts{display:grid;gap:10px}
.opt{display:flex;justify-content:space-between;align-items:center;gap:10px;padding:14px 16px;border:1.5px solid var(--line);border-radius:14px;background:#fff;cursor:pointer;font:600 .95rem 'Cairo',sans-serif;color:var(--ink);text-align:start;width:100%}
.opt small{font-weight:400;color:var(--muted);font-size:.78rem;display:block}
.opt .pr{color:var(--gold);font-weight:700;white-space:nowrap}
.opt.on{border-color:var(--ink);background:var(--soft)}
.chips{display:flex;flex-wrap:wrap;gap:8px}
.chip{padding:10px 16px;border:1.5px solid var(--line);border-radius:999px;background:#fff;font:600 .92rem 'Cairo',sans-serif;color:var(--ink);cursor:pointer}
.chip.on{background:var(--ink);border-color:var(--ink);color:#fff}
.days{display:flex;gap:8px;overflow-x:auto;padding-bottom:6px;scrollbar-width:none}.days::-webkit-scrollbar{display:none}
.day{flex:0 0 auto;min-width:64px;padding:10px 8px;text-align:center;border:1.5px solid var(--line);border-radius:14px;background:#fff;cursor:pointer;font-family:'Cairo',sans-serif;color:var(--ink)}
.day b{display:block;font-size:1.15rem;line-height:1.2}.day span{font-size:.72rem;color:var(--muted)}
.day.on{background:var(--ink);border-color:var(--ink);color:#fff}.day.on span{color:#d6e2de}
.slots{display:grid;grid-template-columns:repeat(3,1fr);gap:9px}
.slot{padding:12px 4px;border:1.5px solid var(--line);border-radius:12px;background:#fff;font:600 .95rem 'Cairo',sans-serif;color:var(--ink);cursor:pointer}
.slot.on{background:var(--ink);border-color:var(--ink);color:#fff}
.hint{color:var(--muted);font-size:.85rem;padding:6px 0}
.dep{background:var(--tint);border-radius:14px;padding:16px;font-size:.9rem}
.dep .big{font-size:1.7rem;font-weight:700;color:var(--ink);line-height:1.2}
.dep .acct{display:flex;flex-direction:column;align-items:stretch;gap:10px;background:#fff;border-radius:10px;padding:10px 12px;margin:10px 0;font-weight:700;direction:ltr}
.dep .acct span{word-break:break-all;overflow-wrap:anywhere;font-size:.95rem;line-height:1.5}.dep .acct .copy,.dep .acct .openlink{display:block;width:100%;box-sizing:border-box;text-align:center;padding:11px;border-radius:10px;font-weight:700;font-size:.95rem;font-family:inherit;text-decoration:none;cursor:pointer}.dep .acct .copy{border:1.5px solid #12363a;background:#fff;color:#12363a}.dep .acct .openlink{border:none;background:#12363a;color:#fff}
.dep .copy{border:none;background:var(--ink);color:#fff;border-radius:8px;padding:6px 12px;font:600 .78rem 'Cairo',sans-serif;cursor:pointer}
.up{display:block;border:2px dashed #cfd6d1;border-radius:14px;padding:18px;text-align:center;color:var(--muted);font-size:.92rem;cursor:pointer;background:#fcfdfc}
.up input{display:none}#prev{max-width:100%;max-height:230px;border-radius:10px;margin-top:10px;display:none}
button.go{width:100%;margin-top:6px;padding:16px;border:0;border-radius:14px;background:var(--ink);color:#fff;font:700 1.05rem 'Cairo',sans-serif;cursor:pointer}
button.go:disabled{opacity:.5}
.err{color:#b3261e;font-size:.88rem;min-height:1.3em;margin:8px 0 0}
.hp{position:absolute;top:0;left:0;width:1px;height:1px;overflow:hidden;opacity:0;pointer-events:none}
.ok{text-align:center}.ok .check{width:64px;height:64px;border-radius:50%;background:#e4f4ea;color:#1b7a4a;display:flex;align-items:center;justify-content:center;font-size:2rem;margin:6px auto 10px}
.ok h1{color:#1b7a4a}.sum{background:var(--soft);border-radius:14px;padding:14px;margin:14px 0;font-weight:600}
.where{background:#fff;border-radius:14px;padding:14px;font-size:.88rem;text-align:start;box-shadow:0 2px 14px rgba(18,54,58,.06)}
a{color:var(--gold);font-weight:600}

/* ---- Calm Ivory look ---- */
:root{--ink:#1c2a28;--muted:#566562;--gold:#8a5f1e;--bg:#f6f4ee;--line:#e1ddd1;--soft:#e3efec;--tint:#fbefd9;--g:#1f5c56}
html{font-size:17px}
body{background:var(--bg)}
.wrap{padding:20px 20px}
.lang{height:44px;padding:0 18px;border-radius:22px}
.logo{width:auto;max-width:150px;max-height:64px;object-fit:contain;margin:10px auto 6px}
h1{font-size:1.7rem;font-weight:800;margin:10px 0 4px}
.sub{font-size:.95rem;margin-bottom:20px}
.steps{gap:6px;margin:0 0 20px}
.dot{width:46px;height:6px;border-radius:6px;background:#dad5c7}.dot.on{background:var(--g)}
.card{border-radius:24px;padding:20px;box-shadow:0 1px 2px rgba(28,42,40,.06);margin-bottom:14px}
.card h2{font-size:1.05rem;font-weight:800;margin:0 0 12px}
label{font-weight:700}
input[type=text],input[type=tel],input[type=date]{height:52px;padding:0 16px;border-radius:14px;border:1.5px solid var(--line);background:#fbfaf6}
input:focus{border-color:var(--g);background:#fff;box-shadow:0 0 0 4px rgba(31,92,86,.12)}
.opt{border-radius:16px;padding:14px 16px}
.opt.on{border-color:var(--g);background:var(--soft)}
.opt .pr{color:var(--gold);font-weight:800}
.chip{min-height:44px;padding:0 18px;border-radius:22px;border:1.5px solid var(--line)}
.chip.on{background:var(--soft);border-color:var(--g);color:#164640}
.day{border-radius:16px;min-width:62px}
.day.on{background:var(--g);border-color:var(--g)}
.slot{min-height:46px;border-radius:14px}
.slot.on{background:var(--g);border-color:var(--g)}
.dep{background:var(--tint);border-radius:18px}
.dep .big{color:#4a3208}
.up{border-radius:18px;border-color:#cfc9b8;background:#fcfbf7;padding:22px 16px}
button.go{height:56px;padding:0;border-radius:18px;background:var(--g);font-size:1.1rem}
.sum{background:var(--soft)}
.ok .check{background:#e3efec;color:#1f5c56}.ok h1{color:#1f5c56}
a{color:var(--gold)}
</style></head><body><div class="wrap" id="app">
<div class="top"><span></span><button type="button" class="lang" id="langBtn">EN</button></div>
<img class="logo" src="/clinic-logo.png" alt="Empower">
<h1 id="title"></h1><div class="sub" id="sub"></div>
<div class="steps"><i class="dot on" id="d1"></i><i class="dot" id="d2"></i><i class="dot" id="d3"></i></div>

<div id="step1" style="display:none"><div class="card">
<input class="hp" id="website" tabindex="-1" autocomplete="off">
<label id="lName"></label><input type="text" id="name" autocomplete="name">
<label id="lPhone"></label><input type="tel" id="phone" inputmode="tel" autocomplete="tel" dir="ltr" style="text-align:start">
<label id="lGender"></label><div class="chips" id="genderBox"><button type="button" class="chip" data-g="male" id="gMale"></button><button type="button" class="chip" data-g="female" id="gFemale"></button></div>
<div class="err" id="err1"></div></div>
<button class="go" id="next"></button></div>

<div id="form" style="display:none">
<div class="card"><h2 id="hType"></h2><div class="opts" id="types"></div></div>
<div class="card"><h2 id="hDoc"></h2><div class="chips" id="docs"></div>
<label id="lDate" style="display:none"></label><div class="days" id="days" style="display:none"></div>
<label id="lOther" style="display:none"></label><input type="date" id="date" style="display:none">
<label id="lTime" style="margin-top:18px"></label><div id="avail"></div><div class="slots" id="slots" style="display:none"></div></div>
<div class="card"><h2 id="hPay"></h2><div class="dep" id="depBox"></div>
<div id="shotWrap" style="margin-top:14px"><label class="up"><span id="upTxt"></span><input type="file" id="shot" accept="image/*"><img id="prev" alt=""></label></div></div>
<div class="err" id="err"></div>
<button class="go" id="go"></button></div>
</div>
<script>
var gender='',cfg=null,chosenTime='',chosenType='',chosenDoc='',shotData=null,shotType='',lang='ar';
try{lang=localStorage.getItem('bl')||((navigator.language||'').toLowerCase().indexOf('en')===0?'en':'ar')}catch(e){}
var T={
 /*docs*/
 en:{title:'Book an appointment',sub0:'Loading…',pickDay:'Choose a day to see the times.',subClosed:'Online booking is not open right now. Please contact the clinic on WhatsApp.',sub1:'Enter your details to start.',sub2:'Choose your visit, doctor and time.',lName:'Full name',lPhone:'Phone number (WhatsApp)',lGender:'Gender',gMale:'Male',gFemale:'Female',eGender:'Please choose your gender.',noDocs:'No doctors are available for this visit type.',next:'Continue',hType:'1. Visit type',hDoc:'2. Doctor & time',lDate:'Day',lOther:'Or pick another date',lTime:'Available times',hPay:'3. Deposit to confirm',go:'Confirm booking',booking:'Booking…',pickDoc:'Choose a doctor and a day to see times.',loading:'Loading…',noTimes:'No available times that day. Try another day.',timesFail:'Could not load times.',
  dep1:'Deposit',dep2:'half of the fee ({p} EGP). It is non-refundable and is deducted from your fee at the clinic.',dep3:'Transfer by InstaPay to:',copy:'Copy',openpay:'Open InstaPay link',copied:'Copied ✓',dep4:'Then upload the transfer screenshot below.',dep5:'Have an active package with us? Skip the screenshot — no deposit needed.',up:'Tap to upload the transfer screenshot',upDone:'Tap to change the screenshot',
  eName:'Please enter your full name.',ePhone:'Please enter a valid phone number.',eDoc:'Please choose a doctor.',eTime:'Please choose a day and a time.',eImg:'Please choose an image file.',eConn:'Connection problem. Please try again.',eNA:'Booking is not available right now.',
  done:'Your booking is confirmed',pkg:'Your active package covers this visit.',depRec:'Deposit received: {d} EGP (non-refundable, deducted from your fee).',addr:'__ADDR_EN__',map:'Open the location on the map',arrive:'Please arrive 5 minutes early. To change the time, contact the clinic on WhatsApp at least 5 hours before.',dr:'Dr. ',egp:'EGP',at:'at',other:'العربية'},
 ar:{title:'احجز ميعادك',sub0:'جاري التحميل…',pickDay:'اختار اليوم عشان تشوف المواعيد.',subClosed:'الحجز الأونلاين مقفول دلوقتي. من فضلك كلّم العيادة على واتساب.',sub1:'اكتب بياناتك عشان تبدأ.',sub2:'اختار نوع الزيارة والدكتور والميعاد.',lName:'الاسم بالكامل',lPhone:'رقم التليفون (واتساب)',lGender:'النوع',gMale:'ذكر',gFemale:'أنثى',eGender:'من فضلك اختار النوع.',noDocs:'مفيش دكاترة متاحين لنوع الزيارة ده.',next:'متابعة',hType:'١. نوع الزيارة',hDoc:'٢. الدكتور والميعاد',lDate:'اليوم',lOther:'أو اختار تاريخ تاني',lTime:'المواعيد المتاحة',hPay:'٣. العربون لتأكيد الحجز',go:'تأكيد الحجز',booking:'جاري الحجز…',pickDoc:'اختار الدكتور واليوم عشان تشوف المواعيد.',loading:'جاري التحميل…',noTimes:'مفيش مواعيد متاحة اليوم ده. جرّب يوم تاني.',timesFail:'مقدرناش نحمّل المواعيد.',
  dep1:'العربون',dep2:'نص السعر ({p} جنيه). العربون غير مسترد ويتخصم من الحساب في العيادة.',dep3:'حوّل بـ InstaPay على:',openpay:'افتح لينك InstaPay',copy:'نسخ',copied:'تم النسخ ✓',dep4:'وبعدين ارفع صورة التحويل تحت.',dep5:'عندك باكدج شغال معانا؟ سيب صورة التحويل فاضية، مش محتاج عربون.',up:'اضغط لرفع صورة التحويل',upDone:'اضغط لتغيير الصورة',
  eName:'من فضلك اكتب اسمك بالكامل.',ePhone:'من فضلك اكتب رقم تليفون صحيح.',eDoc:'من فضلك اختار الدكتور.',eTime:'من فضلك اختار اليوم والميعاد.',eImg:'من فضلك اختار ملف صورة.',eConn:'فيه مشكلة في الاتصال. جرّب تاني.',eNA:'الحجز مش متاح دلوقتي.',
  done:'تم تأكيد حجزك',pkg:'الباكدج بتاعك بيغطي الزيارة دي.',depRec:'تم استلام العربون: {d} جنيه (غير مسترد ويتخصم من الحساب).',addr:'__ADDR_AR__',map:'افتح الموقع على الخريطة',arrive:'من فضلك تعالى قبل الميعاد بـ 5 دقايق. لو عايز تغيّر الميعاد كلّم العيادة على واتساب قبلها بـ 5 ساعات على الأقل.',dr:'Dr. ',egp:'جنيه',at:'الساعة',other:'EN'}
};
var SRV={'Booking is not available right now.':['eNA'],'Please enter your full name and a valid phone number.':['eName'],
 'Sorry, that time is no longer available. Please pick another one.':'عذراً، الميعاد ده اتحجز. اختار ميعاد تاني.',
 'Sorry, someone just took that time. Please pick another one. (Your screenshot was not used.)':'عذراً، حد حجز الميعاد ده دلوقتي. اختار ميعاد تاني. (صورة التحويل ماتستخدمتش.)',
 'Please upload the InstaPay transfer screenshot to confirm your booking.':'من فضلك ارفع صورة تحويل InstaPay عشان نأكد الحجز.',
 'The screenshot is not valid (max 4 MB).':'الصورة مش صالحة (الحد الأقصى 4 ميجا).',
 'Please choose a visit type and a doctor.':'من فضلك اختار نوع الزيارة والدكتور.',
 'Too many attempts. Please try again later.':'محاولات كتير. جرّب تاني بعد شوية.',
 'Too many requests. Please wait a moment.':'طلبات كتير. استنى شوية.',
 'Something went wrong. Please try again.':'حصل خطأ. جرّب تاني.',
 'Could not save your booking. Please try again.':'مقدرناش نسجل الحجز. جرّب تاني.',
 'Could not save the screenshot. Please try again.':'مقدرناش نحفظ الصورة. جرّب تاني.',
 'Online booking is closed right now.':'الحجز الأونلاين مقفول دلوقتي.',
 'Please choose your gender.':'من فضلك اختار النوع.',
 'This doctor is not available for your booking. Please choose another doctor.':'الدكتور ده مش متاح لحجزك. اختار دكتور تاني.',
 'This doctor does not take check-ups. Please choose another doctor.':'الدكتور ده مش بياخد كشوفات. اختار دكتور تاني.'};
function $(i){return document.getElementById(i)}
function dname(n){ n=String(n||'').replace(/^\s*(dr\.?|doctor|د\.?|دكتور|دكتورة)\s+/i,'').replace(/^\s*(dr\.?)\s+/i,'').trim(); n=n.replace(/\S+/g,function(w){ return w.charAt(0).toUpperCase()+w.slice(1).toLowerCase(); }); return 'Dr. '+n; }
function t(k,r){var s=(T[lang]||T.en)[k]; if(s===undefined)s=T.en[k]||''; if(r){for(var x in r)s=s.replace('{'+x+'}',r[x])} return s}
function esc(s){return String(s).replace(/[&<>"]/g,function(c){return{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]})}
function srv(m){ if(lang==='en')return m; var v=SRV[m]; if(!v)return m; return typeof v==='string'?v:t(v[0]); }
function num(n){ return lang==='ar'?String(n).replace(/\d/g,function(d){return '٠١٢٣٤٥٦٧٨٩'[d]}):String(n); }
function fmtTime(hm){ var p=hm.split(':'),h=+p[0],m=p[1],ap=h>=12?(lang==='ar'?'م':'PM'):(lang==='ar'?'ص':'AM'); h=h%12; if(h===0)h=12; return num(h+':'+m)+' '+ap; }
function ymd(d){var m=d.getMonth()+1,dd=d.getDate();return d.getFullYear()+'-'+(m<10?'0':'')+m+'-'+(dd<10?'0':'')+dd}
function typeObj(){return cfg.types.filter(function(x){return x.key===chosenType})[0]}
function setStep(n){ for(var i=1;i<=3;i++)$('d'+i).className='dot'+(i<=n?' on':'') }
function applyLang(){
  document.documentElement.lang=lang; document.documentElement.dir=lang==='ar'?'rtl':'ltr';
  $('langBtn').textContent=t('other'); $('title').textContent=t('title');
  $('lName').textContent=t('lName'); $('lPhone').textContent=t('lPhone'); $('lGender').textContent=t('lGender'); $('gMale').textContent=t('gMale'); $('gFemale').textContent=t('gFemale'); $('next').textContent=t('next');
  $('hType').textContent=t('hType'); $('hDoc').textContent=t('hDoc'); $('lDate').textContent=t('lDate'); $('lOther').textContent=t('lOther'); $('lTime').textContent=t('lTime'); $('hPay').textContent=t('hPay');
  $('go').textContent=$('go').disabled?t('booking'):t('go');
  $('upTxt').textContent=shotData?t('upDone'):t('up');
  if(!cfg){ $('sub').textContent=t('sub0'); } else if(!cfg.enabled){ $('sub').textContent=t('subClosed'); } else if(cfg.locked){ $('sub').textContent=t('sub1'); } else { $('sub').textContent=t('sub2'); }
  if(cfg&&!cfg.locked&&cfg.enabled){ renderTypes(); renderDocs(); renderDays(); depText(); if(chosenDoc) loadSlots(); else $('avail').innerHTML='<div class="hint">'+t('pickDoc')+'</div>'; }
}
$('langBtn').onclick=function(){ lang=lang==='ar'?'en':'ar'; try{localStorage.setItem('bl',lang)}catch(e){} applyLang(); };
function tLabel(x){ if(lang==='ar'){ if(x.label_ar) return x.label_ar; var l=x.label||''; if(/check-?up/i.test(l)) return 'Check-up — كشف (جلسة تقييمية)'; if(/(1|one)\s*body\s*part/i.test(l)) return 'جلسة — على مكان واحد (عضو واحد)'; if(/(2|two)\s*body\s*parts?/i.test(l)) return 'جلسة — على أكتر من مكان (عضوين)'; } return l||x.label; }
function renderTypes(){ $('types').innerHTML=cfg.types.map(function(x){ return '<button type="button" class="opt'+(x.key===chosenType?' on':'')+'" data-k="'+esc(x.key)+'"><span>'+esc(tLabel(x))+'</span><span class="pr">'+num(x.price)+' '+t('egp')+'</span></button>'; }).join('');
  Array.prototype.forEach.call($('types').querySelectorAll('.opt'),function(b){ b.onclick=function(){ chosenType=b.dataset.k; renderTypes(); renderDocs(); depText(); }; }); }
function docList(){ var x=typeObj(); return cfg.doctors.filter(function(d){ return !(x&&x.visit_type==='checkup'&&d.checkups===false); }); }
function renderDocs(){ var L=docList(); if(chosenDoc&&!L.some(function(d){return d.id===chosenDoc})){ chosenDoc=''; loadSlots(); }
  if(!L.length){ $('docs').innerHTML='<div class="hint">'+t('noDocs')+'</div>'; return; }
  $('docs').innerHTML=L.map(function(d){ return '<button type="button" class="chip'+(d.id===chosenDoc?' on':'')+'" data-d="'+esc(d.id)+'">'+esc(dname(d.name))+'</button>'; }).join('');
  Array.prototype.forEach.call($('docs').querySelectorAll('.chip'),function(b){ b.onclick=function(){ chosenDoc=b.dataset.d; renderDocs(); loadSlots(); }; }); }
function renderDays(){ var n=Math.min(cfg.max_days_ahead,14),h='',now=new Date(),cur=$('date').value;
  for(var i=0;i<n;i++){ var d=new Date(now.getFullYear(),now.getMonth(),now.getDate()+i); if(d.getDay()===5)continue; var key=ymd(d);
    h+='<button type="button" class="day'+(key===cur?' on':'')+'" data-y="'+key+'"><span>'+d.toLocaleDateString(lang==='ar'?'ar-EG':'en-GB',{weekday:'short'})+'</span><b>'+num(d.getDate())+'</b><span>'+d.toLocaleDateString(lang==='ar'?'ar-EG':'en-GB',{month:'short'})+'</span></button>'; }
  $('days').innerHTML=h; Array.prototype.forEach.call($('days').querySelectorAll('.day'),function(b){ b.onclick=function(){ $('date').value=b.dataset.y; renderDays(); loadSlots(); }; }); }
function depText(){ var x=typeObj(); if(cfg&&cfg.pkg){ $('depBox').innerHTML='<div class="big" style="font-size:1rem">✅ '+t('pkg')+'</div>'; var sw=$('shotWrap'); if(sw)sw.style.display='none'; return; } if(!x){ $('depBox').innerHTML='<div class="hint">'+t('hType')+'</div>'; return; }
  $('depBox').innerHTML='<div>'+t('dep1')+'</div><div class="big">'+num(x.deposit)+' '+t('egp')+'</div><div>'+t('dep2',{p:num(x.price)})+'</div>'+(cfg.instapay?'<div style="margin-top:10px">'+t('dep3')+'</div><div class="acct"><span>'+esc(cfg.instapay)+'</span>'+(/^https?:\/\//i.test(cfg.instapay)?'<a class="openlink" href="'+esc(cfg.instapay)+'" target="_blank" rel="noopener">'+t('openpay')+'</a>':'')+'<button type="button" class="copy" id="cpy">'+t('copy')+'</button></div>':'')+(cfg.note?'<div>'+esc(cfg.note)+'</div>':'')+'<div style="margin-top:8px">'+t('dep4')+'</div><div class="hint" style="margin-top:6px">'+t('dep5')+'</div>';
  var c=$('cpy'); if(c)c.onclick=function(){ var done=function(){c.textContent=t('copied')}; try{ navigator.clipboard.writeText(cfg.instapay).then(done,function(){ var ta=document.createElement('textarea'); ta.value=cfg.instapay; document.body.appendChild(ta); ta.select(); try{document.execCommand('copy');done()}catch(e){} ta.remove(); }); }catch(e){ var ta=document.createElement('textarea'); ta.value=cfg.instapay; document.body.appendChild(ta); ta.select(); try{document.execCommand('copy');done()}catch(x){} ta.remove(); } }; }
function loadSlots(){ chosenTime=''; $('date').value='';
  if(!chosenDoc){ $('avail').innerHTML='<div class="hint">'+t('pickDoc')+'</div>'; return; }
  var my=chosenDoc; $('avail').innerHTML='<div class="hint">'+t('loading')+'</div>';
  fetch('/api/book/availability?doctor='+encodeURIComponent(chosenDoc)+'&gender='+gender+'&phone='+encodeURIComponent($('phone').value)).then(function(r){return r.json()}).then(function(j){
    if(my!==chosenDoc) return;
    if(!j.days||!j.days.length){ $('avail').innerHTML='<div class="hint">'+t('noTimes')+'</div>'; return; }
    var D=j.days; var cur='';
    function fl(d){ var dt=new Date(d.date+'T12:00:00'),L=lang==='ar'?'ar-EG':'en-GB'; return '<button type="button" class="day'+(d.date===cur?' on':'')+'" data-y="'+d.date+'"><span>'+dt.toLocaleDateString(L,{weekday:'short'})+'</span><b>'+num(dt.getDate())+'</b><span>'+dt.toLocaleDateString(L,{month:'short'})+'</span></button>'; }
    function draw(){ var sel=D.filter(function(d){return d.date===cur})[0];
      $('avail').innerHTML='<div class="days">'+D.map(fl).join('')+'</div><div class="slots" style="margin-top:14px">'+(sel?sel.times.map(function(x){return '<button type="button" class="slot'+(x===chosenTime?' on':'')+'" data-t="'+x+'">'+fmtTime(x)+'</button>'}).join(''):'<div class="hint" style="grid-column:1/-1">'+t('pickDay')+'</div>')+'</div>';
      Array.prototype.forEach.call($('avail').querySelectorAll('.day'),function(b){ b.onclick=function(){ cur=b.dataset.y; $('date').value=cur; chosenTime=''; draw(); }; });
      Array.prototype.forEach.call($('avail').querySelectorAll('.slot'),function(b){ b.onclick=function(){ chosenTime=b.dataset.t; draw(); }; }); }
    draw();
  }).catch(function(){ $('avail').innerHTML='<div class="hint">'+t('timesFail')+'</div>'; }); }
function init(){ applyLang(); fetch('/api/book/config').then(function(r){return r.json()}).then(function(c){ cfg=c; if(!c.enabled){ applyLang(); return; } $('step1').style.display='block'; applyLang(); }).catch(function(){ $('sub').textContent=t('eNA'); }); }
$('next').onclick=function(){ $('err1').textContent='';
  if($('name').value.trim().length<3) return $('err1').textContent=t('eName');
  if($('phone').value.replace(/\D/g,'').length<10) return $('err1').textContent=t('ePhone');
  if(!gender) return $('err1').textContent=t('eGender');
  $('next').disabled=true;
  fetch('/api/book/config?name='+encodeURIComponent($('name').value.trim())+'&gender='+gender+'&phone='+encodeURIComponent($('phone').value)).then(function(r){return r.json()}).then(function(c){
    if(!c.enabled||c.locked){ $('err1').textContent=t('eNA'); $('next').disabled=false; return; }
    cfg=c; chosenType=c.types.length===1?c.types[0].key:''; $('step1').style.display='none'; $('form').style.display='block'; setStep(2); applyLang(); window.scrollTo(0,0);
  }).catch(function(){ $('err1').textContent=t('eConn'); $('next').disabled=false; }); };
$('date').onchange=function(){ renderDays(); loadSlots(); };
Array.prototype.forEach.call(document.querySelectorAll('#genderBox .chip'),function(b){ b.onclick=function(){ gender=b.dataset.g; Array.prototype.forEach.call(document.querySelectorAll('#genderBox .chip'),function(x){ x.classList.toggle('on',x===b); }); }; });
$('shot').onchange=function(){ var f=this.files[0]; shotData=null; $('prev').style.display='none'; $('upTxt').textContent=t('up'); if(!f)return;
  var img=new Image(),url=URL.createObjectURL(f); img.onload=function(){ var s=Math.min(1,1400/Math.max(img.width,img.height)),cv=document.createElement('canvas'); cv.width=Math.round(img.width*s); cv.height=Math.round(img.height*s); cv.getContext('2d').drawImage(img,0,0,cv.width,cv.height);
    var u=cv.toDataURL('image/jpeg',0.82); shotData=u.split(',')[1]; shotType='image/jpeg'; $('prev').src=u; $('prev').style.display='block'; $('upTxt').textContent=t('upDone'); URL.revokeObjectURL(url); setStep(3); };
  img.onerror=function(){ $('err').textContent=t('eImg'); }; img.src=url; };
$('go').onclick=function(){ $('err').textContent='';
  if(!chosenType) return $('err').textContent=srv('Please choose a visit type and a doctor.');
  if(!chosenDoc) return $('err').textContent=t('eDoc');
  if(!$('date').value||!chosenTime) return $('err').textContent=t('eTime');
  $('go').disabled=true; $('go').textContent=t('booking');
  fetch('/api/book',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:$('name').value,gender:gender,phone:$('phone').value,type:chosenType,doctor:chosenDoc,date:$('date').value,time:chosenTime,shotBase64:shotData,shotType:shotType,website:$('website').value})})
  .then(function(r){return r.json().then(function(j){return{ok:r.ok,j:j}})}).then(function(x){
    if(!x.ok){ $('err').textContent=srv(x.j.error||'Something went wrong. Please try again.'); $('go').disabled=false; $('go').textContent=t('go'); if(/no longer|just took/.test(x.j.error||''))loadSlots(); return; }
    var j=x.j; var dd=new Date(j.date+'T12:00:00'); var dtxt=dd.toLocaleDateString(lang==='ar'?'ar-EG':'en-GB',{weekday:'long',day:'numeric',month:'long'});
    $('app').innerHTML='<div class="top"><span></span><button type="button" class="lang" id="langBtn2">'+t('other')+'</button></div><img class="logo" src="/clinic-logo.png" alt="Empower"><div class="card ok"><div class="check">✓</div><h1>'+t('done')+'</h1><div class="sum">'+esc(dname(j.doctor))+'<br>'+esc(dtxt)+' '+t('at')+' '+fmtTime(j.time)+'<br>'+esc(tLabel(typeObj()||{label:j.label}))+'</div><div class="hint">'+(j.package?t('pkg'):t('depRec',{d:num(j.deposit)}))+'</div></div><div class="where">📍 '+t('addr')+'<br><a href="__MAP_URL__">'+t('map')+'</a><br><br>'+t('arrive')+'</div>';
    $('langBtn2').onclick=function(){ lang=lang==='ar'?'en':'ar'; try{localStorage.setItem('bl',lang)}catch(e){} location.reload(); };
  }).catch(function(){ $('err').textContent=t('eConn'); $('go').disabled=false; $('go').textContent=t('go'); }); };
init();
</script></body></html>
`;
app.get('/b', (req, res) => { res.redirect(302, '/book'); });

app.get('/api/booking/stats', requireOwnerOrSecretary, async (req, res) => {
  try {
    const get = async (path) => { const r = await fetch(`${SUPABASE_URL}/rest/v1/${path}`, { headers: bookHeaders() }); const j = await r.json(); return Array.isArray(j) ? j : []; };
    const [opens, leads, deps] = await Promise.all([
      get('login_log?event=eq.page&detail=eq.book&select=created_at&order=created_at.desc&limit=20000'),
      get('booking_leads?select=created_at&order=created_at.desc&limit=20000'),
      get('booking_deposits?select=created_at&order=created_at.desc&limit=20000'),
    ]);
    const now = Date.now(), cairoDay = cairoTodayYmd();
    const sameCairoDay = (iso) => new Date(iso).toLocaleDateString('en-CA', { timeZone: 'Africa/Cairo' }) === cairoDay;
    const within = (iso, days) => now - new Date(iso).getTime() < days * 86400000;
    const pack = (rows) => ({ today: rows.filter(r => sameCairoDay(r.created_at)).length, d7: rows.filter(r => within(r.created_at, 7)).length, d30: rows.filter(r => within(r.created_at, 30)).length, total: rows.length });
    res.json({ opens: pack(opens), started: pack(leads), booked: pack(deps) });
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

app.get('/book', async (req, res) => {
  logActivity(req, 'page', null, 'book');
  res.set({ 'Content-Type': 'text/html; charset=utf-8', 'X-Robots-Tag': 'noindex, nofollow', 'Cache-Control': 'no-store' }).send(renderClinicPage(BOOK_PAGE, await getClinicConfig()));
});

const INTAKE_PAGE = String.raw`<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>استمارة استقبال — __CLINIC_AR__</title><meta name="robots" content="noindex,nofollow"><meta name="theme-color" content="#f6f4ee">
<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin><link href="https://fonts.googleapis.com/css2?family=Cairo:wght@400;500;600;700;800&display=swap" rel="stylesheet">
<style>
  :root{ --ink:#1c2a28; --paper:#f6f4ee; --line:#e1ddd1; --g:#1f5c56; --soft:#e3efec; --muted:#566562; }
  *{box-sizing:border-box;-webkit-tap-highlight-color:transparent;}
  html{overflow-x:hidden;}
  body{ margin:0; background:var(--paper); color:var(--ink); font-family:'Cairo',-apple-system,'Segoe UI',Roboto,Arial,sans-serif; line-height:1.55; }
  .wrap{ max-width:480px; margin:0 auto; padding:22px 20px 40px; }
  .brand{ display:flex; align-items:center; gap:10px; margin-bottom:22px; }
  .badge{ width:42px; height:42px; border-radius:13px; background:var(--g); color:#f6f4ee; display:flex; align-items:center; justify-content:center; font-size:1.3rem; font-weight:800; }
  .bn{ font-size:1.05rem; font-weight:700; }
  h1{ margin:0; font-size:1.65rem; font-weight:800; letter-spacing:-0.2px; }
  .lead{ margin:6px 0 20px; font-size:.95rem; color:var(--muted); }
  .card{ background:#fff; border-radius:24px; padding:20px; box-shadow:0 1px 2px rgba(28,42,40,.06); }
  label,.lb{ display:block; font-size:.88rem; font-weight:700; margin:16px 0 8px; }
  label:first-child{ margin-top:0; }
  input, textarea{ width:100%; height:52px; padding:0 16px; border:1.5px solid var(--line); border-radius:14px; background:#fbfaf6; font-size:1rem; font-family:inherit; color:var(--ink); outline:none; }
  textarea{ height:100px; padding:14px 16px; resize:none; line-height:1.5; }
  input:focus, textarea:focus{ border-color:var(--g); background:#fff; box-shadow:0 0 0 4px rgba(31,92,86,.12); }
  .chips{ display:flex; flex-wrap:wrap; gap:8px; margin-bottom:10px; }
  .chip{ min-height:44px; padding:0 16px; border-radius:22px; border:1.5px solid var(--line); background:#fff; color:var(--ink); font-size:.92rem; font-weight:600; font-family:inherit; cursor:pointer; }
  .chip.on{ background:var(--soft); border-color:var(--g); color:#164640; font-weight:700; }
  #submitBtn{ width:100%; height:56px; margin-top:20px; border:0; border-radius:18px; background:var(--g); color:#f6f4ee; font-size:1.1rem; font-weight:700; font-family:inherit; cursor:pointer; }
  #submitBtn:disabled{ background:#a9b6b2; cursor:not-allowed; }
  #status{ margin-top:12px; font-size:.88rem; color:var(--muted); text-align:center; min-height:1.3em; }
  .priv{ text-align:center; font-size:.78rem; color:var(--muted); margin-top:14px; }
  #successBox{ display:none; text-align:center; padding:26px 6px; }
  #successBox .check{ width:68px; height:68px; border-radius:50%; background:var(--soft); color:var(--g); display:flex; align-items:center; justify-content:center; font-size:2.2rem; margin:0 auto 14px; }
</style>
</head>
<body>
<div class="wrap">
  <div class="brand"><div class="badge" id="lg">E</div><div class="bn" id="cn">__CLINIC_AR__</div></div>

  <div id="formBox">
    <h1>استمارة قبل الكشف</h1>
    <p class="lead">عشان الدكتور يكون مجهز لحالتك قبل ما توصل. بياخد دقيقة.</p>
    <div class="card">
      <label for="nameInput">الاسم بالكامل</label>
      <input type="text" id="nameInput" placeholder="مثال: محمد أحمد" autocomplete="name">

      <label for="phoneInput">رقم الموبايل</label>
      <input type="tel" id="phoneInput" dir="ltr" style="text-align:start" placeholder="01X XXXX XXXX" autocomplete="tel" inputmode="tel">

      <label for="complaintInput">إيه الشكوى الأساسية؟</label>
      <textarea id="complaintInput" placeholder="مثال: ألم في الركبة اليمين من حوالي أسبوعين"></textarea>

      <div class="lb">عرفت عن العيادة إزاي؟</div>
      <div class="chips" id="refChips">
        <button type="button" class="chip" data-v="صديق">صديق</button>
        <button type="button" class="chip" data-v="إنستجرام">إنستجرام</button>
        <button type="button" class="chip" data-v="جوجل">جوجل</button>
        <button type="button" class="chip" data-v="دكتور رشحني">دكتور رشحني</button>
      </div>
      <input type="text" id="referralInput" placeholder="أو اكتب بنفسك">

      <button type="button" id="submitBtn">إرسال</button>
      <div id="status"></div>
    </div>
    <div class="priv">بياناتك سرية ومحدش بيشوفها غير الدكتور.</div>
  </div>

  <div id="successBox" class="card">
    <div class="check">✓</div>
    <div style="font-size:1.15rem;font-weight:800;color:var(--g);">تم الإرسال بنجاح</div>
    <div style="font-size:.9rem;color:var(--muted);margin-top:6px;">شكرًا ليك، البيانات وصلت للعيادة. نشوفك قريب!</div>
  </div>
</div>

<script>
const BACKEND_URL = '';
try{ var _n=(document.getElementById('cn').textContent||'').trim(); if(_n) document.getElementById('lg').textContent=_n.charAt(0); }catch(e){}
document.querySelectorAll('#refChips .chip').forEach(function(b){
  b.addEventListener('click', function(){
    var on = b.classList.contains('on');
    document.querySelectorAll('#refChips .chip').forEach(function(x){ x.classList.remove('on'); });
    if(on){ document.getElementById('referralInput').value=''; return; }
    b.classList.add('on'); document.getElementById('referralInput').value=b.dataset.v;
  });
});
document.getElementById('referralInput').addEventListener('input', function(){
  document.querySelectorAll('#refChips .chip').forEach(function(x){ x.classList.toggle('on', x.dataset.v===document.getElementById('referralInput').value); });
});
document.getElementById('submitBtn').addEventListener('click', async () => {
  const name = document.getElementById('nameInput').value.trim();
  const phone = document.getElementById('phoneInput').value.trim();
  const complaint = document.getElementById('complaintInput').value.trim();
  const referral = document.getElementById('referralInput').value;
  const statusEl = document.getElementById('status');
  const btn = document.getElementById('submitBtn');

  if(!name || !phone){
    statusEl.textContent = 'من فضلك اكتب الاسم ورقم الموبايل.';
    statusEl.style.color = '#a33d3d';
    return;
  }

  btn.disabled = true;
  statusEl.textContent = 'جاري الإرسال…';
  statusEl.style.color = '#5b6863';

  try{
    const res = await fetch(BACKEND_URL + '/api/intake', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ patientName: name, patientPhone: phone, chiefComplaint: complaint, referralSource: referral })
    });
    if(!res.ok) throw new Error('Server error ' + res.status);
    document.getElementById('formBox').style.display = 'none';
    document.getElementById('successBox').style.display = 'block';
  }catch(e){
    console.error(e);
    statusEl.textContent = 'حصل خطأ أثناء الإرسال، حاول تاني.';
    statusEl.style.color = '#a33d3d';
    btn.disabled = false;
  }
});
</script>

</body>
</html>
`;

app.get('/intake', async (req, res) => {
  const c = await getClinicConfig();
  const nm = clinicEsc(c.name_ar || c.name);
  res.set({ 'Content-Type': 'text/html; charset=utf-8', 'X-Robots-Tag': 'noindex, nofollow', 'Cache-Control': 'no-store' }).send(INTAKE_PAGE.replace(/__CLINIC_AR__/g, nm));
});


// ---- Public links page (like Linktree) at /links ----
const LINKS_JS = String.raw`function cp(b){var n=b.getAttribute('data-n');var done=function(){var o=b.textContent;b.textContent='Copied \u2713';setTimeout(function(){b.textContent=o},1500)};function fb(){var t=document.createElement('textarea');t.value=n;document.body.appendChild(t);t.select();try{document.execCommand('copy')}catch(e){}document.body.removeChild(t);done()}if(navigator.clipboard&&navigator.clipboard.writeText){navigator.clipboard.writeText(n).then(done,fb)}else{fb()}}`;
function renderLinksPage(c) {
  const nm = clinicEsc(c.name), tag = clinicEsc(c.tagline || '');
  const btn = (label, url) => '<a class="b" href="' + clinicEsc(url) + '" target="_blank" rel="noopener">' + clinicEsc(label) + '</a>';
  const rows = [];
  rows.push(btn('Book online', '/book'));
  const tel = String(c.phone || '').replace(/[^0-9+]/g, '');
  if (tel) rows.push('<div class="b"><div>For Reservations</div><div class="ph">' + clinicEsc(String(c.phone).trim()) + '</div><div class="act"><a class="ab" href="tel:' + clinicEsc(tel) + '">Call</a><button type="button" class="ab" data-n="' + clinicEsc(String(c.phone).trim()) + '" onclick="cp(this)">Copy number</button></div></div>');
  (Array.isArray(c.links) ? c.links : []).forEach((l) => { const u = safeLinkUrl(l && l.url); if (u && l.label) rows.push(btn(l.label, u)); });
  const addr = c.address || c.address_ar || '';
  const loc = addr ? '<div class="h">&#128205; Our Location</div><a class="b loc" href="' + clinicEsc(safeLinkUrl(c.map_url) || '#') + '" target="_blank" rel="noopener">' + clinicEsc(addr) + '</a>' : '';
  return '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>' + nm + '</title>' +
    '<style>*{box-sizing:border-box}body{margin:0;background:#e9ecef;font-family:-apple-system,Segoe UI,Roboto,Arial,sans-serif;color:#111;min-height:100vh}' +
    '.w{max-width:560px;margin:0 auto;padding:36px 16px 48px;text-align:center}.logo{width:84%;max-width:340px;height:auto;display:block;margin:10px auto 22px}' +
    'h1{font-size:1.05rem;margin:0 0 26px;font-weight:600}.tag{font-size:1.15rem;margin:6px 0 30px}.b{display:block;background:#fff;border-radius:12px;padding:20px 16px;margin:0 0 14px;color:#111;text-decoration:none;font-weight:600;box-shadow:0 1px 3px rgba(0,0,0,.08)}' +
    '.ph{display:block;margin-top:6px;font-size:1.25rem;font-weight:700;letter-spacing:.5px;direction:ltr}.act{display:flex;gap:10px;margin-top:14px}.ab{flex:1;background:#eef1f4;border:0;border-radius:10px;padding:12px 8px;font:inherit;font-weight:600;color:#111;text-decoration:none;cursor:pointer;text-align:center}.b:active{transform:scale(.99)}.h{font-weight:700;margin:26px 0 12px}.loc{font-weight:500;text-align:left}</style></head><body><div class="w">' +
    '<img class="logo" src="/clinic-logo.png" alt="' + nm + '">' + (tag ? '<p class="tag">' + tag + '</p>' : '') + rows.join('') + loc + '</div><script>' + LINKS_JS + '</script></body></html>';
}
app.get(['/links', '/l'], async (req, res) => {
  logActivity(req, 'page', null, 'links');
  res.set({ 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' }).send(renderLinksPage(await getClinicConfig()));
});

// ---- Friendly payment page at /pay (opened from the InstaPay WhatsApp message) ----
app.get('/pay', async (req, res) => {
  logActivity(req, 'page', null, 'pay');
  const c = await getClinicConfig();
  const nm = clinicEsc(c.name);
  const q = (k, n) => clinicEsc(clinicText(req.query[k], n).trim());
  const who = q('n', 40).split(' ')[0];
  const amtRaw = String(req.query.a || '').trim();
  const amt = /^[0-9][0-9.,]{0,9}$/.test(amtRaw) ? clinicEsc(amtRaw) : '';
  const why = q('r', 40);
  const payUrl = safeLinkUrl(c.instapay_url);
  const handle = clinicEsc(c.instapay_handle || '');
  const tel = String(c.phone || '').replace(/[^0-9]/g, '');
  const waNum = tel.length === 11 && tel.startsWith('0') ? '2' + tel : tel;
  const addr = clinicEsc(c.address || c.address_ar || '');
  const html = '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex"><title>' + nm + '</title>' +
    '<style>*{box-sizing:border-box}body{margin:0;background:#e9ecef;font-family:-apple-system,Segoe UI,Roboto,Cairo,Arial,sans-serif;color:#111}.w{max-width:520px;margin:0 auto;padding:28px 16px 44px;text-align:center}' +
    '.logo{width:70%;max-width:280px;height:auto;display:block;margin:6px auto 18px}h1{font-size:1.35rem;margin:6px 0 4px}.sub{color:#4b5563;margin:0 0 4px;font-size:.98rem;line-height:1.5}' +
    '.card{background:#fff;border-radius:14px;padding:16px;margin:14px 0;box-shadow:0 1px 3px rgba(0,0,0,.08);text-align:left}.amt{text-align:center}.amt .n{font-size:2rem;font-weight:800;color:#1f5c56;direction:ltr}.amt .l{color:#6b7280;font-size:.85rem}' +
    '.st{display:flex;gap:12px;align-items:flex-start;margin:10px 0;line-height:1.45}.st b{flex:0 0 28px;height:28px;border-radius:50%;background:#1f5c56;color:#fff;display:flex;align-items:center;justify-content:center;font-size:.9rem}' +
    '.go{display:block;background:#1f5c56;color:#fff;text-decoration:none;font-weight:700;font-size:1.05rem;padding:16px;border-radius:12px;margin:16px 0 10px}.sec{display:block;background:#fff;color:#111;text-decoration:none;font-weight:600;padding:14px;border-radius:12px;margin:10px 0;box-shadow:0 1px 3px rgba(0,0,0,.08);border:0;width:100%;font:inherit;cursor:pointer}' +
    '.hd{direction:ltr;font-weight:700;font-size:1.1rem;margin:4px 0 10px;word-break:break-all}.ft{color:#6b7280;font-size:.82rem;margin-top:24px;line-height:1.5}</style></head><body><div class="w">' +
    '<img class="logo" src="/clinic-logo.png" alt="' + nm + '">' +
    '<h1>Hi' + (who ? ' ' + who : '') + ' &#128075;</h1><p class="sub">Thank you for choosing ' + nm + '.<br>Paying takes less than a minute.</p>' +
    '<p class="sub" dir="rtl">أهلاً بيك' + (who ? ' ' + who : '') + '، شكراً لاختيارك ' + nm + '. الدفع بياخد أقل من دقيقة.</p>' +
    (amt ? '<div class="card amt"><div class="l">Amount to pay &middot; المبلغ المطلوب</div><div class="n">' + amt + ' EGP</div>' + (why ? '<div class="l">' + why + '</div>' : '') + '</div>' : '') +
    '<div class="card"><div class="st"><b>1</b><div>Tap <b style="display:inline;background:none;color:inherit;width:auto;height:auto">Pay with InstaPay</b> below. Your InstaPay app will open.</div></div>' +
    '<div class="st"><b>2</b><div>Check the details and send the payment' + (amt ? ' (' + amt + ' EGP)' : '') + '.</div></div>' +
    '<div class="st"><b>3</b><div>Send us a screenshot of the receipt on WhatsApp so we can confirm it.</div></div></div>' +
    (payUrl ? '<a class="go" href="' + clinicEsc(payUrl) + '">Pay with InstaPay</a>' : '') +
    (handle ? '<div class="card" style="text-align:center"><div class="l" style="color:#6b7280;font-size:.85rem">Or send to this InstaPay address</div><div class="hd">' + handle + '</div><button type="button" class="sec" style="box-shadow:none;background:#eef1f4;margin:0" data-n="' + handle + '" onclick="cp(this)">Copy address</button></div>' : '') +
    (waNum ? '<a class="sec" href="https://wa.me/' + waNum + '" target="_blank" rel="noopener">Send the receipt on WhatsApp</a>' : '') +
    '<div class="ft">' + nm + (addr ? '<br>' + addr : '') + '</div></div><script>' + LINKS_JS + '</script></body></html>';
  res.set({ 'Content-Type': 'text/html; charset=utf-8', 'X-Robots-Tag': 'noindex, nofollow', 'Cache-Control': 'no-store' }).send(html);
});


// ---- HR: leave decisions (owner only) ----
// "unavailable" days from the calendar count as leave automatically; this table stores what the owner decides
// for scheduled days with no patients: kind = leave | worked | closed, and for days off worked: overtime | no_overtime (+ optional hours).
app.get('/api/hr/leaves', requireOwnerDoctor, async (req, res) => {
  try {
    const { start, end } = req.query;
    let url = `${SUPABASE_URL}/rest/v1/doctor_leaves?order=date.asc&limit=5000`;
    if (start && end) url += `&date=gte.${encodeURIComponent(start)}&date=lte.${encodeURIComponent(end)}`;
    const r = await fetch(url, { headers: bookHeaders() });
    res.status(r.status).type('application/json').send(await r.text());
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});
app.post('/api/hr/leaves', requireOwnerDoctor, async (req, res) => {
  const b = req.body || {};
  const name = clinicText(b.doctorName, 80).trim(), date = String(b.date || '');
  const kind = ['leave', 'worked', 'closed', 'overtime', 'no_overtime'].includes(b.kind) ? b.kind : '';
  const hoursNum = parseFloat(b.hours); const hours = Number.isFinite(hoursNum) && hoursNum > 0 && hoursNum <= 24 ? hoursNum : null;
  if (!name || !/^\d{4}-\d{2}-\d{2}$/.test(date) || !kind) return res.status(400).json({ error: 'Missing doctor, date or kind.' });
  try {
    const r = await fetch(`${SUPABASE_URL}/rest/v1/doctor_leaves?on_conflict=doctor_name,date`, { method: 'POST', headers: { ...bookHeaders(), 'Content-Type': 'application/json', Prefer: 'return=representation,resolution=merge-duplicates' }, body: JSON.stringify({ doctor_name: name, date, kind, hours, note: clinicText(b.note, 200).trim() || null, created_by: req.doctor.name || req.doctor.email }) });
    const j = await r.json();
    if (!r.ok) throw new Error(JSON.stringify(j));
    res.json(Array.isArray(j) ? j[0] : j);
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});
app.delete('/api/hr/leaves/:id', requireOwnerDoctor, async (req, res) => {
  try {
    await fetch(`${SUPABASE_URL}/rest/v1/doctor_leaves?id=eq.${encodeURIComponent(req.params.id)}`, { method: 'DELETE', headers: bookHeaders() });
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

// ---- Attendance (check in / check out): secretaries tap in and out; the owner reviews it in HR ----
const attendanceWho = (req) => ({ email: String(req.doctor.email || '').toLowerCase(), name: String(req.doctor.name || req.doctor.email || '').slice(0, 80) });
app.get('/api/attendance/me', requireApprovedAny, async (req, res) => {
  try {
    const w = attendanceWho(req), day = cairoTodayYmd();
    const r = await fetch(`${SUPABASE_URL}/rest/v1/attendance?person_email=eq.${encodeURIComponent(w.email)}&day=eq.${day}&order=check_in.asc`, { headers: bookHeaders() });
    const rows = await r.json();
    res.set('Cache-Control', 'no-store').json({ day, rows: Array.isArray(rows) ? rows : [] });
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});
app.post('/api/attendance/in', requireApprovedAny, async (req, res) => {
  try {
    const w = attendanceWho(req), day = cairoTodayYmd();
    const h = { ...bookHeaders(), 'Content-Type': 'application/json', Prefer: 'return=representation' };
    const open = await (await fetch(`${SUPABASE_URL}/rest/v1/attendance?person_email=eq.${encodeURIComponent(w.email)}&day=eq.${day}&check_out=is.null&limit=1`, { headers: bookHeaders() })).json();
    if (Array.isArray(open) && open.length) return res.json(open[0]);
    const r = await fetch(`${SUPABASE_URL}/rest/v1/attendance`, { method: 'POST', headers: h, body: JSON.stringify({ person_email: w.email, person_name: w.name, day, check_in: new Date().toISOString() }) });
    const j = await r.json(); if (!r.ok) throw new Error(JSON.stringify(j));
    res.json(Array.isArray(j) ? j[0] : j);
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});
app.post('/api/attendance/out', requireApprovedAny, async (req, res) => {
  try {
    const w = attendanceWho(req), day = cairoTodayYmd();
    const open = await (await fetch(`${SUPABASE_URL}/rest/v1/attendance?person_email=eq.${encodeURIComponent(w.email)}&day=eq.${day}&check_out=is.null&order=check_in.desc&limit=1`, { headers: bookHeaders() })).json();
    if (!Array.isArray(open) || !open.length) return res.status(400).json({ error: 'You are not checked in.' });
    const r = await fetch(`${SUPABASE_URL}/rest/v1/attendance?id=eq.${encodeURIComponent(open[0].id)}`, { method: 'PATCH', headers: { ...bookHeaders(), 'Content-Type': 'application/json', Prefer: 'return=representation' }, body: JSON.stringify({ check_out: new Date().toISOString() }) });
    const j = await r.json(); if (!r.ok) throw new Error(JSON.stringify(j));
    res.json(Array.isArray(j) ? j[0] : j);
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});
app.get('/api/hr/attendance', requireOwnerDoctor, async (req, res) => {
  try {
    const { start, end } = req.query;
    if (!/^\d{4}-\d{2}-\d{2}$/.test(String(start)) || !/^\d{4}-\d{2}-\d{2}$/.test(String(end))) return res.status(400).json({ error: 'Bad dates.' });
    const r = await fetch(`${SUPABASE_URL}/rest/v1/attendance?day=gte.${start}&day=lte.${end}&order=day.desc,check_in.asc&limit=5000`, { headers: bookHeaders() });
    const txt = await r.text();
    if (!r.ok) return res.status(500).json({ error: /PGRST205|does not exist|schema cache/.test(txt) ? 'The attendance table is missing — run the attendance SQL in Supabase.' : 'Database error: ' + txt.slice(0, 200) });
    res.type('application/json').send(txt);
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});
app.patch('/api/hr/attendance/:id', requireOwnerDoctor, async (req, res) => {
  try {
    const b = req.body || {};
    const cur = await (await fetch(`${SUPABASE_URL}/rest/v1/attendance?id=eq.${encodeURIComponent(req.params.id)}&limit=1`, { headers: bookHeaders() })).json();
    if (!Array.isArray(cur) || !cur.length) return res.status(404).json({ error: 'Not found.' });
    const day = String(cur[0].day).slice(0, 10), patch = {};
    if (/^\d{2}:\d{2}$/.test(String(b.checkIn || ''))) patch.check_in = cairoToDate(day, b.checkIn).toISOString();
    if (b.checkOut === '' || b.checkOut === null) patch.check_out = null;
    else if (/^\d{2}:\d{2}$/.test(String(b.checkOut || ''))) patch.check_out = cairoToDate(day, b.checkOut).toISOString();
    if (!Object.keys(patch).length) return res.status(400).json({ error: 'Nothing to change.' });
    const r = await fetch(`${SUPABASE_URL}/rest/v1/attendance?id=eq.${encodeURIComponent(req.params.id)}`, { method: 'PATCH', headers: { ...bookHeaders(), 'Content-Type': 'application/json' }, body: JSON.stringify(patch) });
    if (!r.ok) throw new Error(await r.text());
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});
app.delete('/api/hr/attendance/:id', requireOwnerDoctor, async (req, res) => {
  try { await fetch(`${SUPABASE_URL}/rest/v1/attendance?id=eq.${encodeURIComponent(req.params.id)}`, { method: 'DELETE', headers: bookHeaders() }); res.json({ ok: true }); }
  catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

// ---- New-clinic setup form: a friend fills it, the owner reads it inside the app (Settings > Clinic) ----
const ONBOARD_PAGE = Buffer.from(
  'PCFET0NUWVBFIGh0bWw+CjxodG1sIGxhbmc9ImVuIj4KPGhlYWQ+CjxtZXRhIGNoYXJzZXQ9IlVURi04Ij4KPG1ldGEgbmFtZT0i' +
  'dmlld3BvcnQiIGNvbnRlbnQ9IndpZHRoPWRldmljZS13aWR0aCwgaW5pdGlhbC1zY2FsZT0xLjAiPgo8dGl0bGU+TmV3IGNsaW5p' +
  'YyBzZXR1cCBmb3JtPC90aXRsZT48bWV0YSBuYW1lPSJyb2JvdHMiIGNvbnRlbnQ9Im5vaW5kZXgsbm9mb2xsb3ciPgo8c3R5bGU+' +
  'CiAgOnJvb3R7LS1pbms6IzFiMmIyYjstLXBhcGVyOiNmNmY3ZjU7LS1wYW5lbDojZmZmOy0tbGluZTojZGZlM2RmOy0tZ3JlZW46' +
  'IzFmNWM1NjstLWdvbGQ6I2I4ODk0ZjstLXI6MTJweDt9CiAgKntib3gtc2l6aW5nOmJvcmRlci1ib3g7fQogIGJvZHl7bWFyZ2lu' +
  'OjA7YmFja2dyb3VuZDp2YXIoLS1wYXBlcik7Y29sb3I6dmFyKC0taW5rKTtmb250LWZhbWlseTpzeXN0ZW0tdWksLWFwcGxlLXN5' +
  'c3RlbSwiU2Vnb2UgVUkiLFJvYm90byxBcmlhbCxzYW5zLXNlcmlmO3BhZGRpbmc6MTZweDt9CiAgLndyYXB7bWF4LXdpZHRoOjY0' +
  'MHB4O21hcmdpbjowIGF1dG87fQogIGgxe2ZvbnQtc2l6ZToxLjNyZW07bWFyZ2luOjhweCAwIDRweDtjb2xvcjp2YXIoLS1ncmVl' +
  'bik7fQogIC5zdWJ7Zm9udC1zaXplOjAuODVyZW07Y29sb3I6IzViNjg2MzttYXJnaW4tYm90dG9tOjE2cHg7bGluZS1oZWlnaHQ6' +
  'MS41O30KICAuY2FyZHtiYWNrZ3JvdW5kOnZhcigtLXBhbmVsKTtib3JkZXI6MXB4IHNvbGlkIHZhcigtLWxpbmUpO2JvcmRlci1y' +
  'YWRpdXM6dmFyKC0tcik7cGFkZGluZzoxNnB4O21hcmdpbi1ib3R0b206MTZweDt9CiAgLmNhcmQgaDJ7Zm9udC1zaXplOjFyZW07' +
  'bWFyZ2luOjAgMCA0cHg7Y29sb3I6dmFyKC0tZ3JlZW4pO30KICAuaGludHtmb250LXNpemU6MC43OHJlbTtjb2xvcjojN2E4NDdm' +
  'O21hcmdpbjowIDAgMTBweDt9CiAgbGFiZWx7ZGlzcGxheTpibG9jaztmb250LXNpemU6MC44cmVtO21hcmdpbjoxMHB4IDAgM3B4' +
  'O2ZvbnQtd2VpZ2h0OjYwMDt9CiAgbGFiZWwgc21hbGx7Zm9udC13ZWlnaHQ6NDAwO2NvbG9yOiM4YTkzOGU7fQogIGlucHV0LHNl' +
  'bGVjdCx0ZXh0YXJlYXt3aWR0aDoxMDAlO3BhZGRpbmc6MTBweCAxMnB4O2JvcmRlcjoxcHggc29saWQgdmFyKC0tbGluZSk7Ym9y' +
  'ZGVyLXJhZGl1czoxMHB4O2ZvbnQtc2l6ZTowLjkycmVtO2JhY2tncm91bmQ6I2ZmZjtmb250LWZhbWlseTppbmhlcml0O30KICB0' +
  'ZXh0YXJlYXttaW4taGVpZ2h0OjcwcHg7fQogIC5yb3d7Ym9yZGVyOjFweCBzb2xpZCB2YXIoLS1saW5lKTtib3JkZXItcmFkaXVz' +
  'OjEwcHg7cGFkZGluZzoxMHB4O21hcmdpbi10b3A6MTBweDtiYWNrZ3JvdW5kOnZhcigtLXBhcGVyKTt9CiAgLmdyaWR7ZGlzcGxh' +
  'eTpncmlkO2dyaWQtdGVtcGxhdGUtY29sdW1uczoxZnIgMWZyO2dhcDo4cHg7fQogIC5kYXlze2Rpc3BsYXk6ZmxleDtmbGV4LXdy' +
  'YXA6d3JhcDtnYXA6OHB4IDEycHg7bWFyZ2luOjZweCAwO30KICAuZGF5cyBsYWJlbHtkaXNwbGF5OmlubGluZS1mbGV4O2FsaWdu' +
  'LWl0ZW1zOmNlbnRlcjtnYXA6NHB4O21hcmdpbjowO2ZvbnQtd2VpZ2h0OjQwMDtmb250LXNpemU6MC44cmVtO30KICAuZGF5cyBp' +
  'bnB1dHt3aWR0aDphdXRvO30KICBidXR0b257Zm9udC1mYW1pbHk6aW5oZXJpdDtjdXJzb3I6cG9pbnRlcjt9CiAgLmFkZHttYXJn' +
  'aW4tdG9wOjEwcHg7YmFja2dyb3VuZDojZmZmO2JvcmRlcjoxcHggZGFzaGVkIHZhcigtLWdyZWVuKTtjb2xvcjp2YXIoLS1ncmVl' +
  'bik7cGFkZGluZzo5cHggMTJweDtib3JkZXItcmFkaXVzOjEwcHg7Zm9udC1zaXplOjAuODRyZW07d2lkdGg6MTAwJTt9CiAgLmRl' +
  'bHtiYWNrZ3JvdW5kOm5vbmU7Ym9yZGVyOm5vbmU7Y29sb3I6I2EzMztmb250LXNpemU6MC44cmVtO2Zsb2F0OnJpZ2h0O30KICAu' +
  'Z297d2lkdGg6MTAwJTtwYWRkaW5nOjE0cHg7Ym9yZGVyOm5vbmU7Ym9yZGVyLXJhZGl1czoxMnB4O2JhY2tncm91bmQ6dmFyKC0t' +
  'Z3JlZW4pO2NvbG9yOiNmZmY7Zm9udC1zaXplOjFyZW07Zm9udC13ZWlnaHQ6NzAwO30KICAuZ286ZGlzYWJsZWR7b3BhY2l0eTou' +
  'NTt9CiAgLm1zZ3tmb250LXNpemU6MC44NXJlbTttYXJnaW46MTBweCAwO21pbi1oZWlnaHQ6MS4yZW07fQogIC5wcmV2e21heC1o' +
  'ZWlnaHQ6NzBweDttYXgtd2lkdGg6MTAwJTttYXJnaW4tdG9wOjZweDtkaXNwbGF5Om5vbmU7Ym9yZGVyOjFweCBzb2xpZCB2YXIo' +
  'LS1saW5lKTtib3JkZXItcmFkaXVzOjhweDt9CiAgLmhwe3Bvc2l0aW9uOmFic29sdXRlO2xlZnQ6LTk5OTlweDt9Cjwvc3R5bGU+' +
  'CjwvaGVhZD4KPGJvZHk+CjxkaXYgY2xhc3M9IndyYXAiPgogIDxoMT5OZXcgY2xpbmljIHNldHVwIGZvcm08L2gxPgogIDxkaXYg' +
  'Y2xhc3M9InN1YiI+UGxlYXNlIGZpbGwgaW4gd2hhdCB5b3UgY2FuIOKAlCBza2lwIGFueXRoaW5nIHlvdSBkb24ndCBrbm93IGFu' +
  'ZCB3ZSdsbCBzb3J0IGl0IG91dCB0b2dldGhlci4gSXQgdGFrZXMgYWJvdXQgMTAgbWludXRlcy48YnI+2KfZhdmE2KMg2KfZhNmE' +
  '2Yog2KrYudix2YHZh9iMINmI2KfZhNmE2Yog2YXYtCDYudin2LHZgdmHINiz2YrYqNmHINmB2KfYttmKINmI2YfZhtmD2YXZhNmH' +
  'INmF2Lkg2KjYudi2LiDYrdmI2KfZhNmKIDEwINiv2YLYp9mK2YIuPC9kaXY+CiAgPGZvcm0gaWQ9ImYiIGF1dG9jb21wbGV0ZT0i' +
  'b2ZmIj4KICA8aW5wdXQgY2xhc3M9ImhwIiBpZD0id2Vic2l0ZSIgdGFiaW5kZXg9Ii0xIiBhdXRvY29tcGxldGU9Im9mZiI+Cgog' +
  'IDxkaXYgY2xhc3M9ImNhcmQiPjxoMj4xLiBBYm91dCB5b3Ugwrcg2LnZhtmDPC9oMj4KICAgIDxsYWJlbD5Zb3VyIG5hbWUgPHNt' +
  'YWxsPtin2LPZhdmDPC9zbWFsbD48L2xhYmVsPjxpbnB1dCBpZD0ib3duZXJfbmFtZSI+CiAgICA8bGFiZWw+WW91ciBwaG9uZSAv' +
  'IFdoYXRzQXBwIDxzbWFsbD7YsdmC2YUg2KrZhNmK2YHZiNmG2YM8L3NtYWxsPjwvbGFiZWw+PGlucHV0IGlkPSJvd25lcl9waG9u' +
  'ZSIgdHlwZT0idGVsIj4KICAgIDxsYWJlbD5Zb3VyIEdtYWlsIGFkZHJlc3MgKHlvdSB3aWxsIHNpZ24gaW4gd2l0aCBpdCkgPHNt' +
  'YWxsPtin2YTYrNmK2YXZitmEINin2YTZhNmKINmH2KrYr9iu2YQg2KjZitmHPC9zbWFsbD48L2xhYmVsPjxpbnB1dCBpZD0ib3du' +
  'ZXJfZW1haWwiIHR5cGU9ImVtYWlsIj4KICA8L2Rpdj4KCiAgPGRpdiBjbGFzcz0iY2FyZCI+PGgyPjIuIFRoZSBjbGluaWMgwrcg' +
  '2KfZhNi52YrYp9iv2Kk8L2gyPgogICAgPGxhYmVsPkNsaW5pYyBuYW1lIChFbmdsaXNoKSA8c21hbGw+2KfYs9mFINin2YTYudmK' +
  '2KfYr9ipINio2KfZhNil2YbYrNmE2YrYstmKPC9zbWFsbD48L2xhYmVsPjxpbnB1dCBpZD0ibmFtZSI+CiAgICA8bGFiZWw+Q2xp' +
  'bmljIG5hbWUgKEFyYWJpYykgPHNtYWxsPtin2LPZhSDYp9mE2LnZitin2K/YqSDYqNin2YTYudix2KjZijwvc21hbGw+PC9sYWJl' +
  'bD48aW5wdXQgaWQ9Im5hbWVfYXIiPgogICAgPGxhYmVsPlNob3J0IGxpbmUgdW5kZXIgdGhlIG5hbWUgPHNtYWxsPtis2YXZhNip' +
  'INmC2LXZitix2Kkg2KrYrdiqINin2YTYp9iz2YUgKNin2K7YqtmK2KfYsdmKKTwvc21hbGw+PC9sYWJlbD48aW5wdXQgaWQ9InRh' +
  'Z2xpbmUiPgogICAgPGxhYmVsPkFkZHJlc3MgKEVuZ2xpc2gpPC9sYWJlbD48dGV4dGFyZWEgaWQ9ImFkZHJlc3MiPjwvdGV4dGFy' +
  'ZWE+CiAgICA8bGFiZWw+QWRkcmVzcyAoQXJhYmljKSA8c21hbGw+2KfZhNi52YbZiNin2YYg2KjYp9mE2LnYsdio2Yo8L3NtYWxs' +
  'PjwvbGFiZWw+PHRleHRhcmVhIGlkPSJhZGRyZXNzX2FyIj48L3RleHRhcmVhPgogICAgPGxhYmVsPkdvb2dsZSBNYXBzIGxpbmsg' +
  'PHNtYWxsPtmE2YrZhtmDINin2YTZhdmI2YLYuSDYudmE2Ykg2KfZhNiu2LHZiti32Kk8L3NtYWxsPjwvbGFiZWw+PGlucHV0IGlk' +
  'PSJtYXBfdXJsIiB0eXBlPSJ1cmwiPgogICAgPGxhYmVsPkNsaW5pYyBwaG9uZSAvIFdoYXRzQXBwIG51bWJlciA8c21hbGw+2LHZ' +
  'gtmFINin2YTYudmK2KfYr9ipPC9zbWFsbD48L2xhYmVsPjxpbnB1dCBpZD0icGhvbmUiIHR5cGU9InRlbCI+CiAgICA8bGFiZWw+' +
  'SW5zdGFncmFtIC8gRmFjZWJvb2sgbGluayA8c21hbGw+KNin2K7YqtmK2KfYsdmKKTwvc21hbGw+PC9sYWJlbD48aW5wdXQgaWQ9' +
  'InNvY2lhbCI+CiAgICA8bGFiZWw+R29vZ2xlIHJldmlldyBsaW5rIDxzbWFsbD7ZhNmK2YbZgyDYp9mE2KrZgtmK2YrZhSDYudmE' +
  '2Ykg2KzZiNis2YQgKNin2K7YqtmK2KfYsdmKKTwvc21hbGw+PC9sYWJlbD48aW5wdXQgaWQ9InJldmlld191cmwiIHR5cGU9InVy' +
  'bCI+CiAgICA8bGFiZWw+Q2xpbmljIGxvZ28gPHNtYWxsPtin2YTZhNmI2KzZiCAo2LXZiNix2KkgUE5HINij2YggSlBHKTwvc21h' +
  'bGw+PC9sYWJlbD48aW5wdXQgaWQ9ImxvZ29fZmlsZSIgdHlwZT0iZmlsZSIgYWNjZXB0PSJpbWFnZS8qIj48aW1nIGlkPSJsb2dv' +
  'X3ByZXYiIGNsYXNzPSJwcmV2Ij4KICAgIDxsYWJlbD5TdGFtcCBpbWFnZSA8c21hbGw+2LXZiNix2Kkg2KfZhNiu2KrZhSAo2KfY' +
  'rtiq2YrYp9ix2YopPC9zbWFsbD48L2xhYmVsPjxpbnB1dCBpZD0ic3RhbXBfZmlsZSIgdHlwZT0iZmlsZSIgYWNjZXB0PSJpbWFn' +
  'ZS8qIj48aW1nIGlkPSJzdGFtcF9wcmV2IiBjbGFzcz0icHJldiI+CiAgPC9kaXY+CgogIDxkaXYgY2xhc3M9ImNhcmQiPjxoMj4z' +
  'LiBQYXltZW50cyDCtyDYp9mE2K/Zgdi5PC9oMj4KICAgIDxsYWJlbD5Ib3cgZG8gcGF0aWVudHMgcGF5PzwvbGFiZWw+CiAgICA8' +
  'ZGl2IGNsYXNzPSJkYXlzIj48bGFiZWw+PGlucHV0IHR5cGU9ImNoZWNrYm94IiBpZD0icGF5X2Nhc2giIGNoZWNrZWQ+Q2FzaDwv' +
  'bGFiZWw+PGxhYmVsPjxpbnB1dCB0eXBlPSJjaGVja2JveCIgaWQ9InBheV9pbnN0YSIgY2hlY2tlZD5JbnN0YVBheTwvbGFiZWw+' +
  'PC9kaXY+CiAgICA8bGFiZWw+SW5zdGFQYXkgbGluayA8c21hbGw+2YTZitmG2YMg2KfZhtiz2KrYpyDYqNin2Yo8L3NtYWxsPjwv' +
  'bGFiZWw+PGlucHV0IGlkPSJpbnN0YXBheV91cmwiIHR5cGU9InVybCI+CiAgICA8bGFiZWw+SW5zdGFQYXkgYWRkcmVzcyAvIGhh' +
  'bmRsZSA8c21hbGw+2LnZhtmI2KfZhiDYp9mG2LPYqtinINio2KfZijwvc21hbGw+PC9sYWJlbD48aW5wdXQgaWQ9Imluc3RhcGF5' +
  'X2hhbmRsZSI+CiAgPC9kaXY+CgogIDxkaXYgY2xhc3M9ImNhcmQiPjxoMj40LiBUaGUgdGVhbSDCtyDYp9mE2YHYsdmK2YI8L2gy' +
  'PgogICAgPGRpdiBjbGFzcz0iaGludCI+QWRkIGV2ZXJ5b25lIHdobyB3b3JrcyBhdCB0aGUgY2xpbmljOiBkb2N0b3JzLCBudXRy' +
  'aXRpb25pc3QsIHNlY3JldGFyeS4gwrcg2LbZitmBINmD2YQg2KfZhNmE2Yog2KjZiti02KrYutmEINmB2Yog2KfZhNi52YrYp9iv' +
  '2KkuPC9kaXY+CiAgICA8ZGl2IGlkPSJ0ZWFtIj48L2Rpdj4KICAgIDxidXR0b24gdHlwZT0iYnV0dG9uIiBjbGFzcz0iYWRkIiBp' +
  'ZD0iYWRkVGVhbSI+KyBBZGQgYSBwZXJzb248L2J1dHRvbj4KICA8L2Rpdj4KCiAgPGRpdiBjbGFzcz0iY2FyZCI+PGgyPjUuIFNl' +
  'cnZpY2VzIGFuZCBwcmljZXMgwrcg2KfZhNiu2K/Zhdin2Kog2YjYp9mE2KPYs9i52KfYsTwvaDI+CiAgICA8ZGl2IGNsYXNzPSJo' +
  'aW50Ij5DaGVjay11cCwgc2luZ2xlIHNlc3Npb24sIHJlY292ZXJ5LCBwYWNrYWdlcy4uLiDCtyDYp9mE2YPYtNmBINmI2KfZhNis' +
  '2YTYs9ipINmI2KfZhNio2KfZg9iv2KzYp9iqLjwvZGl2PgogICAgPGRpdiBpZD0ic2VydmljZXMiPjwvZGl2PgogICAgPGJ1dHRv' +
  'biB0eXBlPSJidXR0b24iIGNsYXNzPSJhZGQiIGlkPSJhZGRTZXJ2aWNlIj4rIEFkZCBhIHNlcnZpY2U8L2J1dHRvbj4KICAgIDxs' +
  'YWJlbD5QYWNrYWdlIHZhbGlkaXR5IDxzbWFsbD7Zhdiv2Kkg2LXZhNin2K3ZitipINin2YTYqNin2YPYr9isICjZhdir2YTYp9mL' +
  'IDYg2KzZhNiz2KfYqiA9IDMg2KPYs9in2KjZiti5KTwvc21hbGw+PC9sYWJlbD48dGV4dGFyZWEgaWQ9InBhY2thZ2VfdmFsaWRp' +
  'dHkiPjwvdGV4dGFyZWE+CiAgICA8bGFiZWw+Q2FuY2VsbGF0aW9uIHBvbGljeSA8c21hbGw+2LPZitin2LPYqSDYp9mE2KXZhNi6' +
  '2KfYoSAo2YXYq9mE2KfZiyDZgtio2YTZh9inINio2YA1INiz2KfYudin2KopPC9zbWFsbD48L2xhYmVsPjx0ZXh0YXJlYSBpZD0i' +
  'Y2FuY2VsX3BvbGljeSI+PC90ZXh0YXJlYT4KICA8L2Rpdj4KCiAgPGRpdiBjbGFzcz0iY2FyZCI+PGgyPjYuIE1vbnRobHkgZml4' +
  'ZWQgY29zdHMgwrcg2KfZhNmF2LXYp9ix2YrZgSDYp9mE2KvYp9io2KrYqTwvaDI+CiAgICA8ZGl2IGNsYXNzPSJoaW50Ij5SZW50' +
  'LCBkb29ybWFuLCBpbnRlcm5ldCwgYWRzLi4uIMK3INin2YTYpdmK2KzYp9ixINmI2KfZhNio2YjYp9ioINmI2KfZhNmG2Kog2YjY' +
  'p9mE2KXYudmE2KfZhtin2KouPC9kaXY+CiAgICA8ZGl2IGlkPSJmaXhlZCI+PC9kaXY+CiAgICA8YnV0dG9uIHR5cGU9ImJ1dHRv' +
  'biIgY2xhc3M9ImFkZCIgaWQ9ImFkZEZpeGVkIj4rIEFkZCBhIGNvc3Q8L2J1dHRvbj4KICA8L2Rpdj4KCiAgPGRpdiBjbGFzcz0i' +
  'Y2FyZCI+PGgyPjcuIE9ubGluZSBib29raW5nIMK3INin2YTYrdis2LIg2KPZiNmG2YTYp9mK2YY8L2gyPgogICAgPGxhYmVsPkRv' +
  'IHlvdSB3YW50IHBhdGllbnRzIHRvIGJvb2sgb25saW5lPzwvbGFiZWw+CiAgICA8c2VsZWN0IGlkPSJvbmxpbmVfYm9va2luZyI+' +
  'PG9wdGlvbiB2YWx1ZT0ieWVzIj5ZZXM8L29wdGlvbj48b3B0aW9uIHZhbHVlPSJubyI+Tm88L29wdGlvbj48b3B0aW9uIHZhbHVl' +
  'PSJsYXRlciI+TWF5YmUgbGF0ZXI8L29wdGlvbj48L3NlbGVjdD4KICAgIDxsYWJlbD5TZXNzaW9uIGxlbmd0aCBpbiBtaW51dGVz' +
  'IDxzbWFsbD7Zhdiv2Kkg2KfZhNis2YTYs9ipINio2KfZhNiv2YLYp9mK2YI8L3NtYWxsPjwvbGFiZWw+PGlucHV0IGlkPSJzbG90' +
  'X21pbnV0ZXMiIHR5cGU9Im51bWJlciIgcGxhY2Vob2xkZXI9IjMwIj4KICAgIDxsYWJlbD5DbGluaWMgb3BlbmluZyBkYXlzIGFu' +
  'ZCBob3VycyA8c21hbGw+2KPZitin2YUg2YjYs9in2LnYp9iqINin2YTYudmF2YQ8L3NtYWxsPjwvbGFiZWw+PHRleHRhcmVhIGlk' +
  'PSJvcGVuaW5nIiBwbGFjZWhvbGRlcj0iU2F04oCTVGh1IDEwYW3igJM5cG0iPjwvdGV4dGFyZWE+CiAgICA8bGFiZWw+SG93IGRv' +
  'IHBhdGllbnRzIGZpbmQgdGhlIGNsaW5pYz8gPHNtYWxsPtil2LLYp9mKINin2YTZhdix2YrYtiDZitmI2LXZhCDZhNmE2LnZitin' +
  '2K/YqSAo2KfZhNiv2YjYsdiMINin2YTYo9iz2KfZhtiz2YrYsdiMINmD2YjYryDYp9mE2KjYp9ioKTwvc21hbGw+PC9sYWJlbD48' +
  'dGV4dGFyZWEgaWQ9ImRpcmVjdGlvbnMiPjwvdGV4dGFyZWE+CiAgPC9kaXY+CgogICAgPGRpdiBjbGFzcz0iY2FyZCI+PGgyPjgu' +
  'IFBhdGllbnQgbWVzc2FnZXMgwrcg2LHYs9in2KbZhCDYp9mE2YXYsdi22Yk8L2gyPgogICAgPHAgc3R5bGU9ImZvbnQtc2l6ZTow' +
  'LjgycmVtO2NvbG9yOiM1YjY4NjM7bWFyZ2luOjAgMCA2cHg7Ij5UaGVzZSBhcmUgdGhlIFdoYXRzQXBwIG1lc3NhZ2VzIHRoZSBz' +
  'eXN0ZW0gc2VuZHMgdG8gcGF0aWVudHMuIFJlYWQgZWFjaCBvbmUsIGVkaXQgaXQgdGhlIHdheSB5b3UgbGlrZSwgb3Iga2VlcCBp' +
  'dCBhcyBpdCBpcy4gRG9uJ3QgY2hhbmdlIHRoZSB3b3JkcyBpbnNpZGUgeyB9IOKAlCB0aGUgc3lzdGVtIGZpbGxzIHRoZW0gaW4g' +
  'YXV0b21hdGljYWxseSAoZm9yIGV4YW1wbGUge25hbWV9ID0gcGF0aWVudCBuYW1lLCB7Y2xpbmljfSA9IHlvdXIgY2xpbmljIG5h' +
  'bWUsIHtkYXRlfSBhbmQge3RpbWV9ID0gdGhlIHZpc2l0KS48YnI+2K/ZiiDYp9mE2LHYs9in2KbZhCDYp9mE2YTZiiDYp9mE2LPZ' +
  'itiz2KrZhSDYqNmK2KjYudiq2YfYpyDZhNmE2YXYsdi22YkuINin2YLYsdijINmD2YQg2LHYs9in2YTYqSDZiNi52K/ZkdmE2YfY' +
  'pyDYstmKINmF2Kcg2KrYrdioINij2Ygg2LPZitio2YfYpyDYstmKINmF2Kcg2YfZii4g2YXYpyDYqti62YrZkdix2LQg2KfZhNmD' +
  '2YTZhdin2Kog2KfZhNmE2Yog2KjZitmGIHsgfSDZhNij2YYg2KfZhNiz2YrYs9iq2YUg2KjZitmF2YTYp9mH2Kcg2YTZiNit2K/Z' +
  'hy48L3A+CiAgICA8ZGl2IGlkPSJ0cGxzIj48L2Rpdj4KICA8L2Rpdj4KCiAgPGRpdiBjbGFzcz0iY2FyZCI+PGgyPjkuIEFjY291' +
  'bnRzIGFuZCBuYW1lIMK3INin2YTYrdiz2KfYqNin2Ko8L2gyPgogICAgPGxhYmVsPlByZWZlcnJlZCB3ZWIgYWRkcmVzcyA8c21h' +
  'bGw+2KfZhNin2LPZhSDYp9mE2YXYt9mE2YjYqCDZhNmE2LnZhtmI2KfZhiAo2YXYq9mE2KfZizogeW91cmNsaW5pYyk8L3NtYWxs' +
  'PjwvbGFiZWw+PGlucHV0IGlkPSJzdWJkb21haW4iIHBsYWNlaG9sZGVyPSJ5b3VyY2xpbmljIj4KICAgIDxsYWJlbD5Bbnl0aGlu' +
  'ZyBlbHNlIHdlIHNob3VsZCBrbm93PyA8c21hbGw+2KPZiiDYrdin2KzYqSDYqtin2YbZitipPC9zbWFsbD48L2xhYmVsPjx0ZXh0' +
  'YXJlYSBpZD0ibm90ZXMiPjwvdGV4dGFyZWE+CiAgPC9kaXY+CgogIDxkaXYgY2xhc3M9Im1zZyIgaWQ9Im1zZyI+PC9kaXY+CiAg' +
  'PGJ1dHRvbiB0eXBlPSJzdWJtaXQiIGNsYXNzPSJnbyIgaWQ9ImdvIj5TZW5kIMK3INil2LHYs9in2YQ8L2J1dHRvbj4KICA8L2Zv' +
  'cm0+CjwvZGl2Pgo8c2NyaXB0Pgpjb25zdCAkID0gaWQgPT4gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoaWQpOwpjb25zdCBEQVlT' +
  'ID0gWydTYXQnLCdTdW4nLCdNb24nLCdUdWUnLCdXZWQnLCdUaHUnLCdGcmknXTsKZnVuY3Rpb24gcm93SHRtbChpbm5lcil7IHJl' +
  'dHVybiAnPGRpdiBjbGFzcz0icm93Ij48YnV0dG9uIHR5cGU9ImJ1dHRvbiIgY2xhc3M9ImRlbCI+cmVtb3ZlIOKclTwvYnV0dG9u' +
  'PicgKyBpbm5lciArICc8L2Rpdj4nOyB9CmZ1bmN0aW9uIHRlYW1Sb3coKXsKICByZXR1cm4gcm93SHRtbChgPGRpdiBjbGFzcz0i' +
  'Z3JpZCI+PGRpdj48bGFiZWw+TmFtZTwvbGFiZWw+PGlucHV0IGNsYXNzPSJ0X25hbWUiPjwvZGl2PjxkaXY+PGxhYmVsPlJvbGU8' +
  'L2xhYmVsPjxzZWxlY3QgY2xhc3M9InRfcm9sZSI+PG9wdGlvbiB2YWx1ZT0iZG9jdG9yIj5Eb2N0b3I8L29wdGlvbj48b3B0aW9u' +
  'IHZhbHVlPSJwYXJ0bmVyIj5QYXJ0bmVyIGRvY3Rvcjwvb3B0aW9uPjxvcHRpb24gdmFsdWU9Im51dHJpdGlvbmlzdCI+TnV0cml0' +
  'aW9uaXN0PC9vcHRpb24+PG9wdGlvbiB2YWx1ZT0ic2VjcmV0YXJ5Ij5TZWNyZXRhcnk8L29wdGlvbj48b3B0aW9uIHZhbHVlPSJv' +
  'dGhlciI+T3RoZXI8L29wdGlvbj48L3NlbGVjdD48L2Rpdj48L2Rpdj4KICA8bGFiZWw+R21haWwgKHRvIHNpZ24gaW4pIDxzbWFs' +
  'bD7Yp9iu2KrZitin2LHZijwvc21hbGw+PC9sYWJlbD48aW5wdXQgY2xhc3M9InRfZW1haWwiIHR5cGU9ImVtYWlsIj4KICA8bGFi' +
  'ZWw+SG93IGlzIHRoaXMgcGVyc29uIHBhaWQ/PC9sYWJlbD4KICA8c2VsZWN0IGNsYXNzPSJ0X3BheSI+PG9wdGlvbiB2YWx1ZT0i' +
  'c2hhcmUiPkEgJSBvZiB0aGUgbW9uZXkgdGhleSBjb2xsZWN0PC9vcHRpb24+PG9wdGlvbiB2YWx1ZT0iZml4ZWQiPkZpeGVkIG1v' +
  'bnRobHkgc2FsYXJ5PC9vcHRpb24+PG9wdGlvbiB2YWx1ZT0iZml4ZWRfcmF0ZSI+Rml4ZWQgKyBhbW91bnQgcGVyIHNlc3Npb248' +
  'L29wdGlvbj48b3B0aW9uIHZhbHVlPSJwYXJ0bmVyIj5QYXJ0bmVyICglICsgc2hhcmUgb2YgcHJvZml0KTwvb3B0aW9uPjwvc2Vs' +
  'ZWN0PgogIDxkaXYgY2xhc3M9ImdyaWQiPjxkaXY+PGxhYmVsPiUgPHNtYWxsPtin2YTZhtiz2KjYqTwvc21hbGw+PC9sYWJlbD48' +
  'aW5wdXQgY2xhc3M9InRfcGN0IiB0eXBlPSJudW1iZXIiPjwvZGl2PjxkaXY+PGxhYmVsPkZpeGVkIHNhbGFyeSA8c21hbGw+2KfZ' +
  'hNir2KfYqNiqPC9zbWFsbD48L2xhYmVsPjxpbnB1dCBjbGFzcz0idF9maXhlZCIgdHlwZT0ibnVtYmVyIj48L2Rpdj48L2Rpdj4K' +
  'ICA8bGFiZWw+UGVyIHNlc3Npb24gPHNtYWxsPti52YYg2YPZhCDYrNmE2LPYqSAo2YTZiCDZgdmK2YcpPC9zbWFsbD48L2xhYmVs' +
  'PjxpbnB1dCBjbGFzcz0idF9yYXRlIiB0eXBlPSJudW1iZXIiPgogIDxsYWJlbD5Xb3JraW5nIGRheXMgYW5kIHNoaWZ0IGhvdXJz' +
  'IDxzbWFsbD7Yo9mK2KfZhSDYp9mE2LTYutmEINmI2YXZiNin2LnZitivINin2YTYtNmB2Ko8L3NtYWxsPjwvbGFiZWw+CiAgPGRp' +
  'diBjbGFzcz0iZGF5cyI+JHtEQVlTLm1hcChkPT5gPGxhYmVsPjxpbnB1dCB0eXBlPSJjaGVja2JveCIgY2xhc3M9InRfZGF5IiB2' +
  'YWx1ZT0iJHtkfSI+JHtkfTwvbGFiZWw+YCkuam9pbignJyl9PC9kaXY+CiAgPGRpdiBjbGFzcz0iZ3JpZCI+PGRpdj48bGFiZWw+' +
  'U2hpZnQgZnJvbTwvbGFiZWw+PGlucHV0IGNsYXNzPSJ0X2Zyb20iIHR5cGU9InRpbWUiPjwvZGl2PjxkaXY+PGxhYmVsPlNoaWZ0' +
  'IHRvPC9sYWJlbD48aW5wdXQgY2xhc3M9InRfdG8iIHR5cGU9InRpbWUiPjwvZGl2PjwvZGl2PmApOwp9CmZ1bmN0aW9uIHNlcnZp' +
  'Y2VSb3coKXsKICByZXR1cm4gcm93SHRtbChgPGRpdiBjbGFzcz0iZ3JpZCI+PGRpdj48bGFiZWw+U2VydmljZSBuYW1lPC9sYWJl' +
  'bD48aW5wdXQgY2xhc3M9InNfbmFtZSIgcGxhY2Vob2xkZXI9ImUuZy4gQ2hlY2stdXAiPjwvZGl2PjxkaXY+PGxhYmVsPlByaWNl' +
  'IChFR1ApPC9sYWJlbD48aW5wdXQgY2xhc3M9InNfcHJpY2UiIHR5cGU9Im51bWJlciI+PC9kaXY+PC9kaXY+CiAgPGxhYmVsPlR5' +
  'cGU8L2xhYmVsPjxzZWxlY3QgY2xhc3M9InNfdHlwZSI+PG9wdGlvbiB2YWx1ZT0iY2hlY2t1cCI+Q2hlY2stdXAgKNmD2LTZgSk8' +
  'L29wdGlvbj48b3B0aW9uIHZhbHVlPSJzZXNzaW9uIj5TZXNzaW9uICjYrNmE2LPYqSk8L29wdGlvbj48b3B0aW9uIHZhbHVlPSJy' +
  'ZWNvdmVyeSI+UmVjb3ZlcnkgKNix2YrZg9mB2LHZiik8L29wdGlvbj48b3B0aW9uIHZhbHVlPSJwYWNrYWdlIj5QYWNrYWdlICjY' +
  'qNin2YPYr9isKTwvb3B0aW9uPjxvcHRpb24gdmFsdWU9Im90aGVyIj5PdGhlcjwvb3B0aW9uPjwvc2VsZWN0PgogIDxsYWJlbD5O' +
  'dW1iZXIgb2Ygc2Vzc2lvbnMgaW4gaXQgPHNtYWxsPtmE2Ygg2KjYp9mD2K/YrDog2YPYp9mFINis2YTYs9ipPC9zbWFsbD48L2xh' +
  'YmVsPjxpbnB1dCBjbGFzcz0ic19jb3VudCIgdHlwZT0ibnVtYmVyIj5gKTsKfQpmdW5jdGlvbiBmaXhlZFJvdygpewogIHJldHVy' +
  'biByb3dIdG1sKGA8ZGl2IGNsYXNzPSJncmlkIj48ZGl2PjxsYWJlbD5XaGF0PC9sYWJlbD48aW5wdXQgY2xhc3M9ImZfbmFtZSIg' +
  'cGxhY2Vob2xkZXI9IlJlbnQiPjwvZGl2PjxkaXY+PGxhYmVsPkFtb3VudCBwZXIgbW9udGg8L2xhYmVsPjxpbnB1dCBjbGFzcz0i' +
  'Zl9hbW91bnQiIHR5cGU9Im51bWJlciI+PC9kaXY+PC9kaXY+YCk7Cn0KZnVuY3Rpb24gd2lyZURlbChyb290KXsgcm9vdC5xdWVy' +
  'eVNlbGVjdG9yQWxsKCcuZGVsJykuZm9yRWFjaChiPT4gYi5vbmNsaWNrID0gKCk9PiBiLmNsb3Nlc3QoJy5yb3cnKS5yZW1vdmUo' +
  'KSk7IH0KZnVuY3Rpb24gYWRkKGxpc3RJZCwgZm4peyBjb25zdCBsID0gJChsaXN0SWQpOyBsLmluc2VydEFkamFjZW50SFRNTCgn' +
  'YmVmb3JlZW5kJywgZm4oKSk7IHdpcmVEZWwobCk7IH0KJCgnYWRkVGVhbScpLm9uY2xpY2sgPSAoKT0+IGFkZCgndGVhbScsIHRl' +
  'YW1Sb3cpOwokKCdhZGRTZXJ2aWNlJykub25jbGljayA9ICgpPT4gYWRkKCdzZXJ2aWNlcycsIHNlcnZpY2VSb3cpOwokKCdhZGRG' +
  'aXhlZCcpLm9uY2xpY2sgPSAoKT0+IGFkZCgnZml4ZWQnLCBmaXhlZFJvdyk7CmFkZCgndGVhbScsIHRlYW1Sb3cpOyBhZGQoJ3Nl' +
  'cnZpY2VzJywgc2VydmljZVJvdyk7IGFkZCgnZml4ZWQnLCBmaXhlZFJvdyk7Cgpjb25zdCBpbWdzID0geyBsb2dvOicnLCBzdGFt' +
  'cDonJyB9OwpmdW5jdGlvbiByZXNpemUoZmlsZSwgbWF4VywgY2IpewogIGNvbnN0IHJkID0gbmV3IEZpbGVSZWFkZXIoKTsKICBy' +
  'ZC5vbmxvYWQgPSAoKT0+eyBjb25zdCBpbSA9IG5ldyBJbWFnZSgpOyBpbS5vbmxvYWQgPSAoKT0+ewogICAgY29uc3QgayA9IE1h' +
  'dGgubWluKDEsIG1heFcgLyBpbS53aWR0aCk7IGNvbnN0IGN2ID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnY2FudmFzJyk7IGN2' +
  'LndpZHRoID0gTWF0aC5yb3VuZChpbS53aWR0aCprKTsgY3YuaGVpZ2h0ID0gTWF0aC5yb3VuZChpbS5oZWlnaHQqayk7CiAgICBj' +
  'b25zdCBjeCA9IGN2LmdldENvbnRleHQoJzJkJyk7IGN4LmRyYXdJbWFnZShpbSwwLDAsY3Yud2lkdGgsY3YuaGVpZ2h0KTsKICAg' +
  'IGxldCB1ID0gY3YudG9EYXRhVVJMKCdpbWFnZS9wbmcnKTsKICAgIGlmKHUubGVuZ3RoID4gMjUwMDAwKXsgY3guZ2xvYmFsQ29t' +
  'cG9zaXRlT3BlcmF0aW9uPSdkZXN0aW5hdGlvbi1vdmVyJzsgY3guZmlsbFN0eWxlPScjZmZmJzsgY3guZmlsbFJlY3QoMCwwLGN2' +
  'LndpZHRoLGN2LmhlaWdodCk7IHUgPSBjdi50b0RhdGFVUkwoJ2ltYWdlL2pwZWcnLDAuODUpOyB9CiAgICBjYih1Lmxlbmd0aCA+' +
  'IDM4MDAwMCA/ICcnIDogdSk7IH07CiAgICBpbS5vbmVycm9yID0gKCk9PiBjYignJyk7IGltLnNyYyA9IHJkLnJlc3VsdDsgfTsK' +
  'ICByZC5yZWFkQXNEYXRhVVJMKGZpbGUpOwp9CltbJ2xvZ28nLDYwMF0sWydzdGFtcCcsNDAwXV0uZm9yRWFjaCgoW2ssd10pPT57' +
  'CiAgJChrKydfZmlsZScpLm9uY2hhbmdlID0gZT0+eyBjb25zdCBmID0gZS50YXJnZXQuZmlsZXNbMF07IGlmKCFmKSByZXR1cm47' +
  'CiAgICByZXNpemUoZiwgdywgdT0+eyBpZighdSl7IGFsZXJ0KCdUaGlzIGltYWdlIGlzIHRvbyBiaWcgb3Igbm90IHJlYWRhYmxl' +
  'LiBUcnkgYSBzbWFsbGVyIFBORyBvciBKUEcuJyk7IHJldHVybjsgfSBpbWdzW2tdID0gdTsgJChrKydfcHJldicpLnNyYyA9IHU7' +
  'ICQoaysnX3ByZXYnKS5zdHlsZS5kaXNwbGF5ID0gJ2Jsb2NrJzsgfSk7IH07Cn0pOwpjb25zdCBUUExTID0gWwogWydjb25maXJt' +
  'YXRpb24nLCdBcHBvaW50bWVudCBjb25maXJtYXRpb24gwrcg2KrYo9mD2YrYryDYp9mE2YXZiNi52K8nLCdTZW50IHdoZW4gYSB2' +
  'aXNpdCBpcyBib29rZWQuIMK3INio2KrYqtio2LnYqiDZhNmF2Kcg2KfZhNmF2YjYudivINmK2KrYrdis2LIuJywiRGVhciB7bmFt' +
  'ZX1cbldlIGFyZSB3cml0aW5nIHRvIGNvbmZpcm0geW91ciB1cGNvbWluZyBzZXNzaW9uIGF0IHtjbGluaWN9IG9uIHtkYXRlfSBh' +
  'dCB7dGltZX0uXG57YWRkcmVzc19saW5lfXttYXBfbGluZX1cblRoYW5rIHlvdS5cbntjbGluaWN9Il0sCiBbJ2VsZXZhdG9yJywn' +
  'RGlyZWN0aW9ucyDCtyDYpdiy2KfZiiDYqtmI2LXZhCDZhNmE2LnZitin2K/YqScsJ1NlbnQgdG8gaGVscCB0aGUgcGF0aWVudCBm' +
  'aW5kIHRoZSBjbGluaWMuIEFkZCBmbG9vciAvIGxpZnQgLyBkb29yIGNvZGUuIMK3INin2YPYqtioINin2YTYr9mI2LEg2YjYp9mE' +
  '2KPYs9in2YbYs9mK2LEg2YjZg9mI2K8g2KfZhNio2KfYqC4nLCJEaXJlY3Rpb25zIHRvIHtjbGluaWN9OlxuXG57YWRkcmVzc31c' +
  'bnttYXB9Il0sCiBbJ3BhY2thZ2VfcG9saWN5JywnUGFja2FnZSB2YWxpZGl0eSBhbmQgcmVmdW5kIHBvbGljeSDCtyDYs9mK2KfY' +
  's9ipINin2YTYqNin2YPYr9isJywnU2VudCB3aGVuIGEgcGF0aWVudCBidXlzIGEgcGFja2FnZS4gV3JpdGUgaG93IGxvbmcgaXQg' +
  'aXMgdmFsaWQgYW5kIHRoZSByZWZ1bmQgcnVsZXMuIMK3INin2YPYqtioINmF2K/YqSDYtdmE2KfYrdmK2Kkg2KfZhNio2KfZg9iv' +
  '2Kwg2YjYs9mK2KfYs9ipINin2YTYp9iz2KrYsdis2KfYuS4nLCIiXSwKIFsncmVjb3Zlcnlfc2Vzc2lvbl9wb2xpY3knLCdSZWNv' +
  'dmVyeSBzZXNzaW9uIHBvbGljeSDCtyDYs9mK2KfYs9ipINin2YTYsdmK2YPZgdix2YonLCdTZW50IGJlZm9yZSBhIHJlY292ZXJ5' +
  'IHNlc3Npb24uIFdyaXRlIHRoZSBydWxlcyAodGltaW5nLCBjYW5jZWxsYXRpb24uLi4pLiDCtyDYp9mD2KrYqCDYtNix2YjYtyDY' +
  'rNmE2LPYqSDYp9mE2LHZitmD2YHYsdmKLicsIiJdLAogWydpbnN0YXBheV9wYXltZW50JywnSW5zdGFQYXkgcGF5bWVudCByZXF1' +
  'ZXN0IMK3INi32YTYqCDYp9mE2K/Zgdi5INio2KfZhtiz2KrYpyDYqNin2YonLCdTZW50IHdoZW4gdGhlIHBhdGllbnQgcGF5cyBi' +
  'eSBJbnN0YVBheS4gwrcg2KjYqtiq2KjYudiqINmE2YXYpyDYp9mE2YXYsdmK2LYg2YrYr9mB2Lkg2KfZhtiz2KrYpyDYqNin2You' +
  'Jywie2Ftb3VudF9saW5lfXtpbnN0YXBheV91cmx9XG5DbGljayB0aGUgbGluayB0byBzZW5kIG1vbmV5IHRvXG57aW5zdGFwYXlf' +
  'aGFuZGxlfVxuUG93ZXJlZCBieSBJbnN0YVBheVxuXG5QbGVhc2Ugc2VuZCBhIHNjcmVlbnNob3Qgb2YgdGhlIHBheW1lbnQgb25j' +
  'ZSBkb25lLiJdLAogWydpbnRha2VfZm9ybScsJ1BhdGllbnQgaW50YWtlIGZvcm0gwrcg2YHZiNix2YUg2KjZitin2YbYp9iqINin' +
  '2YTZhdix2YrYticsJ1NlbnQgYmVmb3JlIHRoZSBmaXJzdCB2aXNpdC4gwrcg2KjYqtiq2KjYudiqINmC2KjZhCDYo9mI2YQg2LLZ' +
  'itin2LHYqS4nLCJXZWxjb21lIHRvIHtjbGluaWN9IVxuXG5CZWZvcmUgeW91ciB2aXNpdCBvbiB7ZGF0ZX0gYXQge3RpbWV9LCBw' +
  'bGVhc2UgZmlsbCBpbiB0aGlzIHNob3J0IGZvcm0gc28gd2UgY2FuIHByZXBhcmUgZm9yIHlvdTpcblxue2ludGFrZX1cblxuVGhh' +
  'bmsgeW91LiJdLAogWydwYWNrYWdlX2xhc3Rfc2Vzc2lvbicsJ0xhc3Qgc2Vzc2lvbiBpbiBhIHBhY2thZ2Ugwrcg2KLYrtixINis' +
  '2YTYs9ipINmB2Yog2KfZhNio2KfZg9iv2KwnLCdTZW50IGFmdGVyIHRoZSBsYXN0IHNlc3Npb247IGFza3MgZm9yIGEgR29vZ2xl' +
  'IHJldmlldy4gwrcg2KjYqtiq2KjYudiqINio2LnYryDYotiu2LEg2KzZhNiz2Kkg2YjYqNiq2LfZhNioINiq2YLZitmK2YUuJywi' +
  'SGkge25hbWV9LFxuXG5UaGlzIHdhcyB5b3VyIGxhc3Qgc2Vzc2lvbiBpbiB5b3VyIGN1cnJlbnQgcGFja2FnZS4gV2UgaG9wZSB5' +
  'b3UncmUgZmVlbGluZyBtdWNoIGJldHRlciEg8J+Mv1xuXG5JZiB5b3UgaGF2ZSBhIG1vbWVudCwgd2UnZCByZWFsbHkgYXBwcmVj' +
  'aWF0ZSBhIHF1aWNrIEdvb2dsZSByZXZpZXcsIGl0IGhlbHBzIG90aGVyIHBhdGllbnRzIGZpbmQgdXM6XG57cmV2aWV3fVxuXG5U' +
  'YWtlIGNhcmUsXG57Y2xpbmljfSJdCl07CiQoJ3RwbHMnKS5pbm5lckhUTUwgPSBUUExTLm1hcCh0PT4gJzxsYWJlbCBzdHlsZT0i' +
  'bWFyZ2luLXRvcDoxNHB4O2ZvbnQtd2VpZ2h0OjcwMDsiPicrdFsxXSsnPC9sYWJlbD48ZGl2IHN0eWxlPSJmb250LXNpemU6MC43' +
  'NHJlbTtjb2xvcjojOGE5MzhlO21hcmdpbi1ib3R0b206NHB4OyI+Jyt0WzJdKyc8L2Rpdj48dGV4dGFyZWEgY2xhc3M9InRwbCIg' +
  'ZGF0YS1rPSInK3RbMF0rJyIgcm93cz0iNiIgcGxhY2Vob2xkZXI9IiI+Jyt0WzNdLnJlcGxhY2UoLyYvZywnJmFtcDsnKS5yZXBs' +
  'YWNlKC88L2csJyZsdDsnKSsnPC90ZXh0YXJlYT4nKS5qb2luKCcnKTsKY29uc3QgdiA9IGlkID0+ICgkKGlkKS52YWx1ZSB8fCAn' +
  'JykudHJpbSgpOwokKCdmJykuYWRkRXZlbnRMaXN0ZW5lcignc3VibWl0JywgYXN5bmMgZT0+ewogIGUucHJldmVudERlZmF1bHQo' +
  'KTsKICBjb25zdCBtc2cgPSAkKCdtc2cnKTsgbXNnLnN0eWxlLmNvbG9yID0gJyM1YjY4NjMnOwogIGlmKCF2KCduYW1lJykgJiYg' +
  'IXYoJ25hbWVfYXInKSl7IG1zZy5zdHlsZS5jb2xvciA9ICcjYTMzJzsgbXNnLnRleHRDb250ZW50ID0gJ1BsZWFzZSB3cml0ZSB0' +
  'aGUgY2xpbmljIG5hbWUuJzsgcmV0dXJuOyB9CiAgY29uc3QgdGVhbSA9IEFycmF5LmZyb20oZG9jdW1lbnQucXVlcnlTZWxlY3Rv' +
  'ckFsbCgnI3RlYW0gLnJvdycpKS5tYXAocj0+KHsKICAgIG5hbWU6IHIucXVlcnlTZWxlY3RvcignLnRfbmFtZScpLnZhbHVlLnRy' +
  'aW0oKSwgcm9sZTogci5xdWVyeVNlbGVjdG9yKCcudF9yb2xlJykudmFsdWUsIGVtYWlsOiByLnF1ZXJ5U2VsZWN0b3IoJy50X2Vt' +
  'YWlsJykudmFsdWUudHJpbSgpLAogICAgcGF5OiByLnF1ZXJ5U2VsZWN0b3IoJy50X3BheScpLnZhbHVlLCBwZXJjZW50OiByLnF1' +
  'ZXJ5U2VsZWN0b3IoJy50X3BjdCcpLnZhbHVlLCBmaXhlZDogci5xdWVyeVNlbGVjdG9yKCcudF9maXhlZCcpLnZhbHVlLCBwZXJf' +
  'c2Vzc2lvbjogci5xdWVyeVNlbGVjdG9yKCcudF9yYXRlJykudmFsdWUsCiAgICBkYXlzOiBBcnJheS5mcm9tKHIucXVlcnlTZWxl' +
  'Y3RvckFsbCgnLnRfZGF5OmNoZWNrZWQnKSkubWFwKGM9PmMudmFsdWUpLCBzaGlmdF9mcm9tOiByLnF1ZXJ5U2VsZWN0b3IoJy50' +
  'X2Zyb20nKS52YWx1ZSwgc2hpZnRfdG86IHIucXVlcnlTZWxlY3RvcignLnRfdG8nKS52YWx1ZQogIH0pKS5maWx0ZXIoeD0+IHgu' +
  'bmFtZSk7CiAgY29uc3Qgc2VydmljZXMgPSBBcnJheS5mcm9tKGRvY3VtZW50LnF1ZXJ5U2VsZWN0b3JBbGwoJyNzZXJ2aWNlcyAu' +
  'cm93JykpLm1hcChyPT4oeyBuYW1lOiByLnF1ZXJ5U2VsZWN0b3IoJy5zX25hbWUnKS52YWx1ZS50cmltKCksIHByaWNlOiByLnF1' +
  'ZXJ5U2VsZWN0b3IoJy5zX3ByaWNlJykudmFsdWUsIHR5cGU6IHIucXVlcnlTZWxlY3RvcignLnNfdHlwZScpLnZhbHVlLCBzZXNz' +
  'aW9uczogci5xdWVyeVNlbGVjdG9yKCcuc19jb3VudCcpLnZhbHVlIH0pKS5maWx0ZXIoeD0+IHgubmFtZSk7CiAgY29uc3QgZml4' +
  'ZWQgPSBBcnJheS5mcm9tKGRvY3VtZW50LnF1ZXJ5U2VsZWN0b3JBbGwoJyNmaXhlZCAucm93JykpLm1hcChyPT4oeyBuYW1lOiBy' +
  'LnF1ZXJ5U2VsZWN0b3IoJy5mX25hbWUnKS52YWx1ZS50cmltKCksIGFtb3VudDogci5xdWVyeVNlbGVjdG9yKCcuZl9hbW91bnQn' +
  'KS52YWx1ZSB9KSkuZmlsdGVyKHg9PiB4Lm5hbWUpOwogIGNvbnN0IGJvZHkgPSB7IHdlYnNpdGU6IHYoJ3dlYnNpdGUnKSwgY2xp' +
  'bmljX25hbWU6IHYoJ25hbWUnKSB8fCB2KCduYW1lX2FyJyksIGRhdGE6IHsKICAgIG93bmVyOiB7IG5hbWU6IHYoJ293bmVyX25h' +
  'bWUnKSwgcGhvbmU6IHYoJ293bmVyX3Bob25lJyksIGVtYWlsOiB2KCdvd25lcl9lbWFpbCcpIH0sCiAgICBjbGluaWM6IHsgbmFt' +
  'ZTogdignbmFtZScpLCBuYW1lX2FyOiB2KCduYW1lX2FyJyksIHRhZ2xpbmU6IHYoJ3RhZ2xpbmUnKSwgYWRkcmVzczogdignYWRk' +
  'cmVzcycpLCBhZGRyZXNzX2FyOiB2KCdhZGRyZXNzX2FyJyksIG1hcF91cmw6IHYoJ21hcF91cmwnKSwgcGhvbmU6IHYoJ3Bob25l' +
  'JyksIHNvY2lhbDogdignc29jaWFsJyksIHJldmlld191cmw6IHYoJ3Jldmlld191cmwnKSwgbG9nbzogaW1ncy5sb2dvLCBzdGFt' +
  'cDogaW1ncy5zdGFtcCB9LAogICAgcGF5bWVudHM6IHsgY2FzaDogJCgncGF5X2Nhc2gnKS5jaGVja2VkLCBpbnN0YXBheTogJCgn' +
  'cGF5X2luc3RhJykuY2hlY2tlZCwgaW5zdGFwYXlfdXJsOiB2KCdpbnN0YXBheV91cmwnKSwgaW5zdGFwYXlfaGFuZGxlOiB2KCdp' +
  'bnN0YXBheV9oYW5kbGUnKSB9LAogICAgdGVhbSwgc2VydmljZXMsIHBhY2thZ2VfdmFsaWRpdHk6IHYoJ3BhY2thZ2VfdmFsaWRp' +
  'dHknKSwgY2FuY2VsX3BvbGljeTogdignY2FuY2VsX3BvbGljeScpLCBmaXhlZF9jb3N0czogZml4ZWQsCiAgICBib29raW5nOiB7' +
  'IG9ubGluZTogJCgnb25saW5lX2Jvb2tpbmcnKS52YWx1ZSwgc2xvdF9taW51dGVzOiB2KCdzbG90X21pbnV0ZXMnKSwgb3Blbmlu' +
  'Zzogdignb3BlbmluZycpLCBkaXJlY3Rpb25zOiB2KCdkaXJlY3Rpb25zJykgfSwKICAgIHRlbXBsYXRlczogT2JqZWN0LmZyb21F' +
  'bnRyaWVzKEFycmF5LmZyb20oZG9jdW1lbnQucXVlcnlTZWxlY3RvckFsbCgnLnRwbCcpKS5tYXAodD0+W3QuZGF0YXNldC5rLCB0' +
  'LnZhbHVlLnRyaW0oKV0pLmZpbHRlcih4PT54WzFdKSksCiAgICBhY2NvdW50czogeyBzdWJkb21haW46IHYoJ3N1YmRvbWFpbicp' +
  'LCBub3Rlczogdignbm90ZXMnKSB9IH0gfTsKICAkKCdnbycpLmRpc2FibGVkID0gdHJ1ZTsgbXNnLnRleHRDb250ZW50ID0gJ1Nl' +
  'bmRpbmfigKYnOwogIHRyeXsKICAgIGNvbnN0IHIgPSBhd2FpdCBmZXRjaCgnL2FwaS9vbmJvYXJkJywgeyBtZXRob2Q6J1BPU1Qn' +
  'LCBoZWFkZXJzOnsnQ29udGVudC1UeXBlJzonYXBwbGljYXRpb24vanNvbid9LCBib2R5OiBKU09OLnN0cmluZ2lmeShib2R5KSB9' +
  'KTsKICAgIGNvbnN0IGQgPSBhd2FpdCByLmpzb24oKS5jYXRjaCgoKT0+KHt9KSk7CiAgICBpZighci5vaykgdGhyb3cgbmV3IEVy' +
  'cm9yKGQuZXJyb3IgfHwgJ1NlcnZlciBlcnJvciAnICsgci5zdGF0dXMpOwogICAgJCgnZicpLnN0eWxlLmRpc3BsYXkgPSAnbm9u' +
  'ZSc7CiAgICBkb2N1bWVudC5xdWVyeVNlbGVjdG9yKCcuc3ViJykuaW5uZXJIVE1MID0gJzxiIHN0eWxlPSJjb2xvcjojMWY1YzU2' +
  'O2ZvbnQtc2l6ZToxLjA1cmVtOyI+VGhhbmsgeW91ISDinJMgV2UgcmVjZWl2ZWQgeW91ciBkZXRhaWxzLjwvYj48YnI+2LTZg9ix' +
  '2KfZiyEg2YjYtdmE2KrZhtinINio2YrYp9mG2KfYqtmDINmI2YfZhtiq2YjYp9i12YQg2YXYudin2YMg2YLYsdmK2KguJzsKICAg' +
  'IHdpbmRvdy5zY3JvbGxUbygwLDApOwogIH1jYXRjaChlcnIpeyBtc2cuc3R5bGUuY29sb3IgPSAnI2EzMyc7IG1zZy50ZXh0Q29u' +
  'dGVudCA9ICdDb3VsZCBub3Qgc2VuZDogJyArIChlcnIubWVzc2FnZSB8fCBlcnIpOyAkKCdnbycpLmRpc2FibGVkID0gZmFsc2U7' +
  'IH0KfSk7Cjwvc2NyaXB0Pgo8L2JvZHk+CjwvaHRtbD4K',
  'base64').toString('utf8');
const cleanOnb = (v, d = 0) => {
  if (typeof v === 'string') return v.slice(0, v.startsWith('data:image/') ? 400000 : 2000);
  if (typeof v === 'number' || typeof v === 'boolean') return v;
  if (Array.isArray(v)) return v.slice(0, 40).map((x) => cleanOnb(x, d + 1));
  if (v && typeof v === 'object' && d < 4) return Object.fromEntries(Object.entries(v).slice(0, 60).map(([k, x]) => [String(k).slice(0, 40), cleanOnb(x, d + 1)]));
  return '';
};
app.get('/onboard', (req, res) => {
  res.set({ 'Content-Type': 'text/html; charset=utf-8', 'X-Robots-Tag': 'noindex, nofollow', 'Cache-Control': 'no-store' }).send(ONBOARD_PAGE);
});
app.post('/api/onboard', async (req, res) => {
  try {
    const ip = String(req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
    if (bookRateLimited(ip, 'onboard', 8, 3600000)) return res.status(429).json({ error: 'Too many submissions. Please try again later.' });
    const b = req.body || {};
    if (b.website) return res.json({ ok: true });
    const data = cleanOnb(b.data);
    const name = clinicText(b.clinic_name, 120).trim();
    if (!name || !data || typeof data !== 'object') return res.status(400).json({ error: 'Please write the clinic name.' });
    const r = await fetch(`${SUPABASE_URL}/rest/v1/clinic_onboarding`, { method: 'POST', headers: { ...bookHeaders(), 'Content-Type': 'application/json' }, body: JSON.stringify({ clinic_name: name, data }) });
    if (!r.ok) { console.error('onboard insert failed', r.status, await r.text().catch(() => '')); return res.status(500).json({ error: 'Could not save right now. Please try again later.' }); }
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});
app.get('/api/onboard', requireOwnerDoctor, async (req, res) => {
  try {
    const r = await fetch(`${SUPABASE_URL}/rest/v1/clinic_onboarding?order=created_at.desc&limit=30`, { headers: bookHeaders() });
    const txt = await r.text();
    if (!r.ok) return res.status(500).json({ error: 'Database error (did you run the onboarding SQL?)' });
    res.set('Cache-Control', 'no-store').type('application/json').send(txt);
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});
app.delete('/api/onboard/:id', requireOwnerDoctor, async (req, res) => {
  try { await fetch(`${SUPABASE_URL}/rest/v1/clinic_onboarding?id=eq.${encodeURIComponent(req.params.id)}`, { method: 'DELETE', headers: bookHeaders() }); res.json({ ok: true }); }
  catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

// ---- Fixed monthly costs (rent, doorman...) -> added to Expenses once per month ----
// Each cost is added as a normal expense dated the LAST DAY of the month, described "Fixed: <name>".
// Payroll, Net Cash and Net InstaPay then count it like any other expense. Adding twice is safe.
async function applyFixedCostsForMonth(ym, createdBy) {
  const c = await getClinicConfig(true);
  const list = c.fixed_costs || [];
  if (!list.length || !/^\d{4}-\d{2}$/.test(ym)) return { added: 0, total: list.length };
  const [y, m] = ym.split('-').map(Number);
  const first = `${ym}-01`, lastDay = new Date(Date.UTC(y, m, 0)).getUTCDate();
  const last = `${ym}-${String(lastDay).padStart(2, '0')}`;
  const h = { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`, 'Content-Type': 'application/json' };
  const er = await fetch(`${SUPABASE_URL}/rest/v1/expenses?select=description&expense_date=gte.${first}&expense_date=lte.${last}&description=like.Fixed:*`, { headers: h });
  const existing = new Set((await er.json().catch(() => [])).map((e) => String(e.description || '').toLowerCase()));
  let added = 0;
  for (const f of list) {
    const desc = `Fixed: ${f.name}`;
    if (existing.has(desc.toLowerCase())) continue;
    const ir = await fetch(`${SUPABASE_URL}/rest/v1/expenses`, { method: 'POST', headers: h, body: JSON.stringify({ description: desc, amount: f.amount, expense_date: last, payment_method: f.method === 'instapay' ? 'instapay' : 'cash', created_by: createdBy || 'Fixed costs (auto)' }) });
    if (ir.ok) added++; else console.error('fixed cost insert failed', ir.status, await ir.text().catch(() => ''));
  }
  return { added, total: list.length };
}
app.post('/api/fixed-costs/apply', requireFinanceAccess, async (req, res) => {
  try {
    const ym = String((req.body && req.body.month) || '').slice(0, 7);
    if (!/^\d{4}-\d{2}$/.test(ym)) return res.status(400).json({ error: 'Bad month.' });
    res.json(await applyFixedCostsForMonth(ym, req.doctor.name || req.doctor.email));
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});
async function autoFixedCosts() {
  try {
    const today = cairoTodayYmd();
    const tomorrow = new Date(Date.parse(today + 'T00:00:00Z') + 86400000).toISOString().slice(0, 10);
    if (tomorrow.slice(0, 7) !== today.slice(0, 7)) await applyFixedCostsForMonth(today.slice(0, 7), 'Fixed costs (auto)');
  } catch (e) { console.error('auto fixed costs failed', e.message); }
}
if (SUPABASE_URL && SUPABASE_SERVICE_KEY) { setTimeout(autoFixedCosts, 120000); setInterval(autoFixedCosts, 3 * 3600000); }

// Keep-alive: a tiny daily database request so a free Supabase project is never paused for inactivity
if (SUPABASE_URL && SUPABASE_SERVICE_KEY) {
  const dbKeepAlive = () => fetch(`${SUPABASE_URL}/rest/v1/booking_settings?select=id&limit=1`, { headers: bookHeaders() }).catch(() => {});
  setTimeout(dbKeepAlive, 60000);
  setInterval(dbKeepAlive, 12 * 3600000);
}

app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});
