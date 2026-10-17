// Server-side proxy: the Airtable token and session secret live ONLY in Netlify
// environment variables. The browser never sees them.
const crypto = require('crypto');

const TOKEN  = process.env.AIRTABLE_TOKEN;
const BASE   = process.env.AIRTABLE_BASE_ID;
const SECRET = process.env.SESSION_SECRET;
const TABLES = ['Users', 'Leads', 'Comments', 'Personal'];
const API = 'https://api.airtable.com/v0/';

const json = (code, obj) => ({
  statusCode: code,
  headers: {'Content-Type': 'application/json', 'Cache-Control': 'no-store'},
  body: JSON.stringify(obj)
});

function sign(payload){
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig = crypto.createHmac('sha256', SECRET).update(body).digest('base64url');
  return body + '.' + sig;
}
function verify(token){
  if (!token || token.indexOf('.') < 0) return null;
  const [body, sig] = token.split('.');
  const good = crypto.createHmac('sha256', SECRET).update(body).digest('base64url');
  if (sig.length !== good.length || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(good))) return null;
  const p = JSON.parse(Buffer.from(body, 'base64url').toString());
  if (!p.exp || p.exp < Date.now()) return null;
  return p;
}
async function airtable(method, path, body){
  const res = await fetch(API + BASE + '/' + path, {
    method,
    headers: {'Authorization': 'Bearer ' + TOKEN, 'Content-Type': 'application/json'},
    body: body ? JSON.stringify(body) : undefined
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error((data.error && (data.error.message || data.error.type)) || ('HTTP ' + res.status));
  return data;
}
async function allUsers(){
  let out = [], offset = '';
  do {
    const d = await airtable('GET', 'Users?pageSize=100' + (offset ? '&offset=' + offset : ''));
    out = out.concat(d.records || []);
    offset = d.offset || '';
  } while (offset);
  return out;
}

exports.handler = async (event) => {
  if (event.httpMethod !== 'POST') return json(405, {error: 'Method not allowed'});
  if (!TOKEN || !BASE || !SECRET) return json(500, {error: 'Server not set up: environment variables are missing'});

  let req;
  try { req = JSON.parse(event.body || '{}'); } catch (e) { return json(400, {error: 'Bad request'}); }

  try {
    // Public: list account names for the login dropdown (no passwords)
    if (req.action === 'accounts') {
      const recs = await allUsers();
      return json(200, {accounts: recs.map(r => String(r.fields.Username || '').trim())
        .filter(n => n && n.toLowerCase() !== 'username')});
    }

    // Public: check password, return a session
    if (req.action === 'login') {
      const name = String(req.username || '').trim(), pass = String(req.password || '');
      const recs = await allUsers();
      const r = recs.find(x => String(x.fields.Username || '').trim() === name && String(x.fields.Password || '') === pass);
      if (!r) return json(401, {error: 'Wrong password for this account'});
      const user = {id: r.id, username: name, isAdmin: r.fields.IsAdmin === true};
      return json(200, {session: sign({u: r.id, exp: Date.now() + 12 * 3600 * 1000}), user});
    }

    // Everything below requires a valid session
    const s = verify(req.session);
    if (!s) return json(401, {error: 'Session expired. Please log in again.'});
    const self = await airtable('GET', 'Users/' + s.u);
    const isAdmin = self.fields.IsAdmin === true;

    if (req.action === 'changePassword') {
      if (String(self.fields.Password || '') !== String(req.oldPassword || '')) return json(400, {error: 'Current password is wrong'});
      const np = String(req.newPassword || '');
      if (np.length < 4) return json(400, {error: 'New password must be at least 4 characters'});
      await airtable('PATCH', 'Users', {typecast: true, records: [{id: s.u, fields: {Password: np}}]});
      return json(200, {ok: true});
    }

    if (req.action === 'airtable') {
      const method = String(req.method || 'GET').toUpperCase();
      const [pathPart, query = ''] = String(req.path || '').split('?');
      const [table, recId = ''] = pathPart.split('/');

      if (!TABLES.includes(table)) return json(400, {error: 'Table not allowed'});
      if (!['GET', 'POST', 'PATCH', 'DELETE'].includes(method)) return json(400, {error: 'Method not allowed'});
      if (recId && !/^rec[A-Za-z0-9]{10,}$/.test(recId)) return json(400, {error: 'Bad record id'});
      if (query && !/^(pageSize=\d{1,3}|offset=[\w./-]+)(&(pageSize=\d{1,3}|offset=[\w./-]+))*$/.test(query))
        return json(400, {error: 'Bad query'});

      // Non-admins may only change their OWN password in the Users table
      if (table === 'Users' && method !== 'GET' && !isAdmin) {
        const okRecords = method === 'PATCH' && Array.isArray(req.body && req.body.records) &&
          req.body.records.every(r => r.id === s.u && Object.keys(r.fields || {}).every(k => k === 'Password'));
        if (!okRecords) return json(403, {error: 'Only an admin can change accounts'});
      }

      const url = table + (recId ? '/' + recId : '') + (query ? '?' + query : '');
      const data = await airtable(method, url, method === 'GET' ? undefined : req.body);

      // Never send passwords to the browser
      if (table === 'Users') {
        if (Array.isArray(data.records)) data.records.forEach(r => { if (r.fields) delete r.fields.Password; });
        if (data.fields) delete data.fields.Password;
      }
      return json(200, data);
    }

    return json(400, {error: 'Unknown action'});
  } catch (e) {
    return json(400, {error: e.message});
  }
};
