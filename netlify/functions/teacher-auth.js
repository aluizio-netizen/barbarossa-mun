const crypto = require('crypto');

const ALLOWED_ORIGINS = [
  'http://localhost:8888',
  'http://localhost:3999',
  'https://barbarossa-urano.netlify.app'
];

function corsHeaders(origin) {
  const allow = ALLOWED_ORIGINS.includes(origin) ? origin : '';
  return {
    'Access-Control-Allow-Origin': allow,
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Vary': 'Origin'
  };
}

function json(statusCode, body, origin) {
  return {
    statusCode,
    headers: { 'Content-Type': 'application/json', ...corsHeaders(origin) },
    body: JSON.stringify(body)
  };
}

function constantTimeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const ba = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
}

exports.handler = async (event) => {
  const origin = event.headers && (event.headers.origin || event.headers.Origin) || '';

  if (event.httpMethod === 'OPTIONS') {
    return { statusCode: 204, headers: corsHeaders(origin), body: '' };
  }
  if (event.httpMethod !== 'POST') {
    return json(405, { error: 'method_not_allowed' }, origin);
  }
  if (!ALLOWED_ORIGINS.includes(origin)) {
    return json(403, { error: 'origin_not_allowed' }, origin);
  }

  const teacherPassword = (process.env.TEACHER_PASSWORD || '').trim();
  if (!teacherPassword) {
    return json(500, { error: 'server_misconfigured' }, origin);
  }

  const auth = (event.headers.authorization || event.headers.Authorization || '').trim();
  const m = auth.match(/^Bearer\s+(.+)$/i);
  if (!m || !constantTimeEqual(m[1], teacherPassword)) {
    return json(401, { error: 'unauthorized' }, origin);
  }

  return json(200, { ok: true }, origin);
};
