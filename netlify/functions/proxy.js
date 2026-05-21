const crypto = require('crypto');

const ALLOWED_MODELS = ['claude-haiku-4-5-20251001'];
const MAX_TOKENS_CAP = 2000;
const MAX_BODY_BYTES = 32 * 1024;

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

  const appPassword = (process.env.APP_PASSWORD || '').trim();
  const anthropicKey = (process.env.ANTHROPIC_API_KEY || '').trim();
  if (!appPassword || !anthropicKey) {
    return json(500, { error: 'server_misconfigured' }, origin);
  }

  const auth = (event.headers.authorization || event.headers.Authorization || '').trim();
  const m = auth.match(/^Bearer\s+(.+)$/i);
  if (!m || !constantTimeEqual(m[1], appPassword)) {
    return json(401, { error: 'unauthorized' }, origin);
  }

  const raw = event.body || '';
  if (Buffer.byteLength(raw, 'utf8') > MAX_BODY_BYTES) {
    return json(413, { error: 'payload_too_large' }, origin);
  }

  let payload;
  try { payload = JSON.parse(raw); }
  catch { return json(400, { error: 'invalid_json' }, origin); }

  const model = ALLOWED_MODELS.includes(payload.model) ? payload.model : ALLOWED_MODELS[0];
  let max_tokens = Number.isFinite(payload.max_tokens) ? payload.max_tokens : 1000;
  if (max_tokens < 1) max_tokens = 1;
  if (max_tokens > MAX_TOKENS_CAP) max_tokens = MAX_TOKENS_CAP;

  if (typeof payload.system !== 'string' || !Array.isArray(payload.messages)) {
    return json(400, { error: 'invalid_payload' }, origin);
  }

  let upstream;
  try {
    upstream = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'anthropic-version': '2023-06-01',
        'x-api-key': anthropicKey
      },
      body: JSON.stringify({ model, max_tokens, system: payload.system, messages: payload.messages })
    });
  } catch {
    return json(502, { error: 'upstream_unreachable' }, origin);
  }

  if (!upstream.ok) {
    return json(upstream.status, { error: 'upstream_error', status: upstream.status }, origin);
  }

  const data = await upstream.json();
  return json(200, data, origin);
};
