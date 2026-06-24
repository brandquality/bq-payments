/**
 * Cloudflare Pages Function: POST /api/stripe-webhook
 *
 * Security gateway in front of n8n. Stripe should send its webhook here (NOT
 * directly to n8n). This function:
 *   1. Verifies the Stripe-Signature header (HMAC-SHA256) against the raw body
 *      using STRIPE_WEBHOOK_SECRET. Forged / replayed events are rejected.
 *   2. Only on success, forwards the verified event to n8n — adding a private
 *      shared token header so n8n can reject anything that didn't come through
 *      this verified gateway.
 *
 * Environment variables (Cloudflare Pages -> Settings -> Environment variables):
 *   STRIPE_WEBHOOK_SECRET  -> whsec_...  (from the Stripe webhook endpoint)
 *   N8N_PROXY_TOKEN        -> long random string (same value set on the n8n
 *                             webhook's Header Auth credential). Optional: if
 *                             unset, the header simply isn't sent.
 *
 * Point the Stripe webhook endpoint URL at:
 *   https://payments.brandquality.com/api/stripe-webhook
 */

const N8N_WEBHOOK = 'https://n8n.brandquality.com/webhook/stripe-invoice-payment';
const TOLERANCE_SECONDS = 300; // reject events older than 5 minutes (replay guard)

function toHex(buffer) {
  return [...new Uint8Array(buffer)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

function timingSafeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  let mismatch = 0;
  for (let i = 0; i < a.length; i++) mismatch |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return mismatch === 0;
}

async function verifyStripeSignature(rawBody, sigHeader, secret) {
  if (!rawBody || !sigHeader || !secret) return false;

  // Header format: "t=timestamp,v1=signature[,v1=...]"
  let timestamp = '';
  const v1Signatures = [];
  for (const part of sigHeader.split(',')) {
    const eq = part.indexOf('=');
    if (eq === -1) continue;
    const key = part.slice(0, eq).trim();
    const val = part.slice(eq + 1).trim();
    if (key === 't') timestamp = val;
    else if (key === 'v1') v1Signatures.push(val);
  }
  if (!timestamp || v1Signatures.length === 0) return false;

  // Replay protection.
  const now = Math.floor(Date.now() / 1000);
  if (!Number.isFinite(Number(timestamp)) || Math.abs(now - Number(timestamp)) > TOLERANCE_SECONDS) {
    return false;
  }

  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw',
    enc.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const signatureBuf = await crypto.subtle.sign('HMAC', key, enc.encode(`${timestamp}.${rawBody}`));
  const expected = toHex(signatureBuf);

  // Accept if any provided v1 signature matches (Stripe may send more than one).
  return v1Signatures.some((sig) => timingSafeEqual(expected, sig));
}

export async function onRequestPost(context) {
  const { request, env } = context;
  const secret = env.STRIPE_WEBHOOK_SECRET;
  const sigHeader = request.headers.get('stripe-signature');
  const rawBody = await request.text();

  const valid = await verifyStripeSignature(rawBody, sigHeader, secret);
  if (!valid) {
    return new Response('Invalid signature', { status: 400 });
  }

  // Signature verified — forward the verified event to n8n.
  const headers = { 'Content-Type': 'application/json' };
  if (env.N8N_PROXY_TOKEN) headers['x-bq-proxy-token'] = env.N8N_PROXY_TOKEN;

  try {
    const res = await fetch(N8N_WEBHOOK, { method: 'POST', headers, body: rawBody });
    if (!res.ok) return new Response('Upstream error', { status: 502 });
  } catch (err) {
    // n8n unreachable — tell Stripe to retry later.
    return new Response('Upstream error', { status: 502 });
  }

  return new Response(JSON.stringify({ received: true }), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  });
}

// Stripe only POSTs; anything else gets a simple OK so health checks don't error.
export async function onRequestGet() {
  return new Response('OK', { status: 200 });
}
