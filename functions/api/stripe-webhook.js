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
const N8N_RENEWAL_WEBHOOK = 'https://n8n.brandquality.com/webhook/recurring-renewal';
const TOLERANCE_SECONDS = 300; // reject events older than 5 minutes (replay guard)

// Annual recurring price (Stripe, live). Override via env if it ever changes.
const DEFAULT_RECURRING_PRICE_ID = 'price_1Twv3oAAOsKG8k1CiUH5QGsN';

// Turn a YYYY-MM-DD renewal date into a Stripe trial_end timestamp. Stripe
// requires trial_end to be at least 48 hours out; anything sooner (or missing)
// falls back to one year from now so a bad date can't cause an instant charge.
function resolveTrialEnd(renewalDate) {
  const now = Math.floor(Date.now() / 1000);
  const floor = now + 60 * 60 * 72; // 72h cushion
  let ts = 0;
  if (renewalDate && /^\d{4}-\d{2}-\d{2}$/.test(renewalDate)) {
    ts = Math.floor(new Date(renewalDate + 'T12:00:00Z').getTime() / 1000);
  }
  if (!ts || ts < floor) ts = now + 60 * 60 * 24 * 365;
  return ts;
}

// Stripe product that holds every recurring plan price.
const RECURRING_PRODUCT_ID = 'prod_UwohmrNziaaUIT';

// Resolve the Stripe price from what the INVOICE says the plan costs, creating
// it on first use. The price id used to be hardcoded, so changing the plan
// price meant editing and redeploying this file, and any invoice quoting a
// different amount would still have been billed the old one. Now the Notion
// invoice is the source of truth and any amount or interval works untouched.
// Falls back to the configured price id if anything goes wrong, so a Stripe
// hiccup can never leave a paid invoice without a subscription.
async function resolveRecurringPrice(secretKey, md, fallbackPriceId) {
  try {
    const dollars = Number(md.bq_recurring_amount);
    if (!dollars || dollars <= 0) return fallbackPriceId;
    const unitAmount = Math.round(dollars * 100);
    const interval =
      String(md.bq_recurring_interval || 'Annual').toLowerCase() === 'monthly' ? 'month' : 'year';

    // Reuse an existing matching price so we don't litter Stripe with duplicates.
    const listRes = await fetch(
      'https://api.stripe.com/v1/prices?limit=100&active=true&currency=usd&product=' +
        encodeURIComponent(RECURRING_PRODUCT_ID),
      { headers: { Authorization: 'Bearer ' + secretKey } }
    );
    const list = await listRes.json();
    if (listRes.ok && Array.isArray(list.data)) {
      const hit = list.data.find(
        (p) =>
          p.unit_amount === unitAmount &&
          p.recurring &&
          p.recurring.interval === interval &&
          p.recurring.interval_count === 1
      );
      if (hit) return hit.id;
    }

    const pp = new URLSearchParams();
    pp.set('product', RECURRING_PRODUCT_ID);
    pp.set('currency', 'usd');
    pp.set('unit_amount', String(unitAmount));
    pp.set('recurring[interval]', interval);
    pp.set('nickname', 'BQ Recurring \u2014 $' + dollars + '/' + interval);
    pp.set('metadata[bq_service]', 'recurring');
    const createRes = await fetch('https://api.stripe.com/v1/prices', {
      method: 'POST',
      headers: {
        Authorization: 'Bearer ' + secretKey,
        'Content-Type': 'application/x-www-form-urlencoded',
        // Same amount+interval must never create two prices on retry.
        'Idempotency-Key': 'bqprice_' + unitAmount + '_' + interval,
      },
      body: pp.toString(),
    });
    const created = await createRes.json();
    return createRes.ok && created.id ? created.id : fallbackPriceId;
  } catch (err) {
    return fallbackPriceId;
  }
}

// Create the recurring plan subscription after the client's balance payment
// succeeds. Year one is covered by the trial, so this schedules the first real
// charge rather than taking money now. Best-effort: a failure here must never
// fail the webhook, or Stripe will retry a payment that already succeeded.
async function createRecurringSubscription(secretKey, priceId, pi) {
  try {
    const customer = pi.customer;
    const paymentMethod = pi.payment_method;
    if (!customer || !paymentMethod) return '';

    const md = pi.metadata || {};
    const sp = new URLSearchParams();
    sp.set('customer', customer);
    sp.set('items[0][price]', priceId);
    sp.set('default_payment_method', paymentMethod);
    sp.set('trial_end', String(resolveTrialEnd(md.bq_renewal_date)));
    sp.set('proration_behavior', 'none');
    sp.set('metadata[bq_service]', 'recurring');
    if (md.invoiceId) sp.set('metadata[invoiceId]', md.invoiceId);
    if (md.invoiceNum) sp.set('metadata[invoiceNum]', md.invoiceNum);
    if (pi.description) sp.set('metadata[projectName]', pi.description);

    const res = await fetch('https://api.stripe.com/v1/subscriptions', {
      method: 'POST',
      headers: {
        Authorization: 'Bearer ' + secretKey,
        'Content-Type': 'application/x-www-form-urlencoded',
        // Same PaymentIntent must never produce two subscriptions on retry.
        'Idempotency-Key': 'bqrecurring_' + pi.id,
      },
      body: sp.toString(),
    });
    const sub = await res.json();
    return res.ok && sub.id ? sub.id : '';
  } catch (err) {
    return '';
  }
}

// The webhook endpoint runs an older Stripe API version that does not put the
// subscription's metadata on invoice events. That metadata carries the Notion
// invoice id, which is the only link back to the record, so fetch it directly.
async function fetchSubscriptionMetadata(secretKey, subscriptionId) {
  if (!secretKey || !subscriptionId) return null;
  try {
    const res = await fetch('https://api.stripe.com/v1/subscriptions/' + subscriptionId, {
      headers: { Authorization: 'Bearer ' + secretKey },
    });
    if (!res.ok) return null;
    const sub = await res.json();
    return sub && sub.metadata ? sub.metadata : null;
  } catch (err) {
    return null;
  }
}

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

  // Inspect the verified event so recurring plans get set up and renewals
  // route to their own workflow. Parsing failures fall through to the original
  // behavior: forward the raw body untouched.
  let target = N8N_WEBHOOK;
  let body = rawBody;
  try {
    const evt = JSON.parse(rawBody);
    const obj = evt?.data?.object ?? {};
    const md = obj.metadata ?? {};

    if (evt.type === 'payment_intent.succeeded' && md.bq_recurring === 'true') {
      const fallbackPriceId = env.STRIPE_RECURRING_PRICE_ID || DEFAULT_RECURRING_PRICE_ID;
      const priceId = await resolveRecurringPrice(env.STRIPE_SECRET_KEY, md, fallbackPriceId);
      const subId = await createRecurringSubscription(env.STRIPE_SECRET_KEY, priceId, obj);
      if (subId) {
        // Hand the subscription id to n8n so it lands on the Notion invoice.
        // Safe to mutate: the signature was already verified above.
        evt.data.object.metadata = { ...md, bq_subscription_id: subId };
        body = JSON.stringify(evt);
      }
    } else if (evt.type === 'invoice.payment_succeeded' || evt.type === 'invoice.payment_failed') {
      const subId = obj.subscription || obj.parent?.subscription_details?.subscription || '';
      if (subId) {
        target = N8N_RENEWAL_WEBHOOK;
        const subMd = await fetchSubscriptionMetadata(env.STRIPE_SECRET_KEY, subId);
        if (subMd) {
          // Hand n8n the link back to the Notion invoice. Safe to mutate: the
          // signature was already verified above.
          evt.data.object.bq_subscription_metadata = subMd;
          body = JSON.stringify(evt);
        }
      }
    }
  } catch (err) {
    // fall through with the raw body
  }

  try {
    const res = await fetch(target, { method: 'POST', headers, body });
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
