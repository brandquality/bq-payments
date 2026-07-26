/**
 * Cloudflare Pages Function: GET /api/invoice-lookup?inv=<invoice number>
 *
 * Same-origin proxy in front of the n8n invoice lookup.
 *
 * WHY THIS EXISTS
 * The payment page used to call n8n's lookup webhook directly. That webhook is
 * public, takes a short sequential invoice number, and returned the client's
 * organization name, the contact's email address, the full CC list, the contract
 * total, the deposit, the balance, every line item and price, the renewal terms
 * and the Stripe subscription id. Anyone who could count could harvest the
 * client list, the pipeline and the price book. CORS did not prevent this —
 * CORS only restrains browsers, and a script ignores it entirely.
 *
 * This proxy does two things:
 *   1. Attaches the private gateway token, so the n8n webhook can require auth
 *      and stop answering the open internet.
 *   2. Strips the fields the payment page never reads before the response ever
 *      reaches a browser.
 *
 * Environment variable (Cloudflare Pages -> Settings -> Environment variables):
 *   N8N_PROXY_TOKEN -> same value as the n8n Header Auth credential
 *
 * DEPLOY ORDER MATTERS. Ship this file (and the index.html change that points at
 * it) FIRST and confirm the payment page still renders. Only then add Header
 * Auth to the n8n `invoice-lookup` webhook. Doing it the other way round takes
 * the payment page down.
 */

const N8N_LOOKUP = 'https://n8n.brandquality.com/webhook/invoice-lookup';

// Verified against index.html: the page reads clientName and invoiceId, and
// never touches any of these. Contact emails in particular have no business on
// a surface keyed by a guessable invoice number.
const STRIP = ['contactEmail', 'ccEmails', 'subscriptionId', 'recurringStatus', 'primaryContact'];

const CORS = {
  'Content-Type': 'application/json',
  'Access-Control-Allow-Origin': 'https://payments.brandquality.com',
  'Access-Control-Allow-Methods': 'GET, OPTIONS',
  // A stale lookup previously served pre-edit invoice data. Never cache this.
  'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0',
  'Pragma': 'no-cache',
};

export async function onRequestGet(context) {
  const { request, env } = context;

  let inv = '';
  try {
    inv = (new URL(request.url).searchParams.get('inv') || '').trim();
  } catch (err) {
    inv = '';
  }

  if (!inv) {
    return new Response(JSON.stringify({ error: 'Missing invoice number.' }), { status: 400, headers: CORS });
  }

  try {
    const headers = {};
    if (env.N8N_PROXY_TOKEN) headers['x-bq-proxy-token'] = env.N8N_PROXY_TOKEN;

    const upstream = await fetch(N8N_LOOKUP + '?inv=' + encodeURIComponent(inv), {
      headers,
      // Belt and braces alongside the upstream no-store headers.
      cache: 'no-store',
    });

    if (!upstream.ok) {
      // n8n throws on a miss, which surfaces as a 500. Translate it into
      // something the page can act on, and never echo the upstream body: it
      // reports the total number of invoices in the database.
      return new Response(
        JSON.stringify({ error: 'That invoice could not be found.' }),
        { status: 404, headers: CORS }
      );
    }

    const data = await upstream.json();
    if (data && typeof data === 'object') {
      for (const key of STRIP) delete data[key];
    }

    return new Response(JSON.stringify(data), { status: 200, headers: CORS });
  } catch (err) {
    return new Response(
      JSON.stringify({ error: 'The invoice service is unavailable. Please try again in a moment.' }),
      { status: 502, headers: CORS }
    );
  }
}

export async function onRequestOptions() {
  return new Response(null, {
    headers: {
      'Access-Control-Allow-Origin': 'https://payments.brandquality.com',
      'Access-Control-Allow-Methods': 'GET, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
    },
  });
}
