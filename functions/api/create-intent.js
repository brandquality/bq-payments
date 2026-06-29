/**
 * Cloudflare Pages Function: POST /api/create-intent
 * Creates a Stripe PaymentIntent and returns the client_secret.
 *
 * Attaches the invoice's CLIENT identity to the charge so the Stripe dashboard
 * shows a named customer instead of "Unnamed customer (Guest)", and so every
 * invoice for the same client rolls up under ONE Stripe customer — regardless
 * of which contact email each invoice used. The client info is pulled
 * server-side from the invoice lookup (authoritative), not from the browser.
 *
 * Grouping key: a sanitized version of the client (organization) name, stored
 * in the customer's metadata (`bq_client`) and matched via Stripe customer
 * search. Note: Stripe search is eventually consistent (a newly-created
 * customer can take a minute or two to become searchable), so two payments for
 * a brand-new client within ~1 minute may create two customer records the first
 * time; subsequent payments group cleanly.
 *
 * Environment variable required (Cloudflare Pages → Settings → Environment Variables):
 *   STRIPE_SECRET_KEY  →  sk_live_... (or sk_test_... for testing)
 */

const INVOICE_LOOKUP = 'https://n8n.brandquality.com/webhook/invoice-lookup';

// Find an existing Stripe customer for this client (by metadata key), or create
// one. Best-effort: returns '' on any failure so a payment is never blocked.
async function findOrCreateClientCustomer(secretKey, clientName, clientKey, email) {
  if (!clientKey) return '';
  try {
    const query = "metadata['bq_client']:'" + clientKey + "'";
    const sRes = await fetch(
      'https://api.stripe.com/v1/customers/search?limit=1&query=' + encodeURIComponent(query),
      { headers: { Authorization: 'Bearer ' + secretKey } }
    );
    const s = await sRes.json();
    if (s && Array.isArray(s.data) && s.data.length > 0) {
      return s.data[0].id;
    }
    // Not found — create the client customer.
    const cp = new URLSearchParams();
    if (clientName) cp.set('name', clientName);
    if (email) cp.set('email', email);
    cp.set('metadata[bq_client]', clientKey);
    const cRes = await fetch('https://api.stripe.com/v1/customers', {
      method: 'POST',
      headers: { Authorization: 'Bearer ' + secretKey, 'Content-Type': 'application/x-www-form-urlencoded' },
      body: cp.toString(),
    });
    const c = await cRes.json();
    return cRes.ok && c.id ? c.id : '';
  } catch (err) {
    return '';
  }
}

export async function onRequestPost(context) {
  const corsHeaders = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Content-Type': 'application/json',
  };

  try {
    const { STRIPE_SECRET_KEY } = context.env;

    if (!STRIPE_SECRET_KEY) {
      return new Response(
        JSON.stringify({ error: 'Payment processor not configured.' }),
        { status: 500, headers: corsHeaders }
      );
    }

    const { amount, invoiceNum, invoiceId, invoiceName } = await context.request.json();

    if (!amount || amount <= 0) {
      return new Response(
        JSON.stringify({ error: 'Invalid amount.' }),
        { status: 400, headers: corsHeaders }
      );
    }

    // Pull the invoice's client identity server-side and attach a per-CLIENT
    // named customer. Non-fatal: if any step fails, the payment still proceeds.
    let customerId = '';
    try {
      const baseNum = (invoiceNum || '').replace(/-DEP$/i, '');
      if (baseNum) {
        const lr = await fetch(INVOICE_LOOKUP + '?inv=' + encodeURIComponent(baseNum));
        if (lr.ok) {
          const inv = await lr.json();
          const clientName = (inv.clientName || '').toString().trim();
          const contactEmail = (inv.contactEmail || '').toString().trim();
          // Stable, search-safe key from the client name (alphanumeric only).
          const clientKey = clientName.toLowerCase().replace(/[^a-z0-9]/g, '');
          customerId = await findOrCreateClientCustomer(STRIPE_SECRET_KEY, clientName, clientKey, contactEmail);
        }
      }
    } catch (err) {
      // ignore — proceed without a customer
    }

    // Stripe expects amount in cents (integer)
    const amountCents = Math.round(amount * 100);

    const params = new URLSearchParams({
      amount: String(amountCents),
      currency: 'usd',
      'automatic_payment_methods[enabled]': 'true',
    });
    if (invoiceNum) params.set('metadata[invoiceNum]', invoiceNum);
    if (invoiceId) params.set('metadata[invoiceId]', invoiceId);
    // Project name is the primary identifier on the charge (mirrors PayPal's order description)
    if (invoiceName) params.set('description', invoiceName);
    // Per-client named customer so the dashboard groups by client (not "Guest")
    if (customerId) params.set('customer', customerId);

    const stripeRes = await fetch('https://api.stripe.com/v1/payment_intents', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${STRIPE_SECRET_KEY}`,
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: params.toString(),
    });

    const stripeData = await stripeRes.json();

    if (!stripeRes.ok) {
      return new Response(
        JSON.stringify({ error: stripeData.error?.message || 'Stripe error.' }),
        { status: stripeRes.status, headers: corsHeaders }
      );
    }

    return new Response(
      JSON.stringify({ clientSecret: stripeData.client_secret }),
      { status: 200, headers: corsHeaders }
    );

  } catch (err) {
    return new Response(
      JSON.stringify({ error: 'Internal error: ' + err.message }),
      { status: 500, headers: corsHeaders }
    );
  }
}

// Handle CORS preflight
export async function onRequestOptions() {
  return new Response(null, {
    headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
    },
  });
}
