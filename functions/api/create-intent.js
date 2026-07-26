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
  // Scoped to the payment page. This used to be '*', which let any site on the
  // internet open payment intents against the live Stripe account: a card
  // testing surface, and card testing brings disputes and account penalties.
  const corsHeaders = {
    'Access-Control-Allow-Origin': 'https://payments.brandquality.com',
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

    // Pull the invoice server-side. It is authoritative for three things the
    // browser must never decide: who the customer is, how much to charge, and
    // whether a recurring plan gets authorized.
    //
    // A failed lookup used to be swallowed, which quietly produced two bad
    // outcomes. The amount went unchecked, and a recurring invoice was charged
    // as an ordinary one, taking the client's money without ever setting up the
    // plan they had just agreed to. Asking them to retry is far better than
    // getting either of those wrong.
    //
    // Note this calls n8n directly rather than the /api/invoice-lookup proxy,
    // because it needs the contact email that the proxy strips for browsers.
    let customerId = '';
    let recurringPlan = false;
    let recurringAmount = 0;
    let recurringInterval = 'Annual';
    let renewalDate = '';

    const isDeposit = /-DEP$/i.test(String(invoiceNum || ''));
    const baseNum = (invoiceNum || '').replace(/-DEP$/i, '');

    if (baseNum) {
      let inv = null;
      try {
        const lookupHeaders = {};
        if (context.env.N8N_PROXY_TOKEN) lookupHeaders['x-bq-proxy-token'] = context.env.N8N_PROXY_TOKEN;
        const lr = await fetch(INVOICE_LOOKUP + '?inv=' + encodeURIComponent(baseNum), {
          headers: lookupHeaders,
          cache: 'no-store',
        });
        if (lr.ok) inv = await lr.json();
      } catch (err) {
        inv = null;
      }

      if (!inv || !inv.invoiceNum) {
        return new Response(
          JSON.stringify({ error: 'We could not verify this invoice just now. Please refresh the page and try again in a moment.' }),
          { status: 503, headers: corsHeaders }
        );
      }

      // The browser proposes an amount; the invoice decides. Without this an
      // unauthenticated caller could open a payment intent for any figure
      // against any invoice.
      const expected = isDeposit ? Number(inv.deposit) : Number(inv.balanceDue);
      if (!Number.isFinite(expected) || expected <= 0) {
        return new Response(
          JSON.stringify({ error: 'This invoice has nothing outstanding to pay.' }),
          { status: 400, headers: corsHeaders }
        );
      }
      if (Math.round(Number(amount) * 100) !== Math.round(expected * 100)) {
        return new Response(
          JSON.stringify({ error: 'That amount does not match this invoice. Please refresh the page and try again.' }),
          { status: 400, headers: corsHeaders }
        );
      }

      const clientName = (inv.clientName || '').toString().trim();
      const contactEmail = (inv.contactEmail || '').toString().trim();
      // Stable, search-safe key from the client name (alphanumeric only).
      const clientKey = clientName.toLowerCase().replace(/[^a-z0-9]/g, '');
      customerId = await findOrCreateClientCustomer(STRIPE_SECRET_KEY, clientName, clientKey, contactEmail);
      recurringPlan = inv.recurringPlan === true;
      recurringAmount = Number(inv.recurringAmount) || 0;
      recurringInterval = (inv.recurringInterval || 'Annual').toString().trim();
      renewalDate = (inv.renewalDate || '').toString().trim();
    }

    // A recurring plan needs a customer to attach the saved card to. Without one
    // the renewal could never run, so fail loudly rather than silently taking a
    // payment that doesn't set up what the client authorized.
    if (recurringPlan && !customerId) {
      return new Response(
        JSON.stringify({ error: 'Could not set up the recurring plan. Please contact payments@brandquality.com.' }),
        { status: 500, headers: corsHeaders }
      );
    }

    // Stripe expects amount in cents (integer)
    const amountCents = Math.round(amount * 100);

    const params = new URLSearchParams({
      amount: String(amountCents),
      currency: 'usd',
    });

    if (recurringPlan) {
      // Card only on recurring invoices, by decision.
      //
      // Wallets technically work, but Apple mandates its own recurring-payment
      // disclosure block in the sheet whenever a payment sets up a subscription
      // (omitting it makes Apple abort silently). That block can't be styled or
      // suppressed, and it presents the plan as the headline rather than the
      // amount actually being charged. Line items don't override it.
      //
      // Normal invoices are unaffected and still offer wallets.
      params.set('payment_method_types[0]', 'card');
      params.set('setup_future_usage', 'off_session');
      params.set('metadata[bq_recurring]', 'true');
      if (recurringAmount) params.set('metadata[bq_recurring_amount]', String(recurringAmount));
      if (recurringInterval) params.set('metadata[bq_recurring_interval]', recurringInterval);
      if (renewalDate) params.set('metadata[bq_renewal_date]', renewalDate);
    } else {
      params.set('automatic_payment_methods[enabled]', 'true');
    }

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
      'Access-Control-Allow-Origin': 'https://payments.brandquality.com',
      'Access-Control-Allow-Methods': 'POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
    },
  });
}
