/**
 * Cloudflare Pages Function: POST /api/create-intent
 * Creates a Stripe PaymentIntent and returns the client_secret.
 *
 * Environment variable required (set in Cloudflare Pages → Settings → Environment Variables):
 *   STRIPE_SECRET_KEY  →  sk_live_... (or sk_test_... for testing)
 */
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

    const { amount, invoiceNum, invoiceId } = await context.request.json();

    if (!amount || amount <= 0) {
      return new Response(
        JSON.stringify({ error: 'Invalid amount.' }),
        { status: 400, headers: corsHeaders }
      );
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
