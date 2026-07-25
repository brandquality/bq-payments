/**
 * Cloudflare Pages Function: POST /api/sub-check
 *
 * Reports the health of a recurring plan's subscription so the renewal reminder
 * can warn a client (and Diallo) when the card on file will expire before the
 * renewal date. Keeping this here means n8n never needs a Stripe key.
 *
 * Auth: same private shared token the Stripe gateway uses. Requests without a
 * matching `x-bq-proxy-token` header are rejected, so this is not a public
 * lookup even though it lives on a public domain.
 *
 * Request body:  { "subscriptionId": "sub_..." }
 * Response:      { status, cardBrand, cardLast4, expMonth, expYear,
 *                  cardExpiresBeforeRenewal, currentPeriodEnd }
 *
 * Environment variables (Cloudflare Pages -> Settings -> Environment variables):
 *   STRIPE_SECRET_KEY  -> sk_live_...
 *   N8N_PROXY_TOKEN    -> same value as the n8n Header Auth credential
 */

function json(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

export async function onRequestPost(context) {
  const { request, env } = context;

  // Token gate. If no token is configured we refuse rather than fall open —
  // this endpoint reads customer payment details.
  const supplied = request.headers.get('x-bq-proxy-token') || '';
  if (!env.N8N_PROXY_TOKEN || supplied !== env.N8N_PROXY_TOKEN) {
    return json({ error: 'Unauthorized' }, 401);
  }

  let subscriptionId = '';
  try {
    const body = await request.json();
    subscriptionId = (body && body.subscriptionId ? String(body.subscriptionId) : '').trim();
  } catch (err) {
    return json({ error: 'Invalid request body.' }, 400);
  }
  if (!subscriptionId) return json({ error: 'Missing subscriptionId.' }, 400);

  try {
    const key = env.STRIPE_SECRET_KEY;
    const subRes = await fetch(
      'https://api.stripe.com/v1/subscriptions/' + encodeURIComponent(subscriptionId) +
        '?expand[]=default_payment_method',
      { headers: { Authorization: 'Bearer ' + key } }
    );
    if (!subRes.ok) return json({ error: 'Subscription not found.' }, 404);
    const sub = await subRes.json();

    const pm = sub.default_payment_method;
    const card = pm && typeof pm === 'object' ? pm.card : null;

    // Renewal is the end of the current period (or the trial, in year one).
    const renewalTs = sub.trial_end || sub.current_period_end || 0;

    // A card expires at the END of its expiry month, so it's still good through
    // that month. Compare against the renewal month, not the exact day.
    let cardExpiresBeforeRenewal = false;
    if (card && card.exp_year && card.exp_month && renewalTs) {
      const renewal = new Date(renewalTs * 1000);
      const cardDead = new Date(Date.UTC(card.exp_year, card.exp_month, 1)); // first day after expiry
      cardExpiresBeforeRenewal = cardDead <= renewal;
    }

    return json({
      status: sub.status || '',
      cancelAtPeriodEnd: sub.cancel_at_period_end === true,
      cardBrand: card ? card.brand || '' : '',
      cardLast4: card ? card.last4 || '' : '',
      expMonth: card ? card.exp_month || 0 : 0,
      expYear: card ? card.exp_year || 0 : 0,
      cardExpiresBeforeRenewal,
      currentPeriodEnd: renewalTs
        ? new Date(renewalTs * 1000).toISOString().slice(0, 10)
        : '',
    });
  } catch (err) {
    return json({ error: 'Internal error: ' + err.message }, 500);
  }
}
