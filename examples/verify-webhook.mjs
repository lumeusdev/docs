import { createHash, createHmac, timingSafeEqual } from 'node:crypto';

// Lumeus webhook verifier. Node 18+, no dependencies, no network calls.
//
//   const { timestamp, context } = verifyWebhook({ rawBody, headers, secrets });
//
// rawBody   the request body as a Buffer, exactly as received (before JSON parsing)
// headers   a plain object with lower-case names (node:http) or a Fetch Headers object
// secrets   the subscription's whsec_ secrets; pass both during a key rotation
//
// It checks the body signature (X-Webhook-Signature or X-Webhook-Next-Signature),
// the timestamp (default tolerance 300 s) and the signed delivery context
// (X-Webhook-Delivery-Context), which binds the event id, network, lane and body
// hash. Every Lumeus delivery carries signed context, so a request without it is
// rejected with missing_delivery_context. Pass requireContext: false only for an
// endpoint whose deliveries never carry that header.
//
// On failure it throws an Error whose message is a short code. Log only that
// code, never the headers, secrets or payload. Store the event before you
// return 2xx.
export function verifyWebhook({ rawBody, headers, secrets, now = Date.now(), toleranceSeconds = 300, maxBytes = 1 << 20, requireContext = true }) {
  if (!Buffer.isBuffer(rawBody) || rawBody.length > maxBytes || !Array.isArray(secrets) || !secrets.length || secrets.some(s => typeof s !== 'string' || !s)) throw new Error('invalid_verifier_input');
  const get = name => {
    const value = typeof headers.get === 'function' ? headers.get(name) : headers[name.toLowerCase()];
    if (value == null) return '';
    if (typeof value !== 'string') throw new Error('ambiguous_signature_header');
    return value;
  };
  const verify = (value, bytes) => {
    const match = /^t=([0-9]{1,12}),v1=([a-fA-F0-9]{64})$/.exec(value);
    if (!match || !Number.isFinite(now) || Math.abs(now / 1000 - Number(match[1])) > toleranceSeconds) return null;
    const received = Buffer.from(match[2], 'hex');
    for (const secret of secrets) {
      const expected = createHmac('sha256', secret).update(`${match[1]}.`).update(bytes).digest();
      if (timingSafeEqual(expected, received)) return match[1];
    }
    return null;
  };
  const timestamp = verify(get('x-webhook-signature'), rawBody) ?? verify(get('x-webhook-next-signature'), rawBody);
  if (!timestamp) throw new Error('invalid_webhook_signature');
  const encoded = get('x-webhook-delivery-context');
  if (!encoded) {
    if (requireContext) throw new Error('missing_delivery_context');
    return { timestamp, context: null };
  }
  if (encoded.length > 16384 || !/^[A-Za-z0-9_-]+$/.test(encoded)) throw new Error('invalid_delivery_context');
  const bytes = Buffer.from(encoded, 'base64url');
  const contextTimestamp = verify(get('x-webhook-context-signature'), bytes) ?? verify(get('x-webhook-next-context-signature'), bytes);
  if (contextTimestamp !== timestamp) throw new Error('invalid_context_signature');
  let context, event;
  try {
    context = JSON.parse(bytes.toString('utf8'));
    event = JSON.parse(rawBody.toString('utf8'));
  } catch {
    throw new Error('context_body_mismatch');
  }
  const normalized = value => value === 'pubnet' ? 'mainnet' : value;
  if (!context || !event || context.domain !== 'lumeus-delivery-context-v1' || !context.generation || !context.subscription_id ||
      context.event_id !== event.id || normalized(context.network) !== normalized(event.network) ||
      context.body_sha256 !== createHash('sha256').update(rawBody).digest('hex') ||
      !['live', 'replay', 'test'].includes(context.lane) || (context.lane === 'replay' && !context.replay_job_id) ||
      (context.lane === 'test' && (event.kind !== 'test' || get('x-webhook-test') !== 'true'))) throw new Error('context_body_mismatch');
  return { timestamp, context };
}
