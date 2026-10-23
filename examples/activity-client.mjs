// Bounded Node 18+ client for Activity pagination. No network calls when imported.
// idForURL must durably return the SAME key for retries/restarts of that URL.
// Persist pages and the next link atomically in your own application database.
//
// Retries: 429, busy, index_not_ready, unavailable and 5xx without a body code are
// retried up to maxRetries times, waiting Retry-After. A Retry-After over 60 s (the daily
// Testnet request cap, which resets at 00:00 UTC) throws instead of sleeping. query_timeout
// is never retried: it throws an ActivityError so you can narrow the range or lower
// limit. Every other error throws at once with its code and request_id.
export class ActivityError extends Error {
  constructor(status, body, retryAfter) {
    super(`activity_http_${status}${body?.code ? ` ${body.code}` : ''}: ${body?.error ?? 'no error body'}`);
    this.status = status;
    this.code = body?.code;
    this.requestID = body?.request_id;
    this.retryAfter = retryAfter;
  }
}

const RETRYABLE_CODES = new Set(['rate_limited', 'busy', 'index_not_ready', 'unavailable']);

export async function* activityPages({ baseURL, apiKey, initialPath, idForURL, maxPages = 10, maxRetries = 3, fetchImpl = fetch, sleep = ms => new Promise(resolve => setTimeout(resolve, ms)) }) {
  const base = new URL(baseURL);
  if (base.protocol !== 'https:' || !apiKey || typeof idForURL !== 'function' || !Number.isInteger(maxPages) || maxPages < 1 || maxPages > 1000 || !Number.isInteger(maxRetries) || maxRetries < 0 || maxRetries > 10) throw new Error('invalid_client_configuration');
  let next = new URL(initialPath, base);
  let frozenView;
  const visited = new Set();
  for (let pageNumber = 0; pageNumber < maxPages; pageNumber++) {
    if (next.origin !== base.origin || next.username || next.password) throw new Error('cross_origin_pagination');
    if (visited.has(next.href)) throw new Error('pagination_cycle');
    visited.add(next.href);
    const key = await idForURL(next.href);
    if (typeof key !== 'string' || !/^[\x21-\x7e]{8,128}$/.test(key)) throw new Error('invalid_request_identity'); // 8-128 printable ASCII, no spaces
    let result;
    for (let attempt = 0; ; attempt++) {
      const response = await fetchImpl(next.href, { headers: { Authorization: `Bearer ${apiKey}`, 'Idempotency-Key': key }, redirect: 'error', signal: AbortSignal.timeout(45_000) });
      if (response.status === 202) {
        await response.body?.cancel();
        const error = new Error('operation_pending');
        error.operationID = response.headers.get('x-lumeus-operation-id');
        error.location = response.headers.get('location');
        throw error; // poll its status; do not issue a new logical request
      }
      if (response.status !== 200) {
        const text = await response.text().catch(() => '');
        let body;
        try { body = JSON.parse(text); } catch { body = undefined; }
        const header = Number(response.headers.get('retry-after'));
        const retryAfter = Number.isFinite(header) && header >= 0 ? header : undefined;
        const retryable = body?.code ? RETRYABLE_CODES.has(body.code) : response.status === 429 || response.status >= 500;
        if (!retryable || attempt >= maxRetries || retryAfter > 60) throw new ActivityError(response.status, body, retryAfter); // query_timeout lands here
        const backoff = 500 * 2 ** attempt + Math.random() * 250;
        await sleep(retryAfter !== undefined ? retryAfter * 1000 : backoff);
        continue;
      }
      let size = 0;
      const chunks = [];
      for await (const chunk of response.body) {
        size += chunk.length;
        if (size > 16 << 20) throw new Error('response_budget_exceeded');
        chunks.push(chunk);
      }
      result = JSON.parse(Buffer.concat(chunks).toString('utf8'));
      break;
    }
    const view = result?.read_view;
    if (!view?.generation || !view.network || !view.decoder_version || !Number.isSafeInteger(view.snapshot_ledger) || view.snapshot_ledger < 1 || !Array.isArray(result?._embedded?.records) || typeof result.range_complete !== 'boolean') throw new Error('invalid_activity_page');
    const identity = JSON.stringify([view.network, view.generation, view.decoder_version, view.first_ledger, view.snapshot_ledger, view.published_through]);
    if (frozenView !== undefined && identity !== frozenView) throw new Error('history_snapshot_changed');
    frozenView = identity;
    yield result;
    if (result.range_complete) return;
    const href = result._links?.next?.href;
    if (!href) throw new Error('missing_next_link');
    next = new URL(href, base);
  }
  throw new Error('page_budget_exhausted'); // save your next link and resume deliberately
}
