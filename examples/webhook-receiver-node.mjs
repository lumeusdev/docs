// Minimal Lumeus webhook receiver. Node 18+, no dependencies.
//
//   WEBHOOK_SECRET=whsec_... node webhook-receiver-node.mjs
//   WEBHOOK_SECRET_FILE=webhook-secret.txt node webhook-receiver-node.mjs
//
// Put verify-webhook.mjs (https://docs.lumeus.dev/examples/verify-webhook.mjs)
// next to this file. The secret comes from WEBHOOK_SECRET, or from the file
// named by WEBHOOK_SECRET_FILE, which is read on every request: you can start
// the receiver before you create the subscription, and it answers 503 until the
// file exists. During a signing-key rotation also set WEBHOOK_NEXT_SECRET.
import { readFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { verifyWebhook } from './verify-webhook.mjs';

const secretFile = process.env.WEBHOOK_SECRET_FILE;
if (!process.env.WEBHOOK_SECRET && !secretFile) throw new Error('set WEBHOOK_SECRET or WEBHOOK_SECRET_FILE');
const port = Number(process.env.PORT ?? 3000);
const maxBody = 256 * 1024; // deliveries are at most 64 KiB

function currentSecrets() {
  const secrets = [process.env.WEBHOOK_SECRET, process.env.WEBHOOK_NEXT_SECRET];
  if (secretFile) {
    try { secrets.push(readFileSync(secretFile, 'utf8').trim()); } catch { /* not created yet */ }
  }
  return secrets.filter(Boolean);
}

// Demo only: in production use a database UNIQUE key on (network, event id).
const seen = new Set();

createServer((req, res) => {
  if (req.method !== 'POST') return res.writeHead(405).end();
  const chunks = [];
  let size = 0;
  req.on('data', chunk => {
    size += chunk.length;
    if (size <= maxBody) chunks.push(chunk);
  });
  req.on('end', () => {
    if (size > maxBody) return res.writeHead(413).end();
    const secrets = currentSecrets();
    if (!secrets.length) {
      console.warn('no secret yet: waiting for', secretFile);
      return res.writeHead(503).end();
    }
    const rawBody = Buffer.concat(chunks);
    let verified;
    try {
      verified = verifyWebhook({ rawBody, headers: req.headers, secrets });
    } catch (error) {
      console.warn('rejected:', error.message); // a short code, safe to log
      return res.writeHead(400).end();
    }
    const event = JSON.parse(rawBody.toString('utf8'));
    const { lane, network } = verified.context;
    const key = `${network}|${event.id}`;
    if (lane === 'test') {
      console.log('verified test delivery', event.id);
    } else if (seen.has(key)) {
      console.log('duplicate, already processed', event.id);
    } else {
      seen.add(key); // store the event and enqueue your work here, before you answer
      console.log(`verified ${lane} ${event.kind} ${event.type} ${event.id} ledger ${event.ledger}`);
    }
    res.writeHead(204).end(); // answer fast with an empty body
  });
}).listen(port, () => console.log(`listening on http://localhost:${port}`));
