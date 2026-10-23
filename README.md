# Lumeus Docs

Source for [docs.lumeus.dev](https://docs.lumeus.dev), the developer
documentation for [Lumeus](https://lumeus.dev): Stellar data APIs for Mainnet
and Testnet.

## Contents

| Path | Content |
| --- | --- |
| `index.mdx`, `quickstart.mdx` | Home page and quickstart |
| `guides/` | Authentication, browser keys, plans and billing, limits, rate limits, errors, health checks, idempotency |
| `activity/` | Activity API: decoded account, asset, contract and transaction history |
| `assets-api/` | Assets API: holdings, ranked holders, token registry, snapshots |
| `webhooks/` | Webhooks: first webhook, receiving and verifying deliveries, balance events, subscriptions |
| `rpc/` | RPC: authenticated Stellar JSON-RPC, methods, SDKs, sending transactions |
| `recipes/` | Task recipes in curl, JavaScript and Python |
| `agents/` | Using Lumeus with coding agents |
| `api/rpc/` | Reference page for each JSON-RPC method |
| `api-reference/` | OpenAPI documents for the API reference |
| `examples/` | Downloadable code: Activity client, webhook verifier, webhook receivers in Node.js, Python and Go |
| `snippets/` | Shared content, such as the Testnet setup block |
| `docs.json` | Navigation and site configuration |

## Local preview

Requires Node.js 20 or later.

```bash
npm install --global mint
mint dev
```

The site runs at http://localhost:3000.

## Reporting issues

Found an error, a broken example or something unclear?
[Open an issue](https://github.com/lumeusdev/docs/issues/new) and include:

- the page URL;
- what you expected and what happened;
- for API behaviour, the `request_id` from the response (never your API key).

To report a security vulnerability, email
[hello@lumeus.dev](mailto:hello@lumeus.dev) instead of opening a public issue.

## Contributing

Pull requests are welcome for corrections, clearer explanations and new
recipes.

1. Fork the repository and create a branch from `main`.
2. Edit the MDX pages, using the components already used across the site
   (`Steps`, `Tabs`, `CodeGroup`, `Note`, `Card`).
3. Test every code example you add or change on Testnet with your own key from
   [app.lumeus.dev](https://app.lumeus.dev). Examples must run as written after
   the Testnet setup block.
4. Check the build and links:

   ```bash
   mint validate
   mint broken-links --check-anchors
   ```

5. Open a pull request describing the change and the reason for it.

### Style

- Open each page with one to three sentences on what it covers.
- Write short, plain sentences in the second person.
- Show real responses. Never include API keys, secrets or personal data.
- Keep page titles under 30 characters.

### Generated files

`api-reference/` and `api/rpc/` are generated from the Lumeus API definitions
and are overwritten on each update. To report a problem in the API reference,
open an issue rather than editing these files.

## Support

For questions about the APIs, email [hello@lumeus.dev](mailto:hello@lumeus.dev).
