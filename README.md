## Codeus API

Standalone Vercel API for Codeus clients.

## Ownership

- Repository: `codeus-api`
- Vercel project: `codeus-api`
- Production domain: `api.quantumclub.sh`
- Public base URL: `https://api.quantumclub.sh/v1`

The website must not serve Codeus API routes or own the public API domain.

## Routes

- `POST /v1/chat/completions`
- `POST /v1/device/link/init`
- `POST /v1/device/link/poll`
- `POST /v1/auth/device/code`
- `POST /v1/auth/device/token`
- `POST /v1/auth/refresh`
- `GET /v1/auth/whoami`
- `GET /v1/account`
- `GET /v1/balance`
- `GET /v1/usage`
- `POST /v1/auth/signout`

Non-`/v1` aliases are kept for older client builds.

## Environment

Required for chat:

- `AI_GATEWAY_API_KEY`

Required for auth/account forwarding:

- `UPSTASH_REDIS_REST_URL`
- `UPSTASH_REDIS_REST_TOKEN`

Optional:

- `CODEUS_DEVICE_APPROVAL_BASE=https://anaxonic.sh`
- `CODEUS_PUBLIC_API_BASE=https://api.quantumclub.sh`
- `CODEUS_AUTH_BASE`
- `CODEUS_ACCOUNT_BASE`
- `CODEUS_DEVICE_CODE_URL`
- `CODEUS_DEVICE_TOKEN_URL`
- `CODEUS_REFRESH_URL`
- `CODEUS_ACCOUNT_URL`
- `CODEUS_USAGE_URL`
- `CODEUS_SIGNOUT_URL`
- `CODEUS_OAUTH_CLIENT_ID=codeus-cli`
- `CODEUS_OAUTH_SCOPE=chat account usage`

By default, `codeus-api` owns the Codeus device-login bridge. It stores pending
device codes and opaque Codeus session tokens in Upstash Redis, then sends users
to `CODEUS_DEVICE_APPROVAL_BASE/codeus/link` for browser approval. The Anaxonic
website proves the user is signed in with Clerk and approves the pending device
code through `POST /v1/device/link/approve`.

Use the exact URL overrides only when delegating device auth, account, usage,
refresh, or sign-out to another service.

Legacy chat gateway routing is disabled by default. To opt in, set
`CODEUS_ENABLE_LEGACY_LLM_GATEWAY=1` plus `CODEUS_CHAT_BASE` or
`CODEUS_CHAT_COMPLETIONS_URL`.

## Development

```bash
cargo fmt
cargo test
cargo check
```

## Vercel Domain Move

Yes: remove `api.quantumclub.sh` from the website project and add it to the
`codeus-api` project. After the production deploy, verify:

```bash
curl -i https://api.quantumclub.sh/v1/account
curl -i -X POST https://api.quantumclub.sh/v1/auth/device/code \
  -H 'content-type: application/json' \
  --data '{"client_id":"codeus-cli","client_name":"Codeus CLI","scope":"chat account usage"}'
```

The account request should return `401` without a session token. The device-code request should
return JSON with a `linkUrl` pointing at `/codeus/link`. A `GET` request to the same route may
return `405 Allow: POST`; that only confirms the API route exists.
