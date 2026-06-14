# Codeus API

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

- `CODEUS_AUTH_BASE`

Optional:

- `CODEUS_ACCOUNT_BASE`
- `CODEUS_DEVICE_CODE_URL`
- `CODEUS_DEVICE_TOKEN_URL`
- `CODEUS_REFRESH_URL`
- `CODEUS_ACCOUNT_URL`
- `CODEUS_USAGE_URL`
- `CODEUS_SIGNOUT_URL`
- `CODEUS_OAUTH_CLIENT_ID=codeus-cli`
- `CODEUS_OAUTH_SCOPE=chat account usage`

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
```

The account request should return `401` without a session token.
