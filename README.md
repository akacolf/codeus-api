# Codeus API Vercel Split

The API should be its own Vercel project once it serves more than the CLI. Keeping it inside the website is acceptable for a short transition, but it couples chat/auth availability to website deploys, rewrites, and rollback decisions.

## Target shape

- Repository: `codeus-api`
- Vercel project: `codeus-api`
- Production domain: `api.quantumclub.sh`
- Public base URL: `https://api.quantumclub.sh/v1`
- Chat upstream: Vercel AI Gateway by default
- Legacy LLM gateway: disabled unless `CODEUS_ENABLE_LEGACY_LLM_GATEWAY=1`

## Files to move first

Copy these files into the new repo:

```text
api/index.rs
src/vercel_proxy.rs
Cargo.toml
Cargo.lock
rust-toolchain.toml
vercel.json
```

Then trim `Cargo.toml` so the new repo only exposes the API library and Vercel function. A minimal shape is:

```toml
[package]
name = "codeus-api"
version = "0.1.0"
edition = "2021"
publish = false

[dependencies]
anyhow = "1.0"
axum = "0.8"
reqwest = { version = "0.12", default-features = false, features = ["json", "rustls-tls", "stream"] }
serde_json = "1.0"
tokio = { version = "1.48", features = ["full"] }
tower = "0.5"
vercel_runtime = { version = "2", features = ["axum"] }

[lib]
name = "codeus_api"
path = "src/lib.rs"

[[bin]]
name = "codeus_vercel_api"
path = "api/index.rs"
```

Add `src/lib.rs`:

```rust
pub mod vercel_proxy;
```

Update `api/index.rs` to import `codeus_api::vercel_proxy` instead of `codeus::vercel_proxy`.

## Vercel setup

1. Create the new GitHub repo and push the API-only files.
2. In Vercel, create a new project from that repo.
3. Keep the same `vercel.json` rewrites so `/v1/*`, `/auth/*`, `/device/*`, `/chat/*`, `/account`, `/balance`, and `/usage` route to `/api/index`.
4. Add Production environment variables:
   - `AI_GATEWAY_API_KEY`
   - `CODEUS_AUTH_BASE`
   - `CODEUS_ACCOUNT_BASE` if account/balance routes live somewhere other than `CODEUS_AUTH_BASE`
   - `CODEUS_OAUTH_CLIENT_ID=codeus-cli`
   - `CODEUS_OAUTH_SCOPE=chat account usage`
5. Do not set `CODEUS_CHAT_BASE`, `CODEUS_CHAT_COMPLETIONS_URL`, or `CODEUS_CHAT_API_KEY` unless you are intentionally testing the old gateway.
6. Deploy a preview and smoke test:

```bash
curl -i https://<preview>.vercel.app/v1/account
curl -i https://<preview>.vercel.app/v1/chat/completions
```

The account call should return `401` without a session token. The chat call should not report missing Vercel AI Gateway config.

## Moving `api.quantumclub.sh`

The domain is currently attached to the website project. Move it during a quiet window:

1. In the website Vercel project, remove `api.quantumclub.sh` from Settings -> Domains.
2. In the new API project, add `api.quantumclub.sh` in Settings -> Domains.
3. If Vercel asks for DNS changes, configure the shown CNAME for the subdomain.
4. Deploy the API project to Production.
5. Verify:

```bash
curl -i https://api.quantumclub.sh/v1/account
CODEUS_API_BASE=https://api.quantumclub.sh/v1 codeus
```

## Rollback

If the new API project fails, remove `api.quantumclub.sh` from the API project and re-add it to the website project. The CLI default remains `https://api.quantumclub.sh/v1`, so rollback is a domain assignment rollback, not a CLI release.

## Website cleanup after the move

- Remove API rewrites from the website once traffic is stable.
- Leave a short-term health page or monitoring check in the API repo.
- Keep auth/session token semantics backward-compatible; users may already have `~/.config/codeus/config.toml`.
