use axum::routing::{get, post};
use axum::Router;
use codeus_api::vercel_proxy;
use tower::ServiceBuilder;
use vercel_runtime::axum::VercelLayer;
use vercel_runtime::Error;

#[tokio::main]
async fn main() -> Result<(), Error> {
    let router = Router::new()
        // --- Device login flow ---
        // Primary website paths (rewritten from /v1/* by middleware)
        .route("/v1/device/link/init", post(vercel_proxy::device_code))
        .route("/v1/device/link/poll", post(vercel_proxy::device_token))
        // Legacy / alternate OAuth paths
        .route("/v1/auth/device/code", post(vercel_proxy::device_code))
        .route("/v1/auth/device/token", post(vercel_proxy::device_token))
        .route("/v1/auth/refresh", post(vercel_proxy::refresh))
        // Without /v1 prefix (direct hits)
        .route("/device/link/init", post(vercel_proxy::device_code))
        .route("/device/link/poll", post(vercel_proxy::device_token))
        .route("/auth/device/code", post(vercel_proxy::device_code))
        .route("/auth/device/token", post(vercel_proxy::device_token))
        .route("/auth/refresh", post(vercel_proxy::refresh))
        // --- Chat ---
        .route("/v1/chat/completions", post(vercel_proxy::chat_completions))
        .route("/chat/completions", post(vercel_proxy::chat_completions))
        // --- Account (whoami) — matches /api/codeus/v1/auth/whoami on the website ---
        .route("/v1/auth/whoami", get(vercel_proxy::account))
        .route("/auth/whoami", get(vercel_proxy::account))
        // Keep legacy aliases so old CLI builds don't immediately break
        .route("/v1/account", get(vercel_proxy::account))
        .route("/account", get(vercel_proxy::account))
        // --- Balance (usage) — matches /api/codeus/v1/balance on the website ---
        .route("/v1/balance", get(vercel_proxy::usage))
        .route("/balance", get(vercel_proxy::usage))
        // Keep legacy aliases
        .route("/v1/usage", get(vercel_proxy::usage))
        .route("/usage", get(vercel_proxy::usage))
        // --- Sign-out (server-side session revocation) ---
        .route("/v1/auth/signout", post(vercel_proxy::signout))
        .route("/auth/signout", post(vercel_proxy::signout))
        .fallback(vercel_proxy::fallback);

    let app = ServiceBuilder::new()
        .layer(VercelLayer::new())
        .service(router);

    vercel_runtime::run(app).await
}
