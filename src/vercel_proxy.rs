use axum::body::{to_bytes, Body};
use axum::extract::Request;
use axum::http::{header, Response, StatusCode};
use base64::Engine;
use rand::RngCore;
use serde_json::{json, Map, Value};
use std::env;
use std::time::{SystemTime, UNIX_EPOCH};

const BODY_LIMIT: usize = 4 * 1024 * 1024;
const DEVICE_TTL_SECS: u64 = 10 * 60;
const SESSION_TTL_SECS: u64 = 30 * 24 * 60 * 60;
const DEVICE_CODE_PATHS: &[&str] = &[
    "api/codeus/v1/device/link/init",
    "device/link/init",
    "api/codeus/v1/oauth/device/code",
    "oauth/device/code",
    "api/codeus/v1/device/code",
    "device/code",
];
const DEVICE_TOKEN_PATHS: &[&str] = &[
    "api/codeus/v1/device/link/poll",
    "device/link/poll",
    "api/codeus/v1/oauth/token",
    "oauth/token",
    "api/codeus/v1/device/token",
    "device/token",
];
const REFRESH_PATHS: &[&str] = &[
    "api/codeus/v1/oauth/token",
    "oauth/token",
    "api/codeus/v1/refresh",
    "refresh",
];
const ACCOUNT_PATHS: &[&str] = &["api/codeus/v1/auth/whoami", "auth/whoami"];
const USAGE_PATHS: &[&str] = &["api/codeus/v1/balance", "balance"];
const SIGNOUT_PATHS: &[&str] = &["api/codeus/v1/auth/signout", "auth/signout"];
const CORS_ALLOW_HEADERS: &str = "authorization,content-type";
const CORS_ALLOW_METHODS: &str = "GET,POST,OPTIONS";
const DEFAULT_CHAT_MODEL: &str = "anthropic/claude-sonnet-4.6";

#[derive(Debug)]
struct ProxyError {
    status: StatusCode,
    code: &'static str,
    message: String,
}

impl ProxyError {
    fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
        }
    }
}

struct UpstreamText {
    status: reqwest::StatusCode,
    headers: reqwest::header::HeaderMap,
    text: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ChatAuth {
    ServerToken(String),
    UserBearer,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ChatUpstream {
    name: &'static str,
    url: String,
    auth: ChatAuth,
}

pub async fn chat_completions(request: Request) -> Response<Body> {
    respond(chat_completions_inner(request).await)
}

pub async fn device_code(request: Request) -> Response<Body> {
    respond(device_code_inner(request).await)
}

pub async fn device_token(request: Request) -> Response<Body> {
    respond(device_token_inner(request).await)
}

pub async fn device_approve(request: Request) -> Response<Body> {
    respond(device_approve_inner(request).await)
}

pub async fn refresh(request: Request) -> Response<Body> {
    respond(refresh_inner(request).await)
}

pub async fn account(request: Request) -> Response<Body> {
    respond(account_inner(request).await)
}

pub async fn usage(request: Request) -> Response<Body> {
    respond(usage_inner(request).await)
}

pub async fn signout(request: Request) -> Response<Body> {
    respond(signout_inner(request).await)
}

pub async fn fallback() -> Response<Body> {
    json_response(
        StatusCode::NOT_FOUND,
        json!({
            "error": "not_found",
            "error_description": "No Codeus API route matched this request.",
        }),
    )
}

pub async fn preflight() -> Response<Body> {
    Response::builder()
        .status(StatusCode::NO_CONTENT)
        .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
        .header(header::ACCESS_CONTROL_ALLOW_HEADERS, CORS_ALLOW_HEADERS)
        .header(header::ACCESS_CONTROL_ALLOW_METHODS, CORS_ALLOW_METHODS)
        .header(header::CACHE_CONTROL, "no-store")
        .body(Body::empty())
        .unwrap_or_else(|_| internal_error("failed to build preflight response"))
}

async fn chat_completions_inner(request: Request) -> Result<Response<Body>, ProxyError> {
    let user_token = require_bearer_token(&request)?;
    let _session = require_codeus_session(&user_token).await?;
    let body = read_json(request).await?;
    let upstreams = chat_upstream_candidates(true)?;
    let response = post_chat_with_fallback(upstreams, Some(user_token), body).await?;

    Ok(proxy_response(response))
}

async fn device_code_inner(request: Request) -> Result<Response<Body>, ProxyError> {
    if optional_env("CODEUS_DEVICE_CODE_URL").is_none() {
        return local_device_code_inner(request).await;
    }

    let auth_urls = configured_url_candidates(
        "CODEUS_DEVICE_CODE_URL",
        "CODEUS_AUTH_BASE",
        DEVICE_CODE_PATHS,
    )?;
    let mut payload = object_body(read_json(request).await?);
    payload.insert(
        "client_id".to_string(),
        Value::String(
            optional_env("CODEUS_OAUTH_CLIENT_ID").unwrap_or_else(|| "codeus-cli".into()),
        ),
    );
    payload.insert(
        "scope".to_string(),
        Value::String(
            optional_env("CODEUS_OAUTH_SCOPE").unwrap_or_else(|| "chat account usage".into()),
        ),
    );

    let response = post_json_with_404_fallback(auth_urls, Value::Object(payload)).await?;
    let status = response.status;
    let headers = response.headers;
    let text = response.text;
    if !status.is_success() {
        return Ok(text_response(status_code(status), headers, text));
    }

    let upstream = parse_upstream_json(&text)?;
    if upstream.get("deviceCode").and_then(Value::as_str).is_some() {
        return Ok(json_response(
            StatusCode::OK,
            json!({
                "device_code": upstream.get("deviceCode"),
                "user_code": upstream.get("userCode"),
                "verification_uri": upstream.get("linkUrl"),
                "verification_uri_complete": upstream.get("linkUrl"),
                "expires_in": expires_in(upstream.get("expiresAt")),
                "interval": upstream.get("interval"),
            }),
        ));
    }

    Ok(json_response(StatusCode::OK, upstream))
}

async fn device_token_inner(request: Request) -> Result<Response<Body>, ProxyError> {
    if optional_env("CODEUS_DEVICE_TOKEN_URL").is_none() {
        return local_device_token_inner(request).await;
    }

    let auth_urls = configured_url_candidates(
        "CODEUS_DEVICE_TOKEN_URL",
        "CODEUS_AUTH_BASE",
        DEVICE_TOKEN_PATHS,
    )?;
    let mut payload = object_body(read_json(request).await?);
    payload.insert(
        "client_id".to_string(),
        Value::String(
            optional_env("CODEUS_OAUTH_CLIENT_ID").unwrap_or_else(|| "codeus-cli".into()),
        ),
    );
    if let Some(device_code) = payload
        .get("deviceCode")
        .cloned()
        .or_else(|| payload.get("device_code").cloned())
    {
        payload.insert("deviceCode".to_string(), device_code);
    }

    let response = post_json_with_404_fallback(auth_urls, Value::Object(payload)).await?;
    let status = response.status;
    let headers = response.headers;
    let text = response.text;
    let upstream = if text.trim().is_empty() {
        json!({})
    } else {
        parse_upstream_json(&text)?
    };

    if status.as_u16() == 202 || upstream.get("status").and_then(Value::as_str) == Some("pending") {
        return Ok(oauth_error(
            "authorization_pending",
            "Waiting for browser approval.",
        ));
    }
    if status.as_u16() == 410 || upstream.get("status").and_then(Value::as_str) == Some("expired") {
        return Ok(oauth_error("expired_token", "Browser login expired."));
    }
    if upstream.get("status").and_then(Value::as_str) == Some("denied") {
        return Ok(oauth_error("access_denied", "Browser login was denied."));
    }
    if !status.is_success() {
        return Ok(text_response(status_code(status), headers, text));
    }
    if let Some(session_token) = upstream.get("sessionToken").and_then(Value::as_str) {
        return Ok(json_response(
            StatusCode::OK,
            json!({
                "access_token": session_token,
                "session_token": session_token,
                "token_type": "Bearer",
                "expires_in": expires_in(upstream.get("expiresAt")),
            }),
        ));
    }

    Ok(json_response(StatusCode::OK, upstream))
}

async fn local_device_code_inner(request: Request) -> Result<Response<Body>, ProxyError> {
    require_device_store()?;
    let body = object_body(read_json(request).await?);
    let now = now_millis();
    let expires_at = now + (DEVICE_TTL_SECS * 1000);
    let device_code = random_token(32);
    let user_code = random_user_code();
    let account_id = body.get("accountId").cloned().unwrap_or(Value::Null);
    let record = json!({
        "status": "pending",
        "deviceCode": device_code,
        "userCode": user_code,
        "accountId": account_id,
        "createdAt": now,
        "expiresAt": expires_at,
    });
    redis_set_json(&device_key(&device_code), &record, DEVICE_TTL_SECS).await?;

    let approval_base = optional_env("CODEUS_DEVICE_APPROVAL_BASE")
        .unwrap_or_else(|| "https://quantumclub.sh".into());
    let public_base = optional_env("CODEUS_PUBLIC_API_BASE")
        .unwrap_or_else(|| "https://api.quantumclub.sh".into());
    let link_url = format!(
        "{}/codeus/link?code={}&device_code={}",
        approval_base.trim_end_matches('/'),
        user_code,
        device_code
    );
    let poll_url = public_api_url(&public_base, "device/link/poll");

    Ok(json_response(
        StatusCode::OK,
        json!({
            "deviceCode": device_code,
            "device_code": device_code,
            "userCode": user_code,
            "user_code": user_code,
            "linkUrl": link_url,
            "verification_uri": link_url,
            "verification_uri_complete": link_url,
            "pollUrl": poll_url,
            "expiresAt": expires_at,
            "expires_in": DEVICE_TTL_SECS,
            "interval": 2,
        }),
    ))
}

async fn local_device_token_inner(request: Request) -> Result<Response<Body>, ProxyError> {
    require_device_store()?;
    let payload = object_body(read_json(request).await?);
    let device_code = string_field(&Value::Object(payload), &["deviceCode", "device_code"])
        .ok_or_else(|| {
            ProxyError::new(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "Missing device code.",
            )
        })?;
    let key = device_key(&device_code);
    let Some(record) = redis_get_json(&key).await? else {
        return Ok(device_expired_response());
    };

    if is_expired(&record) {
        let _ = redis_del(&key).await;
        return Ok(device_expired_response());
    }

    match record.get("status").and_then(Value::as_str) {
        Some("approved") => Ok(json_response(
            StatusCode::OK,
            json!({
                "status": "approved",
                "sessionToken": record.get("sessionToken"),
                "access_token": record.get("sessionToken"),
                "session_token": record.get("sessionToken"),
                "token_type": "Bearer",
                "userId": record.get("userId"),
                "email": record.get("email"),
                "expiresAt": record.get("sessionExpiresAt"),
                "expires_in": expires_in(record.get("sessionExpiresAt")),
            }),
        )),
        Some("denied") => Ok(json_response(
            StatusCode::GONE,
            json!({
                "status": "denied",
                "error": "access_denied",
                "error_description": "Browser login was denied.",
            }),
        )),
        _ => Ok(json_response(
            StatusCode::ACCEPTED,
            json!({
                "status": "pending",
                "error": "authorization_pending",
                "error_description": "Waiting for browser approval.",
            }),
        )),
    }
}

async fn device_approve_inner(request: Request) -> Result<Response<Body>, ProxyError> {
    require_device_store()?;
    let payload = Value::Object(object_body(read_json(request).await?));
    let device_code = string_field(&payload, &["deviceCode", "device_code"]).ok_or_else(|| {
        ProxyError::new(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Missing device code.",
        )
    })?;
    let user_code =
        string_field(&payload, &["userCode", "user_code", "code"]).ok_or_else(|| {
            ProxyError::new(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "Missing user code.",
            )
        })?;
    let key = device_key(&device_code);
    let Some(mut record) = redis_get_json(&key).await? else {
        return Err(ProxyError::new(
            StatusCode::GONE,
            "expired_token",
            "Browser login expired.",
        ));
    };
    if is_expired(&record) {
        let _ = redis_del(&key).await;
        return Err(ProxyError::new(
            StatusCode::GONE,
            "expired_token",
            "Browser login expired.",
        ));
    }
    let expected = record.get("userCode").and_then(Value::as_str).unwrap_or("");
    if normalize_user_code(expected) != normalize_user_code(&user_code) {
        return Err(ProxyError::new(
            StatusCode::BAD_REQUEST,
            "invalid_user_code",
            "The browser login code did not match.",
        ));
    }

    if payload
        .get("status")
        .and_then(Value::as_str)
        .is_some_and(|status| status.eq_ignore_ascii_case("denied"))
    {
        record["status"] = Value::String("denied".to_string());
        redis_set_json(&key, &record, remaining_device_ttl(&record)).await?;
        return Ok(json_response(StatusCode::OK, json!({ "status": "denied" })));
    }

    let upstream_session_token =
        string_field(&payload, &["sessionToken", "session_token", "access_token"]).ok_or_else(
            || {
                ProxyError::new(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "Missing signed-in browser session token.",
                )
            },
        )?;
    let user_id = string_field(&payload, &["userId", "user_id"]).ok_or_else(|| {
        ProxyError::new(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Missing user id.",
        )
    })?;
    let email = string_field(&payload, &["email", "userEmail", "user_email"]).unwrap_or_default();
    let session_token = random_token(32);
    let session_expires_at = now_millis() + (SESSION_TTL_SECS * 1000);
    let session = json!({
        "token": session_token,
        "upstreamSessionToken": upstream_session_token,
        "userId": user_id,
        "email": email,
        "createdAt": now_millis(),
        "expiresAt": session_expires_at,
        "activePlan": "Anaxonic account",
    });
    redis_set_json(&session_key(&session_token), &session, SESSION_TTL_SECS).await?;

    record["status"] = Value::String("approved".to_string());
    record["sessionToken"] = Value::String(session_token);
    record["userId"] = session.get("userId").cloned().unwrap_or(Value::Null);
    record["email"] = session.get("email").cloned().unwrap_or(Value::Null);
    record["sessionExpiresAt"] = Value::Number(session_expires_at.into());
    redis_set_json(&key, &record, remaining_device_ttl(&record)).await?;

    Ok(json_response(
        StatusCode::OK,
        json!({
            "status": "approved",
            "userId": session.get("userId"),
            "email": session.get("email"),
            "expiresAt": session_expires_at,
        }),
    ))
}

async fn refresh_inner(request: Request) -> Result<Response<Body>, ProxyError> {
    if optional_env("CODEUS_REFRESH_URL").is_none() {
        let token = require_bearer_token(&request)?;
        let session = require_codeus_session(&token).await?;
        return Ok(json_response(
            StatusCode::OK,
            json!({
                "access_token": token,
                "session_token": token,
                "token_type": "Bearer",
                "expires_in": expires_in(session.get("expiresAt")),
            }),
        ));
    }

    let auth_urls =
        configured_url_candidates("CODEUS_REFRESH_URL", "CODEUS_AUTH_BASE", REFRESH_PATHS)?;
    let mut payload = object_body(read_json(request).await?);
    payload.insert(
        "client_id".to_string(),
        Value::String(
            optional_env("CODEUS_OAUTH_CLIENT_ID").unwrap_or_else(|| "codeus-cli".into()),
        ),
    );

    proxy_json_post_candidates(auth_urls, Value::Object(payload)).await
}

async fn account_inner(request: Request) -> Result<Response<Body>, ProxyError> {
    if optional_env("CODEUS_ACCOUNT_URL").is_none() {
        let token = require_bearer_token(&request)?;
        let session = require_codeus_session(&token).await?;
        return Ok(json_response(
            StatusCode::OK,
            json!({
                "id": session.get("userId"),
                "userId": session.get("userId"),
                "email": session.get("email"),
                "activePlan": session.get("activePlan").and_then(Value::as_str).unwrap_or("Anaxonic account"),
            }),
        ));
    }

    let account_urls = configured_account_url_candidates("CODEUS_ACCOUNT_URL", ACCOUNT_PATHS)?;
    let token = bearer_token(&request).ok_or_else(|| {
        ProxyError::new(
            StatusCode::UNAUTHORIZED,
            "not_authenticated",
            "Missing Codeus session token.",
        )
    })?;

    proxy_get_candidates(account_urls, token).await
}

async fn usage_inner(request: Request) -> Result<Response<Body>, ProxyError> {
    if optional_env("CODEUS_USAGE_URL").is_none() {
        let token = require_bearer_token(&request)?;
        let _session = require_codeus_session(&token).await?;
        return Ok(json_response(
            StatusCode::OK,
            json!({
                "plan": "Anaxonic account",
                "usage_remaining": null,
                "remaining": null,
            }),
        ));
    }

    let usage_urls = configured_account_url_candidates("CODEUS_USAGE_URL", USAGE_PATHS)?;
    let token = bearer_token(&request).ok_or_else(|| {
        ProxyError::new(
            StatusCode::UNAUTHORIZED,
            "not_authenticated",
            "Missing Codeus session token.",
        )
    })?;

    proxy_get_candidates(usage_urls, token).await
}

async fn signout_inner(request: Request) -> Result<Response<Body>, ProxyError> {
    if optional_env("CODEUS_SIGNOUT_URL").is_none() {
        if let Some(token) = bearer_token(&request) {
            let _ = redis_del(&session_key(&token)).await;
        }
        return Ok(json_response(
            StatusCode::OK,
            json!({ "status": "signed_out" }),
        ));
    }

    let signout_urls = configured_account_url_candidates("CODEUS_SIGNOUT_URL", SIGNOUT_PATHS)?;
    let token = bearer_token(&request);
    let client = reqwest::Client::new();
    let last_index = signout_urls.len().saturating_sub(1);

    for (index, signout_url) in signout_urls.into_iter().enumerate() {
        let mut builder = client
            .post(&signout_url)
            .header(reqwest::header::CONTENT_TYPE, "application/json");
        if let Some(token) = token.as_ref() {
            builder = builder.bearer_auth(token);
        }
        let response = builder
            .body("{}")
            .send()
            .await
            .map_err(upstream_request_error)?;
        if response.status() != reqwest::StatusCode::NOT_FOUND || index == last_index {
            return Ok(proxy_response(response));
        }
    }

    Err(ProxyError::new(
        StatusCode::INTERNAL_SERVER_ERROR,
        "missing_server_config",
        "No upstream URLs were configured.",
    ))
}

async fn proxy_json_post_candidates(
    urls: Vec<String>,
    body: Value,
) -> Result<Response<Body>, ProxyError> {
    let response = post_json_with_404_fallback(urls, body).await?;
    Ok(text_response(
        status_code(response.status),
        response.headers,
        response.text,
    ))
}

async fn post_json_with_404_fallback(
    urls: Vec<String>,
    body: Value,
) -> Result<UpstreamText, ProxyError> {
    let client = reqwest::Client::new();
    let last_index = urls.len().saturating_sub(1);

    for (index, url) in urls.into_iter().enumerate() {
        let response = client
            .post(url)
            .header(header::CONTENT_TYPE.as_str(), "application/json")
            .json(&body)
            .send()
            .await
            .map_err(upstream_request_error)?;

        let status = response.status();
        let headers = response.headers().clone();
        let text = response.text().await.map_err(upstream_request_error)?;
        if status != reqwest::StatusCode::NOT_FOUND || index == last_index {
            return Ok(UpstreamText {
                status,
                headers,
                text,
            });
        }
    }

    Err(ProxyError::new(
        StatusCode::INTERNAL_SERVER_ERROR,
        "missing_server_config",
        "No upstream URLs were configured.",
    ))
}

async fn post_chat_with_fallback(
    upstreams: Vec<ChatUpstream>,
    user_token: Option<String>,
    body: Value,
) -> Result<reqwest::Response, ProxyError> {
    let client = reqwest::Client::new();
    let last_index = upstreams.len().saturating_sub(1);
    let mut last_failure = None;

    for (index, upstream) in upstreams.into_iter().enumerate() {
        let mut builder = client
            .post(&upstream.url)
            .header(header::CONTENT_TYPE.as_str(), "application/json");

        match &upstream.auth {
            ChatAuth::ServerToken(token) => {
                builder = builder.bearer_auth(token);
                if let Some(user_token) = user_token.as_ref() {
                    builder = builder.header("x-codeus-session-token", user_token);
                }
            }
            ChatAuth::UserBearer => {
                if let Some(user_token) = user_token.as_ref() {
                    builder = builder.bearer_auth(user_token);
                }
            }
        }

        let mut response = match builder.json(&body).send().await {
            Ok(response) => response,
            Err(error) if index < last_index => {
                last_failure = Some(format!("{} request failed: {error}", upstream.name));
                continue;
            }
            Err(error) => return Err(upstream_request_error(error)),
        };

        if should_retry_default_model(&upstream, response.status(), &body) {
            let retry_body = body_with_default_model(&body);
            match post_chat(&client, &upstream, user_token.as_deref(), &retry_body).await {
                Ok(retry) => {
                    if retry.status().is_success() {
                        return Ok(retry);
                    }
                    response = retry;
                }
                Err(error) if index < last_index => {
                    last_failure = Some(format!(
                        "{} default-model retry failed: {error}",
                        upstream.name
                    ));
                    continue;
                }
                Err(error) => return Err(upstream_request_error(error)),
            }
        }

        if response.status().is_success()
            || index == last_index
            || !should_fallback_chat_status(response.status())
        {
            return Ok(response);
        }

        let status = response.status();
        let text = response.text().await.unwrap_or_default();
        last_failure = Some(format!(
            "{} returned {status}: {}",
            upstream.name,
            text.trim()
        ));
    }

    Err(ProxyError::new(
        StatusCode::BAD_GATEWAY,
        "upstream_request_failed",
        last_failure.unwrap_or_else(|| "No chat upstreams were available.".to_string()),
    ))
}

async fn post_chat(
    client: &reqwest::Client,
    upstream: &ChatUpstream,
    user_token: Option<&str>,
    body: &Value,
) -> Result<reqwest::Response, reqwest::Error> {
    let mut builder = client
        .post(&upstream.url)
        .header(header::CONTENT_TYPE.as_str(), "application/json");

    match &upstream.auth {
        ChatAuth::ServerToken(token) => {
            builder = builder.bearer_auth(token);
            if let Some(user_token) = user_token {
                builder = builder.header("x-codeus-session-token", user_token);
            }
        }
        ChatAuth::UserBearer => {
            if let Some(user_token) = user_token {
                builder = builder.bearer_auth(user_token);
            }
        }
    }

    builder.json(body).send().await
}

fn should_retry_default_model(
    upstream: &ChatUpstream,
    status: reqwest::StatusCode,
    body: &Value,
) -> bool {
    upstream.name == "vercel_ai_gateway"
        && status.is_server_error()
        && body
            .get("model")
            .and_then(Value::as_str)
            .is_some_and(|model| model != DEFAULT_CHAT_MODEL)
}

fn body_with_default_model(body: &Value) -> Value {
    let mut retry = body.clone();
    retry["model"] = Value::String(DEFAULT_CHAT_MODEL.to_string());
    retry
}

async fn proxy_get_candidates(
    urls: Vec<String>,
    token: String,
) -> Result<Response<Body>, ProxyError> {
    let client = reqwest::Client::new();
    let last_index = urls.len().saturating_sub(1);

    for (index, url) in urls.into_iter().enumerate() {
        let response = client
            .get(url)
            .bearer_auth(&token)
            .send()
            .await
            .map_err(upstream_request_error)?;

        if response.status() != reqwest::StatusCode::NOT_FOUND || index == last_index {
            return Ok(proxy_response(response));
        }
    }

    Err(ProxyError::new(
        StatusCode::INTERNAL_SERVER_ERROR,
        "missing_server_config",
        "No upstream URLs were configured.",
    ))
}

fn proxy_response(response: reqwest::Response) -> Response<Body> {
    let mut builder = Response::builder().status(status_code(response.status()));
    for (key, value) in response.headers() {
        if key.as_str().eq_ignore_ascii_case("content-encoding") {
            continue;
        }
        if let Ok(value) = value.to_str() {
            builder = builder.header(key.as_str(), value);
        }
    }
    builder = builder.header(header::CACHE_CONTROL, "no-store");

    builder
        .body(Body::from_stream(response.bytes_stream()))
        .unwrap_or_else(|_| internal_error("failed to build upstream response"))
}

fn text_response(
    status: StatusCode,
    headers: reqwest::header::HeaderMap,
    text: String,
) -> Response<Body> {
    let mut builder = Response::builder().status(status);
    for (key, value) in headers.iter() {
        if key.as_str().eq_ignore_ascii_case("content-encoding") {
            continue;
        }
        if let Ok(value) = value.to_str() {
            builder = builder.header(key.as_str(), value);
        }
    }
    builder = builder.header(header::CACHE_CONTROL, "no-store");
    builder
        .body(Body::from(text))
        .unwrap_or_else(|_| internal_error("failed to build upstream response"))
}

async fn read_json(request: Request) -> Result<Value, ProxyError> {
    let bytes = to_bytes(request.into_body(), BODY_LIMIT)
        .await
        .map_err(|_| {
            ProxyError::new(
                StatusCode::BAD_REQUEST,
                "invalid_body",
                "Request body could not be read.",
            )
        })?;

    if bytes.iter().all(u8::is_ascii_whitespace) {
        return Ok(json!({}));
    }

    serde_json::from_slice(&bytes).map_err(|_| {
        ProxyError::new(
            StatusCode::BAD_REQUEST,
            "invalid_json",
            "Request body must be valid JSON.",
        )
    })
}

async fn require_codeus_session(token: &str) -> Result<Value, ProxyError> {
    require_device_store()?;
    let Some(session) = redis_get_json(&session_key(token)).await? else {
        return Err(ProxyError::new(
            StatusCode::UNAUTHORIZED,
            "not_authenticated",
            "Codeus session is missing or expired.",
        ));
    };
    if is_expired(&session) {
        let _ = redis_del(&session_key(token)).await;
        return Err(ProxyError::new(
            StatusCode::UNAUTHORIZED,
            "not_authenticated",
            "Codeus session expired.",
        ));
    }
    Ok(session)
}

fn require_device_store() -> Result<(), ProxyError> {
    if redis_base().is_some() && redis_token().is_some() {
        return Ok(());
    }
    Err(ProxyError::new(
        StatusCode::INTERNAL_SERVER_ERROR,
        "missing_server_config",
        "Missing Upstash Redis REST configuration. Set UPSTASH_REDIS_REST_URL and UPSTASH_REDIS_REST_TOKEN.",
    ))
}

async fn redis_set_json(key: &str, value: &Value, ttl_secs: u64) -> Result<(), ProxyError> {
    let payload = json!(["SET", key, value.to_string(), "EX", ttl_secs]);
    let response = redis_command(payload).await?;
    if response.get("error").is_some() {
        return Err(ProxyError::new(
            StatusCode::BAD_GATEWAY,
            "redis_error",
            response.to_string(),
        ));
    }
    Ok(())
}

async fn redis_get_json(key: &str) -> Result<Option<Value>, ProxyError> {
    let response = redis_command(json!(["GET", key])).await?;
    let Some(raw) = response.get("result") else {
        return Ok(None);
    };
    if raw.is_null() {
        return Ok(None);
    }
    let Some(text) = raw.as_str() else {
        return Err(ProxyError::new(
            StatusCode::BAD_GATEWAY,
            "invalid_store_response",
            "Redis GET returned a non-string value.",
        ));
    };
    serde_json::from_str(text).map(Some).map_err(|_| {
        ProxyError::new(
            StatusCode::BAD_GATEWAY,
            "invalid_store_json",
            "Stored Codeus session data was not valid JSON.",
        )
    })
}

async fn redis_del(key: &str) -> Result<(), ProxyError> {
    let _ = redis_command(json!(["DEL", key])).await?;
    Ok(())
}

async fn redis_command(command: Value) -> Result<Value, ProxyError> {
    let base = redis_base().ok_or_else(|| {
        ProxyError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "missing_server_config",
            "Missing UPSTASH_REDIS_REST_URL.",
        )
    })?;
    let token = redis_token().ok_or_else(|| {
        ProxyError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "missing_server_config",
            "Missing UPSTASH_REDIS_REST_TOKEN.",
        )
    })?;

    let response = reqwest::Client::new()
        .post(base)
        .bearer_auth(token)
        .header(header::CONTENT_TYPE.as_str(), "application/json")
        .json(&command)
        .send()
        .await
        .map_err(upstream_request_error)?;
    let status = response.status();
    let text = response.text().await.map_err(upstream_request_error)?;
    if !status.is_success() {
        return Err(ProxyError::new(
            StatusCode::BAD_GATEWAY,
            "redis_error",
            format!("Redis command failed ({status}): {}", text.trim()),
        ));
    }
    serde_json::from_str(&text).map_err(|_| {
        ProxyError::new(
            StatusCode::BAD_GATEWAY,
            "invalid_store_response",
            "Redis response was not valid JSON.",
        )
    })
}

fn redis_base() -> Option<String> {
    optional_env("UPSTASH_REDIS_REST_URL")
        .or_else(|| optional_env("KV_REST_API_URL"))
        .map(|url| url.trim_end_matches('/').to_string())
}

fn redis_token() -> Option<String> {
    optional_env("UPSTASH_REDIS_REST_TOKEN").or_else(|| optional_env("KV_REST_API_TOKEN"))
}

fn optional_env(name: &str) -> Option<String> {
    env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn configured_url_candidates(
    override_name: &str,
    base_name: &'static str,
    paths: &[&str],
) -> Result<Vec<String>, ProxyError> {
    configured_url_candidates_from_lookup(override_name, base_name, paths, optional_env)
}

fn configured_url_candidates_from_lookup<F>(
    override_name: &str,
    base_name: &'static str,
    paths: &[&str],
    mut lookup: F,
) -> Result<Vec<String>, ProxyError>
where
    F: FnMut(&str) -> Option<String>,
{
    if let Some(url) = lookup(override_name) {
        return Ok(vec![url]);
    }

    let base = lookup(base_name).ok_or_else(|| {
        ProxyError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "missing_server_config",
            format!("Missing required server environment variable: {base_name}."),
        )
    })?;
    Ok(paths.iter().map(|path| upstream_url(&base, path)).collect())
}

fn chat_upstream_candidates(user_token_available: bool) -> Result<Vec<ChatUpstream>, ProxyError> {
    chat_upstream_candidates_from_lookup(user_token_available, optional_env)
}

fn chat_upstream_candidates_from_lookup<F>(
    user_token_available: bool,
    mut lookup: F,
) -> Result<Vec<ChatUpstream>, ProxyError>
where
    F: FnMut(&str) -> Option<String>,
{
    let mut candidates = Vec::new();

    let vercel_token = lookup("AI_GATEWAY_API_KEY").or_else(|| lookup("VERCEL_OIDC_TOKEN"));
    if let Some(token) = vercel_token {
        let url = lookup("CODEUS_VERCEL_AI_GATEWAY_CHAT_COMPLETIONS_URL").unwrap_or_else(|| {
            upstream_url(
                &lookup("CODEUS_VERCEL_AI_GATEWAY_BASE")
                    .or_else(|| lookup("AI_GATEWAY_BASE_URL"))
                    .unwrap_or_else(|| "https://ai-gateway.vercel.sh/v1".to_string()),
                "chat/completions",
            )
        });
        candidates.push(ChatUpstream {
            name: "vercel_ai_gateway",
            url,
            auth: ChatAuth::ServerToken(token),
        });
    }

    if env_flag(&mut lookup, "CODEUS_ENABLE_LEGACY_LLM_GATEWAY") {
        if let Some(url) = lookup("CODEUS_CHAT_COMPLETIONS_URL").or_else(|| {
            lookup("CODEUS_CHAT_BASE").map(|base| upstream_url(&base, "chat/completions"))
        }) {
            let auth = lookup("CODEUS_CHAT_API_KEY")
                .map(ChatAuth::ServerToken)
                .unwrap_or(ChatAuth::UserBearer);
            candidates.push(ChatUpstream {
                name: "llm_gateway",
                url,
                auth,
            });
        }
    }

    if candidates.is_empty() {
        let detail = if user_token_available {
            "A user session token is present, but no OpenAI-compatible chat gateway URL is configured."
        } else {
            "No user session token or OpenAI-compatible chat gateway URL is configured."
        };
        return Err(ProxyError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "missing_server_config",
            format!("{detail} Configure AI_GATEWAY_API_KEY/VERCEL_OIDC_TOKEN for Vercel AI Gateway. Legacy LLM gateway routing requires CODEUS_ENABLE_LEGACY_LLM_GATEWAY=1 plus CODEUS_CHAT_BASE/CODEUS_CHAT_COMPLETIONS_URL."),
        ));
    }

    Ok(candidates)
}

fn env_flag<F>(lookup: &mut F, name: &str) -> bool
where
    F: FnMut(&str) -> Option<String>,
{
    matches!(
        lookup(name)
            .as_deref()
            .map(str::trim)
            .map(str::to_ascii_lowercase)
            .as_deref(),
        Some("1" | "true" | "yes" | "on")
    )
}

fn configured_account_url_candidates(
    override_name: &str,
    paths: &[&str],
) -> Result<Vec<String>, ProxyError> {
    configured_account_url_candidates_from_lookup(override_name, paths, optional_env)
}

fn configured_account_url_candidates_from_lookup<F>(
    override_name: &str,
    paths: &[&str],
    mut lookup: F,
) -> Result<Vec<String>, ProxyError>
where
    F: FnMut(&str) -> Option<String>,
{
    if let Some(url) = lookup(override_name) {
        return Ok(vec![url]);
    }

    let base = lookup("CODEUS_ACCOUNT_BASE").map(Ok).unwrap_or_else(|| {
        lookup("CODEUS_AUTH_BASE").ok_or_else(|| {
            ProxyError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "missing_server_config",
                "Missing required server environment variable: CODEUS_AUTH_BASE.",
            )
        })
    })?;
    Ok(paths.iter().map(|path| upstream_url(&base, path)).collect())
}

fn bearer_token(request: &Request) -> Option<String> {
    let authorization = request
        .headers()
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .trim();
    let (scheme, token) = authorization.split_once(char::is_whitespace)?;
    if scheme.eq_ignore_ascii_case("bearer") {
        let token = token.trim();
        if !token.is_empty() {
            return Some(token.to_string());
        }
    }
    None
}

fn require_bearer_token(request: &Request) -> Result<String, ProxyError> {
    bearer_token(request).ok_or_else(|| {
        ProxyError::new(
            StatusCode::UNAUTHORIZED,
            "not_authenticated",
            "Missing Codeus session token.",
        )
    })
}

fn upstream_url(base: &str, path: &str) -> String {
    format!(
        "{}/{}",
        base.trim_end_matches('/'),
        path.trim_start_matches('/')
    )
}

fn public_api_url(base: &str, path_after_v1: &str) -> String {
    let base = base.trim_end_matches('/');
    if base.ends_with("/v1") {
        upstream_url(base, path_after_v1)
    } else {
        upstream_url(base, &format!("v1/{path_after_v1}"))
    }
}

fn device_key(device_code: &str) -> String {
    format!("codeus:device:{device_code}")
}

fn session_key(session_token: &str) -> String {
    format!("codeus:session:{session_token}")
}

fn random_token(bytes_len: usize) -> String {
    let mut bytes = vec![0_u8; bytes_len];
    rand::rng().fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn random_user_code() -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let mut bytes = [0_u8; 8];
    rand::rng().fill_bytes(&mut bytes);
    let code: String = bytes
        .iter()
        .map(|byte| ALPHABET[(*byte as usize) % ALPHABET.len()] as char)
        .collect();
    format!("{}-{}", &code[..4], &code[4..])
}

fn normalize_user_code(value: &str) -> String {
    value
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .flat_map(char::to_uppercase)
        .collect()
}

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

fn is_expired(value: &Value) -> bool {
    value
        .get("expiresAt")
        .and_then(Value::as_u64)
        .is_some_and(|expires_at| expires_at <= now_millis())
}

fn remaining_device_ttl(value: &Value) -> u64 {
    value
        .get("expiresAt")
        .and_then(Value::as_u64)
        .map(|expires_at| expires_at.saturating_sub(now_millis()).saturating_div(1000))
        .unwrap_or(DEVICE_TTL_SECS)
        .max(1)
}

fn string_field(value: &Value, keys: &[&str]) -> Option<String> {
    let object = value.as_object()?;
    keys.iter().find_map(|key| {
        object
            .get(*key)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|text| !text.is_empty())
            .map(ToString::to_string)
    })
}

fn device_expired_response() -> Response<Body> {
    json_response(
        StatusCode::GONE,
        json!({
            "status": "expired",
            "error": "expired_token",
            "error_description": "Browser login expired.",
        }),
    )
}

fn object_body(value: Value) -> Map<String, Value> {
    match value {
        Value::Object(map) => map,
        _ => Map::new(),
    }
}

fn parse_upstream_json(text: &str) -> Result<Value, ProxyError> {
    serde_json::from_str(text).map_err(|_| {
        ProxyError::new(
            StatusCode::BAD_GATEWAY,
            "invalid_upstream_json",
            "Upstream response was not valid JSON.",
        )
    })
}

fn expires_in(value: Option<&Value>) -> Option<u64> {
    let expires_at = value.and_then(Value::as_u64)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()?
        .as_millis() as u64;
    Some(expires_at.saturating_sub(now).saturating_div(1000).max(1))
}

fn status_code(status: reqwest::StatusCode) -> StatusCode {
    StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::BAD_GATEWAY)
}

fn should_fallback_chat_status(status: reqwest::StatusCode) -> bool {
    matches!(status.as_u16(), 402 | 408 | 409 | 425 | 429 | 500..=599)
}

fn upstream_request_error(error: reqwest::Error) -> ProxyError {
    ProxyError::new(
        StatusCode::BAD_GATEWAY,
        "upstream_request_failed",
        error.to_string(),
    )
}

fn oauth_error(error: &'static str, description: &'static str) -> Response<Body> {
    json_response(
        StatusCode::BAD_REQUEST,
        json!({
            "error": error,
            "error_description": description,
        }),
    )
}

fn respond(result: Result<Response<Body>, ProxyError>) -> Response<Body> {
    match result {
        Ok(response) => response,
        Err(error) => json_response(
            error.status,
            json!({
                "error": error.code,
                "error_description": error.message,
            }),
        ),
    }
}

fn json_response(status: StatusCode, body: Value) -> Response<Body> {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json; charset=utf-8")
        .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
        .header(header::ACCESS_CONTROL_ALLOW_HEADERS, CORS_ALLOW_HEADERS)
        .header(header::ACCESS_CONTROL_ALLOW_METHODS, CORS_ALLOW_METHODS)
        .header(header::CACHE_CONTROL, "no-store")
        .body(Body::from(body.to_string()))
        .unwrap_or_else(|_| internal_error("failed to build JSON response"))
}

fn internal_error(message: &'static str) -> Response<Body> {
    Response::builder()
        .status(StatusCode::INTERNAL_SERVER_ERROR)
        .header(header::CONTENT_TYPE, "application/json; charset=utf-8")
        .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
        .header(header::ACCESS_CONTROL_ALLOW_HEADERS, CORS_ALLOW_HEADERS)
        .header(header::ACCESS_CONTROL_ALLOW_METHODS, CORS_ALLOW_METHODS)
        .header(header::CACHE_CONTROL, "no-store")
        .body(Body::from(
            json!({
                "error": "server_error",
                "error_description": message,
            })
            .to_string(),
        ))
        .expect("static internal error response should be valid")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn chat_upstreams_use_vercel_without_implicit_llm_fallback() {
        let env = HashMap::from([
            ("AI_GATEWAY_API_KEY", "vercel-key"),
            ("CODEUS_CHAT_BASE", "https://llm.example/v1"),
            ("CODEUS_CHAT_API_KEY", "llm-key"),
        ]);

        let candidates = chat_upstream_candidates_from_lookup(false, |key| {
            env.get(key).map(|value| value.to_string())
        })
        .unwrap();

        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].name, "vercel_ai_gateway");
        assert_eq!(
            candidates[0].url,
            "https://ai-gateway.vercel.sh/v1/chat/completions"
        );
        assert_eq!(
            candidates[0].auth,
            ChatAuth::ServerToken("vercel-key".to_string())
        );
    }

    #[test]
    fn chat_upstreams_can_opt_into_legacy_llm_gateway_fallback() {
        let env = HashMap::from([
            ("AI_GATEWAY_API_KEY", "vercel-key"),
            ("CODEUS_CHAT_BASE", "https://llm.example/v1"),
            ("CODEUS_CHAT_API_KEY", "llm-key"),
            ("CODEUS_ENABLE_LEGACY_LLM_GATEWAY", "1"),
        ]);

        let candidates = chat_upstream_candidates_from_lookup(false, |key| {
            env.get(key).map(|value| value.to_string())
        })
        .unwrap();

        assert_eq!(candidates.len(), 2);
        assert_eq!(candidates[0].name, "vercel_ai_gateway");
        assert_eq!(candidates[1].name, "llm_gateway");
        assert_eq!(candidates[1].url, "https://llm.example/v1/chat/completions");
        assert_eq!(
            candidates[1].auth,
            ChatAuth::ServerToken("llm-key".to_string())
        );
    }

    #[test]
    fn chat_upstreams_keep_existing_llm_gateway_without_vercel_key() {
        let env = HashMap::from([
            ("CODEUS_CHAT_COMPLETIONS_URL", "https://llm.example/chat"),
            ("CODEUS_ENABLE_LEGACY_LLM_GATEWAY", "true"),
        ]);

        let candidates = chat_upstream_candidates_from_lookup(true, |key| {
            env.get(key).map(|value| value.to_string())
        })
        .unwrap();

        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].name, "llm_gateway");
        assert_eq!(candidates[0].url, "https://llm.example/chat");
        assert_eq!(candidates[0].auth, ChatAuth::UserBearer);
    }

    #[test]
    fn chat_upstreams_reject_legacy_gateway_without_opt_in() {
        let env = HashMap::from([("CODEUS_CHAT_COMPLETIONS_URL", "https://llm.example/chat")]);

        let error = chat_upstream_candidates_from_lookup(true, |key| {
            env.get(key).map(|value| value.to_string())
        })
        .unwrap_err();

        assert_eq!(error.code, "missing_server_config");
        assert!(error.message.contains("Vercel AI Gateway"));
    }

    #[test]
    fn chat_requires_codeus_session_token_before_using_gateway() {
        let request = Request::builder().body(Body::empty()).unwrap();

        let error = require_bearer_token(&request).unwrap_err();

        assert_eq!(error.status, StatusCode::UNAUTHORIZED);
        assert_eq!(error.code, "not_authenticated");
        assert!(error.message.contains("Missing Codeus session token"));
    }

    #[test]
    fn device_code_candidates_try_website_api_namespace_first() {
        let env = HashMap::from([("CODEUS_AUTH_BASE", "https://anaxonic.com")]);

        let candidates = configured_url_candidates_from_lookup(
            "CODEUS_DEVICE_CODE_URL",
            "CODEUS_AUTH_BASE",
            DEVICE_CODE_PATHS,
            |key| env.get(key).map(|value| value.to_string()),
        )
        .unwrap();

        assert_eq!(
            candidates.first().map(String::as_str),
            Some("https://anaxonic.com/api/codeus/v1/device/link/init")
        );
        assert!(candidates
            .iter()
            .any(|url| url == "https://anaxonic.com/device/link/init"));
    }

    #[test]
    fn exact_device_code_url_override_disables_fallback_candidates() {
        let env = HashMap::from([
            ("CODEUS_AUTH_BASE", "https://anaxonic.com"),
            (
                "CODEUS_DEVICE_CODE_URL",
                "https://auth.anaxonic.com/device/code",
            ),
        ]);

        let candidates = configured_url_candidates_from_lookup(
            "CODEUS_DEVICE_CODE_URL",
            "CODEUS_AUTH_BASE",
            DEVICE_CODE_PATHS,
            |key| env.get(key).map(|value| value.to_string()),
        )
        .unwrap();

        assert_eq!(candidates, vec!["https://auth.anaxonic.com/device/code"]);
    }

    #[test]
    fn account_candidates_try_website_api_namespace_first() {
        let env = HashMap::from([("CODEUS_AUTH_BASE", "https://anaxonic.com")]);

        let candidates = configured_account_url_candidates_from_lookup(
            "CODEUS_ACCOUNT_URL",
            ACCOUNT_PATHS,
            |key| env.get(key).map(|value| value.to_string()),
        )
        .unwrap();

        assert_eq!(
            candidates,
            vec![
                "https://anaxonic.com/api/codeus/v1/auth/whoami",
                "https://anaxonic.com/auth/whoami"
            ]
        );
    }

    #[test]
    fn account_base_overrides_auth_base_for_account_candidates() {
        let env = HashMap::from([
            ("CODEUS_AUTH_BASE", "https://anaxonic.com"),
            ("CODEUS_ACCOUNT_BASE", "https://account.anaxonic.com"),
        ]);

        let candidates =
            configured_account_url_candidates_from_lookup("CODEUS_USAGE_URL", USAGE_PATHS, |key| {
                env.get(key).map(|value| value.to_string())
            })
            .unwrap();

        assert_eq!(
            candidates.first().map(String::as_str),
            Some("https://account.anaxonic.com/api/codeus/v1/balance")
        );
    }

    #[test]
    fn public_api_url_accepts_base_with_or_without_v1() {
        assert_eq!(
            public_api_url("https://api.quantumclub.sh", "device/link/poll"),
            "https://api.quantumclub.sh/v1/device/link/poll"
        );
        assert_eq!(
            public_api_url("https://api.quantumclub.sh/v1", "device/link/poll"),
            "https://api.quantumclub.sh/v1/device/link/poll"
        );
    }

    #[test]
    fn vercel_gateway_5xx_retries_non_default_model_with_default_model() {
        let upstream = ChatUpstream {
            name: "vercel_ai_gateway",
            url: "https://ai-gateway.vercel.sh/v1/chat/completions".to_string(),
            auth: ChatAuth::ServerToken("key".to_string()),
        };
        let body = json!({ "model": "anthropic/claude-haiku-4.5" });

        assert!(should_retry_default_model(
            &upstream,
            reqwest::StatusCode::INTERNAL_SERVER_ERROR,
            &body
        ));
        assert_eq!(
            body_with_default_model(&body)
                .get("model")
                .and_then(Value::as_str),
            Some(DEFAULT_CHAT_MODEL)
        );
    }

    #[test]
    fn vercel_gateway_does_not_retry_default_model_again() {
        let upstream = ChatUpstream {
            name: "vercel_ai_gateway",
            url: "https://ai-gateway.vercel.sh/v1/chat/completions".to_string(),
            auth: ChatAuth::ServerToken("key".to_string()),
        };
        let body = json!({ "model": DEFAULT_CHAT_MODEL });

        assert!(!should_retry_default_model(
            &upstream,
            reqwest::StatusCode::INTERNAL_SERVER_ERROR,
            &body
        ));
    }

    #[test]
    fn fallback_statuses_cover_credit_and_rate_limit_failures() {
        assert!(should_fallback_chat_status(
            reqwest::StatusCode::PAYMENT_REQUIRED
        ));
        assert!(should_fallback_chat_status(
            reqwest::StatusCode::TOO_MANY_REQUESTS
        ));
        assert!(should_fallback_chat_status(
            reqwest::StatusCode::BAD_GATEWAY
        ));
        assert!(!should_fallback_chat_status(
            reqwest::StatusCode::BAD_REQUEST
        ));
        assert!(!should_fallback_chat_status(
            reqwest::StatusCode::UNAUTHORIZED
        ));
    }
}
