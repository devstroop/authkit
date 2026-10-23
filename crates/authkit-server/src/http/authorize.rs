//! OAuth/OIDC authorization endpoint and consent form.

use std::collections::HashSet;

use authkit_core::domain::{
    AuditActor, ClientId, ErrorCode, GrantType, Nonce, PkceChallenge, RedirectUri, Scope, ScopeSet,
};
use axum::extract::{Extension, RawForm, RawQuery, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};

use crate::authorization::{AuthorizationService, ClientContext, ConsentMode, IssueCode};
use crate::http::error::OAuthErrorCode;
use crate::http::request_id::RequestId;
use crate::http::routes::AppState;
use crate::http::session::SessionContext;

const MAX_STATE_LEN: usize = 2_048;
const MAX_QUERY_LEN: usize = 16 * 1024;
const MAX_FORM_LEN: usize = 64 * 1024;
const MAX_PARAMETERS: usize = 64;
const MAX_PARAMETER_NAME: usize = 64;
const MAX_PARAMETER_VALUE: usize = 8 * 1024;
const MAX_MAX_AGE_SECS: u64 = 30 * 24 * 60 * 60;

/// Handles a browser authorization request.
pub(crate) async fn authorize(
    State(state): State<AppState>,
    session: Option<Extension<SessionContext>>,
    request_id: Option<Extension<RequestId>>,
    RawQuery(query): RawQuery,
) -> Response {
    let request_id = request_id_string(request_id.as_ref());
    let Some(service) = state.authorization.as_deref() else {
        return error_page(
            StatusCode::NOT_FOUND,
            "Not found",
            "The authorization endpoint is not available.",
        );
    };
    let params = match Params::from_query(query.as_deref()) {
        Ok(params) => params,
        Err(()) => {
            reject_local(service, &request_id, "malformed_query").await;
            return error_page(
                StatusCode::BAD_REQUEST,
                "Invalid request",
                "The authorization request could not be parsed.",
            );
        }
    };

    let Some(client_id) = params
        .get("client_id")
        .and_then(|value| ClientId::parse(value).ok())
    else {
        reject_local(service, &request_id, "invalid_client_id").await;
        return error_page(
            StatusCode::BAD_REQUEST,
            "Invalid request",
            "The client identifier is missing or invalid.",
        );
    };
    let context = match service.resolve_client(&client_id).await {
        Ok(Some(context)) => context,
        Ok(None) => {
            reject_local(service, &request_id, "unknown_client").await;
            return error_page(
                StatusCode::BAD_REQUEST,
                "Invalid request",
                "The client is unknown or disabled.",
            );
        }
        Err(error) => return unavailable(error),
    };

    let redirect_uri = match registered_redirect(&params, &context) {
        Some(redirect_uri) => redirect_uri,
        None => {
            reject_context(
                service,
                &context,
                &request_id,
                "invalid_redirect_uri",
                AuditActor::Anonymous,
            )
            .await;
            return error_page(
                StatusCode::BAD_REQUEST,
                "Invalid request",
                "The redirect URI is not registered for this client.",
            );
        }
    };
    let state_value = optional_state(&params);

    let validated = match validate(&params, &context, &redirect_uri) {
        Ok(validated) => validated,
        Err(error) => {
            reject_context(
                service,
                &context,
                &request_id,
                error.reason,
                AuditActor::Anonymous,
            )
            .await;
            return error_redirect(
                &redirect_uri,
                error.code,
                error.description,
                state_value.as_deref(),
            );
        }
    };

    let Some(Extension(session)) = session else {
        if validated.prompt_none {
            reject_context(
                service,
                &context,
                &request_id,
                "session_required",
                AuditActor::Anonymous,
            )
            .await;
            return error_redirect(
                &redirect_uri,
                OAuthErrorCode::LoginRequired,
                "the end user must sign in",
                state_value.as_deref(),
            );
        }
        reject_context(
            service,
            &context,
            &request_id,
            "session_required",
            AuditActor::Anonymous,
        )
        .await;
        return error_page(
            StatusCode::UNAUTHORIZED,
            "Sign in required",
            "An active AuthKit session is required to authorize this client.",
        );
    };

    if let Some(max_age) = validated.max_age_secs
        && session_is_stale(service, &session, max_age)
    {
        if validated.prompt_none {
            return error_redirect(
                &redirect_uri,
                OAuthErrorCode::LoginRequired,
                "the end user must sign in again",
                state_value.as_deref(),
            );
        }
        return error_page(
            StatusCode::UNAUTHORIZED,
            "Sign in required",
            "This request requires fresh authentication.",
        );
    }

    match membership_active(service, &context, &session).await {
        Ok(true) => {}
        Ok(false) => {
            reject_context(
                service,
                &context,
                &request_id,
                "membership_required",
                AuditActor::User(session.session().user_id().clone()),
            )
            .await;
            return error_redirect(
                &redirect_uri,
                OAuthErrorCode::AccessDenied,
                "the user is not an active member of this organization",
                state_value.as_deref(),
            );
        }
        Err(error) => return unavailable(error),
    }

    let consent = match service.consent(&context, session.session().user_id()).await {
        Ok(consent) => consent,
        Err(error) => return unavailable(error),
    };
    let covered = consent
        .as_ref()
        .is_some_and(|consent| consent.is_active() && consent.covers(&validated.scopes));
    let needs_consent = validated.prompt_consent || !covered;

    if needs_consent && validated.prompt_consent {
        return render_consent(&context, &validated, session.csrf_token());
    }
    if needs_consent && !context.application().is_first_party() {
        if validated.prompt_none {
            reject_context(
                service,
                &context,
                &request_id,
                "consent_required",
                AuditActor::User(session.session().user_id().clone()),
            )
            .await;
            return error_redirect(
                &redirect_uri,
                OAuthErrorCode::ConsentRequired,
                "the end user must grant consent",
                state_value.as_deref(),
            );
        }
        return render_consent(&context, &validated, session.csrf_token());
    }

    let mode = if !needs_consent {
        ConsentMode::Reuse
    } else if context.application().is_first_party() {
        ConsentMode::Automatic
    } else {
        ConsentMode::Explicit
    };
    issue(service, &context, &session, &validated, &request_id, mode).await
}

/// Handles an explicit consent decision.
pub(crate) async fn consent(
    State(state): State<AppState>,
    session: Option<Extension<SessionContext>>,
    request_id: Option<Extension<RequestId>>,
    RawForm(body): RawForm,
) -> Response {
    let request_id = request_id_string(request_id.as_ref());
    let Some(service) = state.authorization.as_deref() else {
        return error_page(
            StatusCode::NOT_FOUND,
            "Not found",
            "The authorization endpoint is not available.",
        );
    };
    let Some(Extension(session)) = session else {
        return error_page(
            StatusCode::UNAUTHORIZED,
            "Sign in required",
            "An active AuthKit session is required to decide consent.",
        );
    };

    if body.len() > MAX_FORM_LEN {
        return error_page(
            StatusCode::PAYLOAD_TOO_LARGE,
            "Request too large",
            "The consent form is too large.",
        );
    }
    let params = match Params::from_form(&body) {
        Ok(params) => params,
        Err(()) => {
            return error_page(
                StatusCode::BAD_REQUEST,
                "Invalid request",
                "The consent form could not be parsed.",
            );
        }
    };
    let Some(decision) = params.get("decision") else {
        return error_page(
            StatusCode::BAD_REQUEST,
            "Invalid request",
            "A consent decision is required.",
        );
    };
    let allow = match decision {
        "allow" => true,
        "deny" => false,
        _ => {
            return error_page(
                StatusCode::BAD_REQUEST,
                "Invalid request",
                "The consent decision is invalid.",
            );
        }
    };

    let Some(client_id) = params
        .get("client_id")
        .and_then(|value| ClientId::parse(value).ok())
    else {
        return error_page(
            StatusCode::BAD_REQUEST,
            "Invalid request",
            "The client identifier is missing or invalid.",
        );
    };
    let context = match service.resolve_client(&client_id).await {
        Ok(Some(context)) => context,
        Ok(None) => {
            return error_page(
                StatusCode::BAD_REQUEST,
                "Invalid request",
                "The client is unknown or disabled.",
            );
        }
        Err(error) => return unavailable(error),
    };
    let Some(redirect_uri) = registered_redirect(&params, &context) else {
        reject_context(
            service,
            &context,
            &request_id,
            "invalid_redirect_uri",
            AuditActor::User(session.session().user_id().clone()),
        )
        .await;
        return error_page(
            StatusCode::BAD_REQUEST,
            "Invalid request",
            "The redirect URI is not registered for this client.",
        );
    };
    let state_value = optional_state(&params);
    let validated = match validate(&params, &context, &redirect_uri) {
        Ok(validated) => validated,
        Err(error) => {
            reject_context(
                service,
                &context,
                &request_id,
                error.reason,
                AuditActor::Anonymous,
            )
            .await;
            return error_redirect(
                &redirect_uri,
                error.code,
                error.description,
                state_value.as_deref(),
            );
        }
    };
    match membership_active(service, &context, &session).await {
        Ok(true) => {}
        Ok(false) => {
            reject_context(
                service,
                &context,
                &request_id,
                "membership_required",
                AuditActor::User(session.session().user_id().clone()),
            )
            .await;
            return error_redirect(
                &redirect_uri,
                OAuthErrorCode::AccessDenied,
                "the user is not an active member of this organization",
                state_value.as_deref(),
            );
        }
        Err(error) => return unavailable(error),
    }

    if !allow {
        if let Err(error) = service
            .record_denial(&context, session.session().user_id(), &request_id)
            .await
        {
            tracing::warn!(
                event = "authorization.audit_failed",
                request_id = %request_id,
                error = %error,
                "could not append consent denial audit event"
            );
        }
        return error_redirect(
            &redirect_uri,
            OAuthErrorCode::AccessDenied,
            "the resource owner denied the request",
            state_value.as_deref(),
        );
    }

    if let Some(max_age) = validated.max_age_secs
        && session_is_stale(service, &session, max_age)
    {
        return error_page(
            StatusCode::UNAUTHORIZED,
            "Sign in required",
            "This request requires fresh authentication.",
        );
    }

    issue(
        service,
        &context,
        &session,
        &validated,
        &request_id,
        ConsentMode::Explicit,
    )
    .await
}

/// Serves the small authorization stylesheet through the strict CSP.
pub(crate) async fn stylesheet() -> Response {
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "text/css; charset=utf-8"),
            (header::CACHE_CONTROL, "public, max-age=3600"),
        ],
        AUTHORIZE_CSS,
    )
        .into_response()
}

async fn issue(
    service: &AuthorizationService,
    context: &ClientContext,
    session: &SessionContext,
    validated: &Validated,
    request_id: &str,
    consent_mode: ConsentMode,
) -> Response {
    let result = service
        .issue_code(IssueCode {
            context: context.clone(),
            user_id: session.session().user_id().clone(),
            session_id: session.session().id().clone(),
            auth_time: session.session().created_at(),
            redirect_uri: validated.redirect_uri.clone(),
            scopes: validated.scopes.clone(),
            nonce: validated.nonce.clone(),
            pkce_challenge: validated.pkce_challenge.clone(),
            request_id: request_id.to_owned(),
            consent_mode,
        })
        .await;
    match result {
        Ok(code) => success_redirect(&validated.redirect_uri, &code, validated.state.as_deref()),
        Err(error) if error.code() == ErrorCode::Forbidden => {
            reject_context(
                service,
                context,
                request_id,
                "membership_required",
                AuditActor::User(session.session().user_id().clone()),
            )
            .await;
            error_redirect(
                &validated.redirect_uri,
                OAuthErrorCode::AccessDenied,
                "the user is not an active member of this organization",
                validated.state.as_deref(),
            )
        }
        Err(error) if error.code() == ErrorCode::InvalidInput => {
            tracing::warn!(
                event = "authorization.invalid_issuance",
                request_id = %request_id,
                error = %error,
                "authorization code issuance rejected an invalid request"
            );
            error_page(
                StatusCode::BAD_REQUEST,
                "Invalid request",
                "The authorization request is no longer valid.",
            )
        }
        Err(error) => unavailable(error),
    }
}

async fn membership_active(
    service: &AuthorizationService,
    context: &ClientContext,
    session: &SessionContext,
) -> Result<bool, authkit_core::domain::DomainError> {
    Ok(service
        .membership(context, session.session().user_id())
        .await?
        .is_some_and(|membership| membership.is_active()))
}

fn registered_redirect(params: &Params, context: &ClientContext) -> Option<RedirectUri> {
    let candidate = params.get("redirect_uri")?;
    let candidate = RedirectUri::parse(candidate).ok()?;
    context
        .client()
        .redirect_uris()
        .iter()
        .any(|registered| registered == &candidate)
        .then_some(candidate)
}

fn validate(
    params: &Params,
    context: &ClientContext,
    redirect_uri: &RedirectUri,
) -> Result<Validated, ProtocolError> {
    let response_type = params.get("response_type").ok_or(ProtocolError::new(
        OAuthErrorCode::InvalidRequest,
        "response_type is required",
        "response_type",
    ))?;
    if response_type != "code" {
        return Err(ProtocolError::new(
            OAuthErrorCode::UnsupportedResponseType,
            "only response_type=code is supported",
            "unsupported_response_type",
        ));
    }

    if params.get("request").is_some() || params.get("request_uri").is_some() {
        return Err(ProtocolError::new(
            OAuthErrorCode::InvalidRequest,
            "request objects are not supported",
            "request_object",
        ));
    }
    if params.get("claims").is_some() {
        return Err(ProtocolError::new(
            OAuthErrorCode::InvalidRequest,
            "the claims parameter is not supported",
            "claims_parameter",
        ));
    }
    if params.get("acr_values").is_some() {
        return Err(ProtocolError::new(
            OAuthErrorCode::InvalidRequest,
            "acr_values is not supported",
            "acr_values",
        ));
    }
    if params.get("resource").is_some() {
        return Err(ProtocolError::new(
            OAuthErrorCode::InvalidRequest,
            "resource indicators are not supported",
            "resource_parameter",
        ));
    }
    if let Some(response_mode) = params.get("response_mode")
        && response_mode != "query"
    {
        return Err(ProtocolError::new(
            OAuthErrorCode::InvalidRequest,
            "only response_mode=query is supported",
            "response_mode",
        ));
    }

    if !context.client().allows_grant(GrantType::AuthorizationCode) {
        return Err(ProtocolError::new(
            OAuthErrorCode::UnauthorizedClient,
            "the client may not use the authorization code grant",
            "grant_not_allowed",
        ));
    }

    let raw_scope = params.get("scope").ok_or(ProtocolError::new(
        OAuthErrorCode::InvalidScope,
        "scope is required",
        "missing_scope",
    ))?;
    let mut scopes = Vec::new();
    for scope in raw_scope.split_whitespace() {
        let scope = Scope::parse(scope).map_err(|_| {
            ProtocolError::new(
                OAuthErrorCode::InvalidScope,
                "the requested scope is invalid",
                "invalid_scope",
            )
        })?;
        if !context.client().allowed_scopes().contains(&scope) {
            return Err(ProtocolError::new(
                OAuthErrorCode::InvalidScope,
                "the requested scope is not allowed for this client",
                "scope_not_allowed",
            ));
        }
        if !scopes.contains(&scope) {
            scopes.push(scope);
        }
    }
    if scopes.is_empty() {
        return Err(ProtocolError::new(
            OAuthErrorCode::InvalidScope,
            "scope is required",
            "missing_scope",
        ));
    }
    let scopes = ScopeSet::new(scopes);
    let openid = scopes
        .as_slice()
        .iter()
        .any(|scope| scope.as_str() == "openid");

    let nonce = match params.get("nonce") {
        Some(value) => Some(Nonce::parse(value).map_err(|_| {
            ProtocolError::new(
                OAuthErrorCode::InvalidRequest,
                "the nonce is invalid",
                "invalid_nonce",
            )
        })?),
        None => None,
    };
    if openid && nonce.is_none() {
        return Err(ProtocolError::new(
            OAuthErrorCode::InvalidRequest,
            "nonce is required for OpenID requests",
            "missing_nonce",
        ));
    }

    let challenge = params.get("code_challenge").ok_or(ProtocolError::new(
        OAuthErrorCode::InvalidRequest,
        "code_challenge is required",
        "missing_code_challenge",
    ))?;
    let pkce_challenge = PkceChallenge::parse(challenge).map_err(|_| {
        ProtocolError::new(
            OAuthErrorCode::InvalidRequest,
            "the code_challenge is invalid",
            "invalid_code_challenge",
        )
    })?;
    let method = params
        .get("code_challenge_method")
        .ok_or(ProtocolError::new(
            OAuthErrorCode::InvalidRequest,
            "code_challenge_method is required",
            "missing_code_challenge_method",
        ))?;
    if method != "S256" {
        return Err(ProtocolError::new(
            OAuthErrorCode::InvalidRequest,
            "only code_challenge_method=S256 is supported",
            "unsupported_code_challenge_method",
        ));
    }

    let (prompt_none, prompt_consent) = parse_prompt(params.get("prompt"))?;
    let max_age_secs = match params.get("max_age") {
        Some(value) => Some(
            value
                .parse::<u64>()
                .ok()
                .filter(|value| *value <= MAX_MAX_AGE_SECS)
                .ok_or_else(|| {
                    ProtocolError::new(
                        OAuthErrorCode::InvalidRequest,
                        "max_age is invalid",
                        "invalid_max_age",
                    )
                })?,
        ),
        None => None,
    };
    let state = match params.get("state") {
        Some(value) if value.len() > MAX_STATE_LEN => {
            return Err(ProtocolError::new(
                OAuthErrorCode::InvalidRequest,
                "state is too long",
                "invalid_state",
            ));
        }
        Some(value) => Some(value.to_owned()),
        None => None,
    };

    Ok(Validated {
        redirect_uri: redirect_uri.clone(),
        scopes,
        nonce,
        pkce_challenge,
        state,
        prompt_none,
        prompt_consent,
        max_age_secs,
    })
}

fn session_is_stale(
    service: &AuthorizationService,
    session: &SessionContext,
    max_age_secs: u64,
) -> bool {
    let age = service
        .now()
        .as_millis()
        .saturating_sub(session.session().created_at().as_millis());
    age > max_age_secs.saturating_mul(1_000)
}

fn optional_state(params: &Params) -> Option<String> {
    params
        .get("state")
        .filter(|state| state.len() <= MAX_STATE_LEN)
        .map(str::to_owned)
}

fn parse_prompt(prompt: Option<&str>) -> Result<(bool, bool), ProtocolError> {
    let Some(prompt) = prompt else {
        return Ok((false, false));
    };
    let mut none = false;
    let mut consent = false;
    for value in prompt.split_whitespace() {
        match value {
            "none" => none = true,
            "consent" => consent = true,
            "login" | "select_account" => {
                return Err(ProtocolError::new(
                    OAuthErrorCode::InvalidRequest,
                    "the requested prompt mode is not supported",
                    "unsupported_prompt",
                ));
            }
            _ => {
                return Err(ProtocolError::new(
                    OAuthErrorCode::InvalidRequest,
                    "the requested prompt mode is invalid",
                    "invalid_prompt",
                ));
            }
        }
    }
    if none && consent {
        return Err(ProtocolError::new(
            OAuthErrorCode::InvalidRequest,
            "prompt=none cannot be combined with other values",
            "invalid_prompt",
        ));
    }
    Ok((none, consent))
}

fn render_consent(context: &ClientContext, validated: &Validated, csrf_token: &str) -> Response {
    let scopes = validated
        .scopes
        .as_slice()
        .iter()
        .map(|scope| format!("<li>{}</li>", escape(scope.as_str())))
        .collect::<String>();
    let state = validated
        .state
        .as_deref()
        .map(|value| {
            format!(
                r#"<input type="hidden" name="state" value="{}">"#,
                escape(value)
            )
        })
        .unwrap_or_default();
    let nonce = validated
        .nonce
        .as_ref()
        .map(|value| {
            format!(
                r#"<input type="hidden" name="nonce" value="{}">"#,
                escape(value.as_str())
            )
        })
        .unwrap_or_default();
    let scope = validated
        .scopes
        .as_slice()
        .iter()
        .map(Scope::as_str)
        .collect::<Vec<_>>()
        .join(" ");
    let max_age = validated
        .max_age_secs
        .map(|value| format!(r#"<input type="hidden" name="max_age" value="{value}">"#,))
        .unwrap_or_default();
    let body = format!(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>Authorize {client}</title>
<link rel="stylesheet" href="/oauth2/authorize.css" referrerpolicy="no-referrer">
</head>
<body>
<main class="card">
<p class="eyebrow">Authorization request</p>
<h1>{client}</h1>
<p><strong>{application}</strong> from {organization} wants to access your AuthKit account.</p>
<p class="muted">Requested access</p>
<ul class="scopes">{scopes}</ul>
<form method="post" action="/oauth2/authorize/consent">
<input type="hidden" name="_csrf" value="{csrf}">
<input type="hidden" name="client_id" value="{client_id}">
<input type="hidden" name="redirect_uri" value="{redirect_uri}">
<input type="hidden" name="response_type" value="code">
<input type="hidden" name="scope" value="{scope}">
<input type="hidden" name="code_challenge" value="{challenge}">
<input type="hidden" name="code_challenge_method" value="S256">
{max_age}
{state}
{nonce}
<div class="actions">
<button type="submit" name="decision" value="deny" class="secondary">Deny</button>
<button type="submit" name="decision" value="allow">Allow access</button>
</div>
</form>
<p class="fine">An administrator can revoke this access later.</p>
</main>
</body>
</html>"#,
        client = escape(context.client().name().as_str()),
        application = escape(context.application().name().as_str()),
        organization = escape(context.organization().name().as_str()),
        scopes = scopes,
        csrf = escape(csrf_token),
        client_id = escape(context.client().client_id().as_str()),
        redirect_uri = escape(validated.redirect_uri.as_str()),
        scope = escape(&scope),
        challenge = escape(validated.pkce_challenge.as_str()),
        max_age = max_age,
        state = state,
        nonce = nonce,
    );
    html_response(StatusCode::OK, body)
}

fn success_redirect(redirect_uri: &RedirectUri, code: &str, state: Option<&str>) -> Response {
    let Some(mut url) = url::Url::parse(redirect_uri.as_str()).ok() else {
        return error_page(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Server error",
            "The authorization response could not be constructed.",
        );
    };
    {
        let mut query = url.query_pairs_mut();
        query.append_pair("code", code);
        if let Some(state) = state {
            query.append_pair("state", state);
        }
    }
    redirect(url.as_str())
}

fn error_redirect(
    redirect_uri: &RedirectUri,
    code: OAuthErrorCode,
    description: &'static str,
    state: Option<&str>,
) -> Response {
    let Some(mut url) = url::Url::parse(redirect_uri.as_str()).ok() else {
        return error_page(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Server error",
            "The authorization response could not be constructed.",
        );
    };
    {
        let mut query = url.query_pairs_mut();
        query.append_pair("error", code.as_str());
        query.append_pair("error_description", description);
        if let Some(state) = state {
            query.append_pair("state", state);
        }
    }
    redirect(url.as_str())
}

fn redirect(location: &str) -> Response {
    match HeaderValue::from_str(location) {
        Ok(location) => (
            StatusCode::SEE_OTHER,
            [
                (header::LOCATION, location),
                (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
            ],
        )
            .into_response(),
        Err(_) => error_page(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Server error",
            "The authorization response could not be constructed.",
        ),
    }
}

fn error_page(status: StatusCode, title: &str, message: &str) -> Response {
    let body = format!(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>{title}</title>
<link rel="stylesheet" href="/oauth2/authorize.css" referrerpolicy="no-referrer">
</head>
<body>
<main class="card">
<p class="eyebrow">AuthKit</p>
<h1>{title}</h1>
<p>{message}</p>
</main>
</body>
</html>"#,
        title = escape(title),
        message = escape(message),
    );
    html_response(status, body)
}

fn html_response(status: StatusCode, body: String) -> Response {
    (
        status,
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        body,
    )
        .into_response()
}

fn unavailable(error: authkit_core::domain::DomainError) -> Response {
    tracing::warn!(
        event = "authorization.storage_unavailable",
        error = %error,
        "authorization storage operation failed"
    );
    error_page(
        StatusCode::SERVICE_UNAVAILABLE,
        "Temporarily unavailable",
        "The authorization service is temporarily unavailable.",
    )
}

async fn reject_local(service: &AuthorizationService, request_id: &str, reason: &'static str) {
    if let Err(error) = service
        .record_rejection(None, AuditActor::Anonymous, None, request_id, reason)
        .await
    {
        tracing::warn!(
            event = "authorization.audit_failed",
            request_id = %request_id,
            error = %error,
            "could not append authorization rejection audit event"
        );
    }
}

async fn reject_context(
    service: &AuthorizationService,
    context: &ClientContext,
    request_id: &str,
    reason: &'static str,
    actor: AuditActor,
) {
    if let Err(error) = service
        .record_rejection(
            Some(context.tenant().organization_id().clone()),
            actor,
            Some(context.client().id().as_str()),
            request_id,
            reason,
        )
        .await
    {
        tracing::warn!(
            event = "authorization.audit_failed",
            request_id = %request_id,
            error = %error,
            "could not append authorization rejection audit event"
        );
    }
}

fn request_id_string(request_id: Option<&Extension<RequestId>>) -> String {
    request_id
        .map(|request_id| request_id.0.as_str().to_owned())
        .unwrap_or_else(|| "unknown".to_owned())
}

fn escape(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            _ => escaped.push(character),
        }
    }
    escaped
}

struct Validated {
    redirect_uri: RedirectUri,
    scopes: ScopeSet,
    nonce: Option<Nonce>,
    pkce_challenge: PkceChallenge,
    state: Option<String>,
    prompt_none: bool,
    prompt_consent: bool,
    max_age_secs: Option<u64>,
}

#[derive(Debug)]
struct ProtocolError {
    code: OAuthErrorCode,
    description: &'static str,
    reason: &'static str,
}

impl ProtocolError {
    const fn new(code: OAuthErrorCode, description: &'static str, reason: &'static str) -> Self {
        Self {
            code,
            description,
            reason,
        }
    }
}

struct Params(Vec<(String, String)>);

impl Params {
    fn from_query(query: Option<&str>) -> Result<Self, ()> {
        let Some(query) = query else {
            return Ok(Self(Vec::new()));
        };
        if query.len() > MAX_QUERY_LEN {
            return Err(());
        }
        Self::from_pairs(url::form_urlencoded::parse(query.as_bytes()))
    }

    fn from_form(body: &[u8]) -> Result<Self, ()> {
        Self::from_pairs(url::form_urlencoded::parse(body))
    }

    fn from_pairs<'a>(
        pairs: impl Iterator<Item = (std::borrow::Cow<'a, str>, std::borrow::Cow<'a, str>)>,
    ) -> Result<Self, ()> {
        let mut values = Vec::new();
        let mut seen = HashSet::new();
        for (name, value) in pairs {
            let name = name.into_owned();
            let value = value.into_owned();
            if name.len() > MAX_PARAMETER_NAME || value.len() > MAX_PARAMETER_VALUE {
                return Err(());
            }
            if !seen.insert(name.clone()) {
                return Err(());
            }
            values.push((name, value));
            if values.len() > MAX_PARAMETERS {
                return Err(());
            }
        }
        Ok(Self(values))
    }

    fn get(&self, name: &str) -> Option<&str> {
        self.0
            .iter()
            .find(|(candidate, _)| candidate == name)
            .map(|(_, value)| value.as_str())
    }
}

const AUTHORIZE_CSS: &str = r#"
:root { color-scheme: light dark; font-family: ui-sans-serif, system-ui, sans-serif; }
* { box-sizing: border-box; }
body { margin: 0; min-height: 100vh; display: grid; place-items: center; background: #f4f5f7; color: #17202a; }
.card { width: min(34rem, calc(100vw - 2rem)); background: #fff; border: 1px solid #d8dde5; border-radius: 1rem; padding: 2rem; box-shadow: 0 12px 40px rgb(15 23 42 / 8%); }
.eyebrow { margin: 0 0 .5rem; font-size: .75rem; letter-spacing: .08em; text-transform: uppercase; color: #5b6b7f; }
h1 { margin: 0 0 1rem; font-size: 1.5rem; }
p { line-height: 1.5; }
.muted { margin-bottom: .25rem; color: #5b6b7f; font-size: .875rem; }
.scopes { margin: 0 0 1.5rem; padding-left: 1.25rem; }
.actions { display: flex; gap: .75rem; justify-content: flex-end; }
button { border: 0; border-radius: .5rem; padding: .7rem 1rem; font: inherit; font-weight: 600; cursor: pointer; background: #1456c0; color: #fff; }
button.secondary { background: #e8ecf2; color: #17202a; }
.fine { margin: 1.25rem 0 0; color: #5b6b7f; font-size: .8rem; }
@media (prefers-color-scheme: dark) {
  body { background: #11161d; color: #e7edf5; }
  .card { background: #18202a; border-color: #2c3948; }
  .eyebrow, .muted, .fine { color: #9fb0c4; }
  button.secondary { background: #263342; color: #e7edf5; }
}
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_html() {
        assert_eq!(escape("<script>\"'&"), "&lt;script&gt;&quot;&#39;&amp;");
    }

    #[test]
    fn rejects_duplicate_parameters() {
        assert!(Params::from_form(b"client_id=a&client_id=b").is_err());
    }

    #[test]
    fn parses_consent_prompt() {
        assert_eq!(parse_prompt(None).expect("none"), (false, false));
        assert_eq!(
            parse_prompt(Some("consent")).expect("consent"),
            (false, true)
        );
        assert_eq!(parse_prompt(Some("none")).expect("none"), (true, false));
        assert!(parse_prompt(Some("none consent")).is_err());
        assert!(parse_prompt(Some("login")).is_err());
    }
}
