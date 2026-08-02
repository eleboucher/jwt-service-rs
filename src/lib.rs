pub mod cs_api;
pub mod delayed_event;

use axum::{
    Router,
    extract::{Extension, Json},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, options},
};

use serde::{Deserialize, Serialize};

use std::{collections::HashSet, env, sync::Arc, time::Duration};
use tracing::{debug, error, info, instrument, trace, warn};
use url::Url;

pub use resolvematrix::server::MatrixResolver;

use crate::delayed_event::{DelayedEventManager, JobParams, Signal};

/// Ceiling on the client-supplied `delay_timeout`.
const MAX_DELAY_TIMEOUT: Duration = Duration::from_hours(24);

#[derive(Clone)]
pub struct AppState {
    pub key: String,
    pub secret: String,
    pub lk_url: String,
    pub full_access_homeservers: HashSet<String>,
    pub federation_client: reqwest::Client,
    pub resolver: Arc<MatrixResolver>,
    pub delayed_events: Arc<DelayedEventManager>,
}

impl AppState {
    /// Schedules the delayed leave event, if the client asked us to take it
    /// over. Restricted to full-access homeservers, as in lk-jwt-service.
    async fn delegate_delayed_leave(
        &self,
        server_name: &str,
        delay_id: &str,
        delay_timeout_ms: i64,
        live_kit_room: &str,
        live_kit_identity: &str,
    ) {
        // The client's claim is unverifiable, so cap it. An absurd value would
        // otherwise keep a job alive indefinitely.
        let delay_timeout =
            Duration::from_millis(delay_timeout_ms.unsigned_abs()).min(MAX_DELAY_TIMEOUT);

        self.delayed_events
            .add_job(JobParams {
                delay_id: delay_id.to_owned(),
                delay_timeout,
                server_name: server_name.to_owned(),
                live_kit_room: live_kit_room.to_owned(),
                live_kit_identity: live_kit_identity.to_owned(),
            })
            .await;
    }
}

pub use jwt_service_core::wire::{
    DelegateDelayedLeaveRequest, GetTokenRequest as SFURequest,
    LegacySfuRequest as LegacySFURequest, MatrixError, OpenIdToken as OpenIDTokenType,
    RtcMember as MatrixRTCMemberType, SfuResponse as SFUResponse,
};

#[derive(Serialize, Debug)]
pub struct DelegateDelayedLeaveResponse {}

fn check_delay_params(delay: &jwt_service_core::wire::DelayParams) -> Result<(), MatrixError> {
    if delay.is_half_specified() {
        error!("Missing delayed event delegation parameters");
        return Err(MatrixError {
            errcode: "M_BAD_JSON".to_string(),
            error: "The request body is missing `delay_id` or `delay_timeout`".to_string(),
        });
    }

    Ok(())
}

trait ValidatableSFURequest {
    fn validate(&self) -> Result<(), MatrixError>;
}

impl ValidatableSFURequest for LegacySFURequest {
    fn validate(&self) -> Result<(), MatrixError> {
        if self.room.is_empty() {
            return Err(MatrixError {
                errcode: "M_BAD_JSON".to_string(),
                error: "Missing room parameter".to_string(),
            });
        }
        if self.openid_token.access_token.is_empty()
            || self.openid_token.matrix_server_name.is_empty()
        {
            return Err(MatrixError {
                errcode: "M_BAD_JSON".to_string(),
                error: "Missing OpenID token parameters".to_string(),
            });
        }
        check_delay_params(&self.delay)
    }
}

impl ValidatableSFURequest for SFURequest {
    fn validate(&self) -> Result<(), MatrixError> {
        if self.room_id.is_empty() || self.slot_id.is_empty() {
            error!(
                room_id = %self.room_id,
                slot_id = %self.slot_id,
                "Missing room_id or slot_id"
            );
            return Err(MatrixError {
                errcode: "M_BAD_JSON".to_string(),
                error: "The request body is missing `room_id` or `slot_id`".to_string(),
            });
        }
        if self.member.id.is_empty()
            || self.member.claimed_user_id.is_empty()
            || self.member.claimed_device_id.is_empty()
        {
            error!(
                member_id = %self.member.id,
                claimed_user_id = %self.member.claimed_user_id,
                claimed_device_id = %self.member.claimed_device_id,
                "Missing member parameters"
            );
            return Err(MatrixError {
                errcode: "M_BAD_JSON".to_string(),
                error: "The request body `member` is missing a `id`, `claimed_user_id` or `claimed_device_id`".to_string(),
            });
        }
        if self.openid_token.access_token.is_empty()
            || self.openid_token.matrix_server_name.is_empty()
        {
            error!(
                access_token_present = !self.openid_token.access_token.is_empty(),
                matrix_server_name = %self.openid_token.matrix_server_name,
                "Missing OpenID token parameters"
            );
            return Err(MatrixError {
                errcode: "M_BAD_JSON".to_string(),
                error: "The request body `openid_token` is missing a `access_token` or `matrix_server_name`".to_string(),
            });
        }
        check_delay_params(&self.delay)
    }
}

impl ValidatableSFURequest for DelegateDelayedLeaveRequest {
    fn validate(&self) -> Result<(), MatrixError> {
        if self.room_id.is_empty() || self.slot_id.is_empty() {
            return Err(MatrixError {
                errcode: "M_BAD_JSON".to_string(),
                error: "The request body is missing `room_id` or `slot_id`".to_string(),
            });
        }
        if self.member.id.is_empty()
            || self.member.claimed_user_id.is_empty()
            || self.member.claimed_device_id.is_empty()
        {
            return Err(MatrixError {
                errcode: "M_BAD_JSON".to_string(),
                error: "The request body `member` is missing `id`, `claimed_user_id` or \
                        `claimed_device_id`"
                    .to_string(),
            });
        }
        if self.openid_token.access_token.is_empty()
            || self.openid_token.matrix_server_name.is_empty()
        {
            return Err(MatrixError {
                errcode: "M_BAD_JSON".to_string(),
                error: "The request body `openid_token` is missing `access_token` or \
                        `matrix_server_name`"
                    .to_string(),
            });
        }
        if self.delay_id.is_empty() || self.delay_timeout <= 0 {
            return Err(MatrixError {
                errcode: "M_BAD_JSON".to_string(),
                error: "The request body is missing `delay_id` or `delay_timeout`".to_string(),
            });
        }
        Ok(())
    }
}

#[instrument]
pub async fn healthcheck() -> impl IntoResponse {
    StatusCode::OK
}

#[instrument]
pub async fn handle_options() -> impl IntoResponse {
    let mut headers = HeaderMap::new();
    headers.insert("Access-Control-Allow-Origin", "*".parse().unwrap());
    headers.insert("Access-Control-Allow-Methods", "POST".parse().unwrap());
    headers.insert(
        "Access-Control-Allow-Headers",
        "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token"
            .parse()
            .unwrap(),
    );
    (StatusCode::OK, headers)
}

/// Deprecated: serves the pre-Matrix-2.0 `/sfu/get` endpoint.
#[instrument(skip(state, body))]
pub async fn handle_legacy_post(
    Extension(state): Extension<Arc<AppState>>,
    body: String,
) -> Response {
    info!("Processing legacy /sfu/get request");

    let headers = json_cors_headers();

    let payload = match serde_json::from_str::<LegacySFURequest>(&body) {
        Ok(payload) => payload,
        Err(e) => {
            error!(error = %e, "Error reading request");
            let err = MatrixError {
                errcode: "M_NOT_JSON".to_string(),
                error: "Error reading request".to_string(),
            };
            return (StatusCode::BAD_REQUEST, headers, axum::Json(err)).into_response();
        }
    };

    if let Err(e) = payload.validate() {
        error!(errcode = %e.errcode, error = %e.error, "Validation failed");
        return (StatusCode::BAD_REQUEST, headers, axum::Json(e)).into_response();
    }

    handle_legacy_sfu_request(state, payload, headers).await
}

fn json_cors_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert("Access-Control-Allow-Origin", "*".parse().unwrap());
    headers.insert("Content-Type", "application/json".parse().unwrap());
    headers
}

/// One error for every authentication failure, so the cause is not disclosed.
fn unauthorised() -> MatrixError {
    MatrixError {
        errcode: "M_UNAUTHORIZED".to_string(),
        error: "The request could not be authorised.".to_string(),
    }
}

/// New MSC4195 endpoint handler - only accepts SFURequest
#[instrument(skip(state, payload))]
pub async fn handle_post(
    Extension(state): Extension<Arc<AppState>>,
    Json(payload): Json<SFURequest>,
) -> Response {
    info!("Processing /get_token request");

    let mut headers = HeaderMap::new();
    headers.insert("Access-Control-Allow-Origin", "*".parse().unwrap());
    headers.insert("Content-Type", "application/json".parse().unwrap());

    if let Err(e) = payload.validate() {
        error!(errcode = %e.errcode, error = %e.error, "Validation failed");
        return (StatusCode::BAD_REQUEST, headers, axum::Json(e)).into_response();
    }

    handle_sfu_request(state, payload, headers).await
}

async fn handle_legacy_sfu_request(
    state: Arc<AppState>,
    payload: LegacySFURequest,
    headers: HeaderMap,
) -> Response {
    let user_info = match exchange_openid_userinfo(
        &payload.openid_token,
        &state.resolver,
        &state.federation_client,
    )
    .await
    {
        Ok(user) => user,
        Err(e) => {
            error!(
                errcode = "M_UNAUTHORIZED",
                error = %e,
                server_name = %payload.openid_token.matrix_server_name,
                "The request could not be authorised"
            );
            return (
                StatusCode::UNAUTHORIZED,
                headers,
                axum::Json(unauthorised()),
            )
                .into_response();
        }
    };

    let is_full_access_user = is_full_access_user(
        &state.full_access_homeservers,
        &payload.openid_token.matrix_server_name,
    );

    info!(
        user = %user_info.sub,
        access_level = if is_full_access_user { "full access" } else { "restricted access" },
        "Got Matrix user info"
    );

    let lk_identity = format!("{}:{}", user_info.sub, payload.device_id);

    // For legacy requests, derive the room alias using the same method as new requests
    // This ensures compatibility between old and new clients
    let slot_id = "m.call#ROOM";
    let lk_room_alias = room_alias(&payload.room, slot_id);

    let token = match get_join_token(&state.key, &state.secret, &lk_room_alias, &lk_identity) {
        Ok(t) => t,
        Err(e) => {
            error!(errcode = "M_UNKNOWN", error = %e, "Failed to generate join token");
            let err = MatrixError {
                errcode: "M_UNKNOWN".to_string(),
                error: "Internal Server Error".to_string(),
            };
            return (StatusCode::INTERNAL_SERVER_ERROR, headers, axum::Json(err)).into_response();
        }
    };

    if is_full_access_user {
        let lk_client = livekit_api::services::room::RoomClient::with_api_key(
            &state.lk_url,
            &state.key,
            &state.secret,
        );
        let options = livekit_api::services::room::CreateRoomOptions {
            empty_timeout: 5 * 60, // keep the room open if no one joins
            departure_timeout: 20, // keep the room after everyone leaves
            max_participants: 0,   // no limit
            ..Default::default()
        };
        match lk_client.create_room(&lk_room_alias, options).await {
            Ok(room) => {
                info!(
                    room_sid = %room.sid,
                    room_name = %room.name,
                    matrix_user = %user_info.sub,
                    lk_identity = %lk_identity,
                    "Created LiveKit room"
                );
            }
            Err(e) => {
                error!(
                    errcode = "M_UNKNOWN",
                    error = %e,
                    room_name = %lk_room_alias,
                    "Unable to create room on SFU"
                );
                let err = MatrixError {
                    errcode: "M_UNKNOWN".to_string(),
                    error: "Unable to create room on SFU".to_string(),
                };
                return (StatusCode::INTERNAL_SERVER_ERROR, headers, axum::Json(err))
                    .into_response();
            }
        }
    }

    if let Some((delay_id, delay_timeout)) = payload.delay.requested() {
        // Refuse rather than silently drop it: the client would otherwise
        // believe its deadman switch was delegated and stop restarting it.
        if !is_full_access_user {
            let err = MatrixError {
                errcode: "M_BAD_JSON".to_string(),
                error: "Delegation of delayed events is only supported for full access users"
                    .to_string(),
            };
            return (StatusCode::BAD_REQUEST, headers, axum::Json(err)).into_response();
        }

        state
            .delegate_delayed_leave(
                &payload.openid_token.matrix_server_name,
                delay_id,
                delay_timeout,
                &lk_room_alias,
                &lk_identity,
            )
            .await;
    }

    let res = SFUResponse {
        url: state.lk_url.clone(),
        jwt: token,
    };
    (StatusCode::OK, headers, axum::Json(res)).into_response()
}

async fn handle_sfu_request(
    state: Arc<AppState>,
    payload: SFURequest,
    headers: HeaderMap,
) -> Response {
    let user_info = match exchange_openid_userinfo(
        &payload.openid_token,
        &state.resolver,
        &state.federation_client,
    )
    .await
    {
        Ok(user) => user,
        Err(e) => {
            error!(
                errcode = "M_UNAUTHORIZED",
                error = %e,
                server_name = %payload.openid_token.matrix_server_name,
                "The request could not be authorised"
            );
            let err = MatrixError {
                errcode: "M_UNAUTHORIZED".to_string(),
                error: "The request could not be authorised.".to_string(),
            };
            return (StatusCode::UNAUTHORIZED, headers, axum::Json(err)).into_response();
        }
    };

    // Check if validated userInfo.Sub matches payload.member.claimed_user_id
    if payload.member.claimed_user_id != user_info.sub {
        error!(
            claimed_user_id = %payload.member.claimed_user_id,
            token_subject = %user_info.sub,
            "Claimed user ID does not match token subject"
        );
        let err = MatrixError {
            errcode: "M_UNAUTHORIZED".to_string(),
            error: "The request could not be authorised.".to_string(),
        };
        return (StatusCode::UNAUTHORIZED, headers, axum::Json(err)).into_response();
    }

    let is_full_access_user = is_full_access_user(
        &state.full_access_homeservers,
        &payload.openid_token.matrix_server_name,
    );

    info!(
        user = %user_info.sub,
        access_level = if is_full_access_user { "full access" } else { "restricted access" },
        "Got Matrix user info"
    );

    // Use base64 encoded hash of user_id|device_id|member_id for identity
    let lk_identity = participant_identity(
        &user_info.sub,
        &payload.member.claimed_device_id,
        &payload.member.id,
    );

    // Use base64 encoded hash of room_id|slot_id for room alias
    let lk_room_alias = room_alias(&payload.room_id, &payload.slot_id);

    let token = match get_join_token(&state.key, &state.secret, &lk_room_alias, &lk_identity) {
        Ok(t) => t,
        Err(e) => {
            error!(errcode = "M_UNKNOWN", error = %e, "Failed to generate join token");
            let err = MatrixError {
                errcode: "M_UNKNOWN".to_string(),
                error: "Internal Server Error".to_string(),
            };
            return (StatusCode::INTERNAL_SERVER_ERROR, headers, axum::Json(err)).into_response();
        }
    };

    if is_full_access_user {
        let lk_client = livekit_api::services::room::RoomClient::with_api_key(
            &state.lk_url,
            &state.key,
            &state.secret,
        );
        let options = livekit_api::services::room::CreateRoomOptions {
            empty_timeout: 5 * 60, // keep the room open if no one joins
            departure_timeout: 20, // keep the room after everyone leaves
            max_participants: 0,   // no limit
            ..Default::default()
        };
        match lk_client.create_room(&lk_room_alias, options).await {
            Ok(room) => {
                info!(
                    room_sid = %room.sid,
                    room_name = %room.name,
                    matrix_user = %user_info.sub,
                    lk_identity = %lk_identity,
                    "Created LiveKit room"
                );
            }
            Err(e) => {
                error!(
                    errcode = "M_UNKNOWN",
                    error = %e,
                    room_name = %lk_room_alias,
                    "Unable to create room on SFU"
                );
                let err = MatrixError {
                    errcode: "M_UNKNOWN".to_string(),
                    error: "Unable to create room on SFU".to_string(),
                };
                return (StatusCode::INTERNAL_SERVER_ERROR, headers, axum::Json(err))
                    .into_response();
            }
        }
    }

    if let Some((delay_id, delay_timeout)) = payload.delay.requested() {
        // Refuse rather than silently drop it: the client would otherwise
        // believe its deadman switch was delegated and stop restarting it.
        if !is_full_access_user {
            let err = MatrixError {
                errcode: "M_BAD_JSON".to_string(),
                error: "Delegation of delayed events is only supported for full access users"
                    .to_string(),
            };
            return (StatusCode::BAD_REQUEST, headers, axum::Json(err)).into_response();
        }

        state
            .delegate_delayed_leave(
                &payload.openid_token.matrix_server_name,
                delay_id,
                delay_timeout,
                &lk_room_alias,
                &lk_identity,
            )
            .await;
    }

    let res = SFUResponse {
        url: state.lk_url.clone(),
        jwt: token,
    };
    (StatusCode::OK, headers, axum::Json(res)).into_response()
}

// Mocked user info struct and exchange function
#[derive(Debug, Deserialize, Serialize)]
pub struct UserInfo {
    pub sub: String,
}

use thiserror::Error;

/// Error type for Matrix server resolution.
#[derive(Debug, Error)]
pub enum ExchangeOpenIdUserInfoError {
    #[error("Invalid token")]
    InvalidToken,
    #[error("Failed to resolve matrix server: {0}")]
    FailedToResolveMatrixServer(#[from] resolvematrix::error::ServerResolutionError),
    #[error("Bad URL: {0}")]
    BadUrl(#[from] url::ParseError),

    #[error("HTTP client error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("Userinfo lookup returned HTTP {0}")]
    UnexpectedStatus(StatusCode),

    #[error("Userinfo returned a user ID belonging to another server")]
    ForeignUserId,
}

#[instrument(level="debug", skip(token, resolver, federation_client), fields(server = %token.matrix_server_name))]
pub async fn exchange_openid_userinfo(
    token: &OpenIDTokenType,
    resolver: &Arc<MatrixResolver>,
    federation_client: &reqwest::Client,
) -> Result<UserInfo, ExchangeOpenIdUserInfoError> {
    if token.access_token.is_empty() || token.matrix_server_name.is_empty() {
        error!(
            errcode = "InvalidToken",
            "Access token or matrix server name is empty"
        );
        return Err(ExchangeOpenIdUserInfoError::InvalidToken);
    }
    let resolution = resolver
        .resolve_server(token.matrix_server_name.as_str())
        .await?;

    trace!(?resolution, "Resolved server");

    // Use the base_url to build the request URL
    let url = format!(
        "{}/_matrix/federation/v1/openid/userinfo",
        resolution.base_url()
    );

    let response = federation_client
        .get(Url::parse_with_params(
            &url,
            &[("access_token", token.access_token.as_str())],
        )?)
        .send()
        .await?;

    trace!("Sent request");

    let status = response.status();
    if !status.is_success() {
        error!(%status, "Userinfo lookup returned a non-success status");
        return Err(ExchangeOpenIdUserInfoError::UnexpectedStatus(status));
    }

    let user_info: UserInfo = response.json().await?;
    trace!("Parsed response");

    // The spec requires this: "The caller MUST validate that the returned user
    // ID is on the server they called". Without it, any host can vouch for a
    // user on any homeserver simply by answering with their MXID.
    if user_id_server_name(&user_info.sub) != Some(token.matrix_server_name.as_str()) {
        error!(
            sub = %user_info.sub,
            server = %token.matrix_server_name,
            "Userinfo returned a user ID belonging to another server"
        );
        return Err(ExchangeOpenIdUserInfoError::ForeignUserId);
    }

    Ok(user_info)
}

/// The server name of an MXID, i.e. everything after the first colon.
fn user_id_server_name(user_id: &str) -> Option<&str> {
    user_id
        .strip_prefix('@')?
        .split_once(':')
        .map(|(_, server)| server)
}

fn is_full_access_user(
    full_access_homeservers: &HashSet<String>,
    matrix_server_name: &str,
) -> bool {
    // Grant full access if wildcard '*' is present as the only entry
    if full_access_homeservers.len() == 1 && full_access_homeservers.contains("*") {
        return true;
    }

    // Check if the matrixServerName is in the list of full-access homeservers
    full_access_homeservers.contains(matrix_server_name)
}

// The MSC4195 derivations and token minting live in jwt-service-core so a
// homeserver can reuse them without this crate's HTTP and OpenID machinery.
use jwt_service_core::{join_token as get_join_token, participant_identity, room_alias};

pub fn read_key_secret() -> (String, String) {
    let key = env::var("LIVEKIT_KEY")
        .or_else(|_| env::var("LIVEKIT_API_KEY"))
        .unwrap_or_default();
    let secret = env::var("LIVEKIT_SECRET")
        .or_else(|_| env::var("LIVEKIT_API_SECRET"))
        .unwrap_or_default();
    let key_path = env::var("LIVEKIT_KEY_FROM_FILE").unwrap_or_default();
    let secret_path = env::var("LIVEKIT_SECRET_FROM_FILE").unwrap_or_default();
    let key_secret_path = env::var("LIVEKIT_KEY_FILE").unwrap_or_default();

    let (mut key, mut secret) = (key, secret);

    if !key_secret_path.is_empty() {
        if let Ok(contents) = std::fs::read_to_string(&key_secret_path) {
            let parts: Vec<&str> = contents.trim().split(':').collect();
            if parts.len() == 2 {
                key = parts[0].to_string();
                secret = parts[1].to_string();
            }
        }
    } else {
        if !key_path.is_empty()
            && let Ok(contents) = std::fs::read_to_string(&key_path)
        {
            key = contents.trim().to_string();
        }
        if !secret_path.is_empty()
            && let Ok(contents) = std::fs::read_to_string(&secret_path)
        {
            secret = contents.trim().to_string();
        }
    }
    (key.trim().to_string(), secret.trim().to_string())
}

/// # `POST /delegate_delayed_leave`
///
/// Hands the delayed leave event over after the client is already connected,
/// so no JWT is issued and the LiveKit room already exists.
#[instrument(skip(state, payload))]
pub async fn handle_delegate_delayed_leave(
    Extension(state): Extension<Arc<AppState>>,
    Json(payload): Json<DelegateDelayedLeaveRequest>,
) -> Response {
    let headers = json_cors_headers();

    if let Err(e) = payload.validate() {
        error!(errcode = %e.errcode, error = %e.error, "Validation failed");
        return (StatusCode::BAD_REQUEST, headers, axum::Json(e)).into_response();
    }

    let user_info = match exchange_openid_userinfo(
        &payload.openid_token,
        &state.resolver,
        &state.federation_client,
    )
    .await
    {
        Ok(user) => user,
        Err(e) => {
            error!(error = %e, "The request could not be authorised");
            return (
                StatusCode::UNAUTHORIZED,
                headers,
                axum::Json(unauthorised()),
            )
                .into_response();
        }
    };

    if payload.member.claimed_user_id != user_info.sub {
        error!("Claimed user ID does not match token subject");
        return (
            StatusCode::UNAUTHORIZED,
            headers,
            axum::Json(unauthorised()),
        )
            .into_response();
    }

    if !is_full_access_user(
        &state.full_access_homeservers,
        &payload.openid_token.matrix_server_name,
    ) {
        let err = MatrixError {
            errcode: "M_FORBIDDEN".to_string(),
            error: "Delegation of delayed events is only supported for full access users"
                .to_string(),
        };
        return (StatusCode::FORBIDDEN, headers, axum::Json(err)).into_response();
    }

    let lk_identity = participant_identity(
        &user_info.sub,
        &payload.member.claimed_device_id,
        &payload.member.id,
    );
    let lk_room_alias = room_alias(&payload.room_id, &payload.slot_id);

    state
        .delegate_delayed_leave(
            &payload.openid_token.matrix_server_name,
            &payload.delay_id,
            payload.delay_timeout,
            &lk_room_alias,
            &lk_identity,
        )
        .await;

    (
        StatusCode::OK,
        headers,
        axum::Json(DelegateDelayedLeaveResponse {}),
    )
        .into_response()
}

/// # `POST /sfu_webhook`
///
/// Receives LiveKit participant events. Signed with the API key/secret, so no
/// CORS and no Matrix auth.
#[instrument(skip(state, headers, body))]
pub async fn handle_sfu_webhook(
    Extension(state): Extension<Arc<AppState>>,
    headers: HeaderMap,
    body: String,
) -> StatusCode {
    let auth = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();

    let receiver = livekit_api::webhooks::WebhookReceiver::new(
        livekit_api::access_token::TokenVerifier::with_api_key(&state.key, &state.secret),
    );

    let event = match receiver.receive(&body, auth) {
        Ok(event) => event,
        Err(e) => {
            warn!(error = %e, "SFU webhook error");
            return StatusCode::OK;
        }
    };

    let (Some(room), Some(participant)) = (&event.room, &event.participant) else {
        return StatusCode::OK;
    };

    // Only a client-initiated leave is intentional; anything else is a drop.
    let signal = match event.event.as_str() {
        "participant_joined" => Signal::ParticipantConnected,
        "participant_left" | "participant_connection_aborted" => {
            if participant.disconnect_reason
                == livekit_protocol::DisconnectReason::ClientInitiated as i32
            {
                Signal::ParticipantDisconnectedIntentionally
            } else {
                Signal::ParticipantConnectionAborted
            }
        }
        _ => return StatusCode::OK,
    };

    debug!(room = %room.name, identity = %participant.identity, ?signal, "SFU webhook");
    state
        .delayed_events
        .dispatch(&room.name, &participant.identity, signal)
        .await;

    StatusCode::OK
}

pub fn build_app(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/healthz", get(healthcheck))
        .route("/get_token", options(handle_options).post(handle_post))
        .route(
            "/sfu/get",
            options(handle_options).post(
                |Extension(state): Extension<Arc<AppState>>, body: String| {
                    handle_legacy_post(Extension(state), body)
                },
            ),
        )
        .route(
            "/delegate_delayed_leave",
            options(handle_options).post(handle_delegate_delayed_leave),
        )
        .route("/sfu_webhook", axum::routing::post(handle_sfu_webhook))
        .layer(Extension(state))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};

    use std::sync::Arc;
    use tower::ServiceExt; // for `oneshot` method

    fn test_manager() -> Arc<DelayedEventManager> {
        Arc::new(DelayedEventManager::new(delayed_event::JobContext {
            http: reqwest::Client::new(),
            cs_api_overrides: std::collections::HashMap::new(),
            cs_api_cache: Arc::new(cs_api::CsApiUrlCache::new()),
            live_kit: delayed_event::LiveKitAuth {
                url: String::new(),
                key: String::new(),
                secret: String::new(),
            },
            sanity_check_interval: None,
        }))
    }

    #[tokio::test]
    async fn test_healthcheck() {
        let resolver = Arc::new(MatrixResolver::new().unwrap());
        let federation_client = resolver.create_client().unwrap();

        let state = Arc::new(AppState {
            key: "".to_string(),
            secret: "".to_string(),
            lk_url: "".to_string(),
            full_access_homeservers: HashSet::new(),
            federation_client,
            resolver,
            delayed_events: test_manager(),
        });
        let app = build_app(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/healthz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_handle_options() {
        let resolver = Arc::new(MatrixResolver::new().unwrap());
        let federation_client = resolver.create_client().unwrap();

        let state = Arc::new(AppState {
            key: "".to_string(),
            secret: "".to_string(),
            lk_url: "".to_string(),
            full_access_homeservers: HashSet::new(),
            federation_client,
            resolver,
            delayed_events: test_manager(),
        });
        let app = build_app(state);
        let response = app
            .oneshot(
                Request::builder()
                    .method("OPTIONS")
                    .uri("/get_token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let headers = response.headers();
        assert_eq!(headers.get("Access-Control-Allow-Origin").unwrap(), "*");
        assert_eq!(headers.get("Access-Control-Allow-Methods").unwrap(), "POST");
    }

    #[tokio::test]
    async fn test_handle_post_missing_params() {
        let resolver = Arc::new(MatrixResolver::new().unwrap());
        let federation_client = resolver.create_client().unwrap();

        let state = Arc::new(AppState {
            key: "".to_string(),
            secret: "".to_string(),
            lk_url: "".to_string(),
            full_access_homeservers: HashSet::new(),
            federation_client,
            resolver,
            delayed_events: test_manager(),
        });
        let app = build_app(state);
        let body = serde_json::json!({}).to_string();
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/get_token")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(response.status().is_client_error());
    }

    #[tokio::test]
    async fn test_is_full_access_user_wildcard() {
        let mut homeservers = HashSet::new();
        homeservers.insert("*".to_string());
        assert!(is_full_access_user(&homeservers, "any.server.com"));
    }

    #[tokio::test]
    async fn test_is_full_access_user_specific() {
        let mut homeservers = HashSet::new();
        homeservers.insert("example.com".to_string());
        assert!(is_full_access_user(&homeservers, "example.com"));
        assert!(!is_full_access_user(&homeservers, "other.com"));
    }

    /// Demonstrates client reuse with dynamic DNS resolution.
    ///
    /// The MatrixDnsResolver enables a single reqwest client to handle all
    /// Matrix federation requests by dynamically resolving server names according
    /// to the Matrix spec (.well-known delegation, SRV records, etc.) while
    /// maintaining correct SNI for TLS connections.
    ///
    /// This approach is superior to static `.resolve()` mappings because:
    /// - One client works for all servers (no need for client-per-server)
    /// - Proper SNI is automatically maintained
    /// - DNS resolution follows Matrix spec dynamically
    /// - No need for client caching or LRU eviction
    #[tokio::test]
    async fn test_client_reuse_with_dynamic_dns() {
        // Initialize resolver (wrapped in Arc for sharing)
        let resolver = Arc::new(MatrixResolver::new().unwrap());

        // Create ONE client with the Matrix DNS resolver
        // This client can be reused for ALL Matrix federation requests
        let federation_client = resolver.create_client().unwrap();

        // This client dynamically resolves any Matrix server
        let _app_state = AppState {
            key: "test".to_string(),
            secret: "test".to_string(),
            lk_url: "https://localhost".to_string(),
            full_access_homeservers: HashSet::new(),
            federation_client, // Reusable for ALL servers with correct SNI
            resolver,
            delayed_events: test_manager(),
        };

        // The federation_client will now correctly handle requests to any Matrix server:
        // - It follows .well-known delegation
        // - It performs SRV lookups
        // - It resolves hostnames to IPs
        // - It sends correct SNI based on the URL hostname
        // All without needing per-server client configuration!
    }
}
