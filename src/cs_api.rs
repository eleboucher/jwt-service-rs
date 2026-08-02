//! Client-Server API discovery and delayed-event actions (MSC4140).

use std::{
    collections::HashMap,
    sync::RwLock,
    time::{Duration, Instant},
};

use serde::Deserialize;
use thiserror::Error;
use tracing::{debug, warn};
use url::Url;

const STABLE_DELAYED_EVENTS_ENDPOINT: &str = "_matrix/client/v1/delayed_events";
const UNSTABLE_DELAYED_EVENTS_ENDPOINT: &str =
    "_matrix/client/unstable/org.matrix.msc4140/delayed_events";

/// MSC4140 advertises this once the stable endpoints are available.
const STABLE_FEATURE_FLAG: &str = "org.matrix.msc4140.stable";

const DEFAULT_CS_API_CACHE_TTL: Duration = Duration::from_hours(4);
/// Floor on a `.well-known` `max-age`, so a tiny value cannot turn us into a
/// hammer. Ceiling so a hostile one cannot pin a stale URL indefinitely.
const MIN_CS_API_CACHE_TTL: Duration = Duration::from_hours(1);
const MAX_CS_API_CACHE_TTL: Duration = Duration::from_hours(24);
const ACTION_TIMEOUT: Duration = Duration::from_secs(5);

/// A resolved homeserver, and which delayed-events endpoint it speaks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CsApi {
    pub base_url: String,
    pub stable_delayed_events: bool,
}

impl CsApi {
    const fn delayed_events_endpoint(&self) -> &'static str {
        if self.stable_delayed_events {
            STABLE_DELAYED_EVENTS_ENDPOINT
        } else {
            UNSTABLE_DELAYED_EVENTS_ENDPOINT
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DelayEventAction {
    Restart,
    Send,
}

impl std::fmt::Display for DelayEventAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl DelayEventAction {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Restart => "restart",
            Self::Send => "send",
        }
    }
}

#[derive(Debug, Error)]
pub enum ActionError {
    #[error("CS API: delayed event not found")]
    NotFound,

    #[error("CS API returned terminal status {0}")]
    Terminal(u16),

    #[error("CS API rate limited, retry after {0:?}")]
    RetryAfter(Duration),

    #[error("{0}")]
    Transient(String),
}

#[derive(Debug, Error)]
pub enum ResolveCsApiUrlError {
    #[error("no .well-known/matrix/client record found for {0}")]
    NotFound(String),
    #[error("HTTP client error: {0}")]
    Http(#[from] reqwest::Error),
}

#[derive(Default)]
pub struct CsApiUrlCache {
    entries: RwLock<HashMap<String, (CsApi, Instant)>>,
}

impl CsApiUrlCache {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn get(&self, server_name: &str) -> Option<CsApi> {
        let entries = self.entries.read().expect("cs api cache lock poisoned");
        let (cs_api, expires_at) = entries.get(server_name)?;

        // Left in place; the caller will re-resolve and overwrite.
        (Instant::now() < *expires_at).then(|| cs_api.clone())
    }

    fn set(&self, server_name: &str, cs_api: CsApi, ttl: Duration) {
        self.entries
            .write()
            .expect("cs api cache lock poisoned")
            .insert(server_name.to_owned(), (cs_api, Instant::now() + ttl));
    }
}

#[derive(Deserialize)]
struct WellKnownClient {
    #[serde(rename = "m.homeserver")]
    homeserver: WellKnownHomeserver,
}

#[derive(Deserialize)]
struct WellKnownHomeserver {
    base_url: String,
}

pub async fn resolve_cs_api(
    client: &reqwest::Client,
    server_name: &str,
    overrides: &HashMap<String, String>,
    cache: &CsApiUrlCache,
) -> Result<CsApi, ResolveCsApiUrlError> {
    if let Some(cs_api) = cache.get(server_name) {
        return Ok(cs_api);
    }

    let (base_url, ttl) = if let Some(url) = overrides.get(server_name) {
        (url.clone(), DEFAULT_CS_API_CACHE_TTL)
    } else {
        discover_base_url(client, server_name).await?
    };

    let cs_api = CsApi {
        stable_delayed_events: supports_stable_delayed_events(client, &base_url).await,
        base_url,
    };

    cache.set(server_name, cs_api.clone(), ttl);

    Ok(cs_api)
}

async fn discover_base_url(
    client: &reqwest::Client,
    server_name: &str,
) -> Result<(String, Duration), ResolveCsApiUrlError> {
    let well_known = format!("https://{server_name}/.well-known/matrix/client");
    let response = client.get(&well_known).send().await?;

    if !response.status().is_success() {
        warn!(%server_name, status = %response.status(), "Failed to resolve Client-Server API");
        return Err(ResolveCsApiUrlError::NotFound(server_name.to_owned()));
    }

    let ttl = cache_ttl(response.headers());

    match response.json::<WellKnownClient>().await {
        Ok(body) if !body.homeserver.base_url.is_empty() => Ok((body.homeserver.base_url, ttl)),
        _ => {
            warn!(%server_name, "Failed to resolve Client-Server API");
            Err(ResolveCsApiUrlError::NotFound(server_name.to_owned()))
        }
    }
}

/// `max-age` from the response, clamped so neither an aggressive nor an
/// absurd value is honoured verbatim.
fn cache_ttl(headers: &reqwest::header::HeaderMap) -> Duration {
    headers
        .get(reqwest::header::CACHE_CONTROL)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| {
            value
                .split(',')
                .filter_map(|directive| directive.trim().strip_prefix("max-age="))
                .find_map(|seconds| seconds.trim().parse::<u64>().ok())
        })
        .map_or(DEFAULT_CS_API_CACHE_TTL, |seconds| {
            Duration::from_secs(seconds).clamp(MIN_CS_API_CACHE_TTL, MAX_CS_API_CACHE_TTL)
        })
}

/// Falls back to the unstable endpoint whenever the probe is inconclusive.
async fn supports_stable_delayed_events(client: &reqwest::Client, base_url: &str) -> bool {
    let Ok(url) = Url::parse(base_url).and_then(|u| u.join("_matrix/client/versions")) else {
        return false;
    };

    let Ok(response) = client.get(url).send().await else {
        return false;
    };

    response
        .json::<ClientVersions>()
        .await
        .is_ok_and(|body| body.unstable_features.get(STABLE_FEATURE_FLAG) == Some(&true))
}

#[derive(Deserialize)]
struct ClientVersions {
    #[serde(default)]
    unstable_features: HashMap<String, bool>,
}

/// POSTs `action` for `delay_id` to the homeserver.
///
/// Terminal outcomes are not retried: a 404 means no such delayed event, and a
/// 409 means it was already finalised the other way. A 404 on
/// [`DelayEventAction::Send`] leaves nothing to do, so it counts as success.
pub async fn execute_delayed_event_action(
    client: &reqwest::Client,
    cs_api: &CsApi,
    delay_id: &str,
    action: DelayEventAction,
) -> Result<u16, ActionError> {
    let endpoint = build_action_url(cs_api, delay_id, action)
        .map_err(|e| ActionError::Transient(format!("invalid URL: {e}")))?;

    let response = client
        .post(endpoint.clone())
        .timeout(ACTION_TIMEOUT)
        .header("Content-Type", "application/json")
        .body("{}")
        .send()
        .await;

    let response = match response {
        Ok(response) => response,
        Err(e) => {
            debug!(%action, error = %e, "Delayed event action failed");
            return Err(ActionError::Transient(e.to_string()));
        }
    };

    let status = response.status();
    debug!(%action, %status, "Delayed event action");

    match status.as_u16() {
        // Needs the body, so it cannot go through `classify`.
        429 => Err(retry_after(response).await),
        code => classify(code, action),
    }
}

fn classify(code: u16, action: DelayEventAction) -> Result<u16, ActionError> {
    match code {
        200 | 204 => Ok(code),
        // Nothing left to send, so there is nothing to retry.
        404 if action == DelayEventAction::Send => Ok(code),
        404 => Err(ActionError::NotFound),
        // Already finalised the other way.
        409 => Err(ActionError::Terminal(code)),
        // MSC4140 specifies these endpoints as authenticated; we rely on the
        // delegation model where `delay_id` is the credential. A homeserver
        // that disagrees will never accept us.
        401 | 403 => Err(ActionError::Terminal(code)),
        500..=599 => Err(ActionError::Transient(format!(
            "CS API temporarily unavailable (http status code {code})"
        ))),
        // 408, 421, 423 and 425 are retriable.
        _ => Err(ActionError::Transient(format!(
            "CS API returned unexpected status: {code}"
        ))),
    }
}

/// Percent-escapes `delay_id`, which is attacker-controlled.
fn build_action_url(
    cs_api: &CsApi,
    delay_id: &str,
    action: DelayEventAction,
) -> Result<Url, url::ParseError> {
    let mut url = Url::parse(&cs_api.base_url)?;

    url.path_segments_mut()
        .map_err(|()| url::ParseError::RelativeUrlWithCannotBeABaseBase)?
        .pop_if_empty()
        .extend(cs_api.delayed_events_endpoint().split('/'))
        .push(delay_id)
        .push(action.as_str());

    Ok(url)
}

#[derive(Deserialize)]
struct RateLimitBody {
    retry_after_ms: Option<u64>,
}

/// `retry_after_ms` is deprecated since spec v1.10 but is all older
/// homeservers emit.
async fn retry_after(response: reqwest::Response) -> ActionError {
    if let Some(value) = response
        .headers()
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
    {
        return ActionError::RetryAfter(Duration::from_secs(value));
    }

    if let Ok(Some(ms)) = response
        .json::<RateLimitBody>()
        .await
        .map(|b| b.retry_after_ms)
        && ms > 0
    {
        return ActionError::RetryAfter(Duration::from_millis(ms));
    }

    ActionError::Transient("CS API temporarily unavailable (http status code 429)".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cs_api(base_url: &str, stable_delayed_events: bool) -> CsApi {
        CsApi {
            base_url: base_url.to_owned(),
            stable_delayed_events,
        }
    }

    fn headers(cache_control: &str) -> reqwest::header::HeaderMap {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::CACHE_CONTROL,
            cache_control.parse().unwrap(),
        );
        headers
    }

    #[test]
    fn action_url_is_built_under_the_endpoint() {
        let url = build_action_url(
            &cs_api("https://hs.example.com", false),
            "abc123",
            DelayEventAction::Send,
        )
        .unwrap();

        assert_eq!(
            url.as_str(),
            "https://hs.example.com/_matrix/client/unstable/org.matrix.msc4140/delayed_events/abc123/send"
        );
    }

    #[test]
    fn action_url_uses_the_stable_endpoint_when_supported() {
        let url = build_action_url(
            &cs_api("https://hs.example.com", true),
            "abc123",
            DelayEventAction::Send,
        )
        .unwrap();

        assert_eq!(
            url.as_str(),
            "https://hs.example.com/_matrix/client/v1/delayed_events/abc123/send"
        );
    }

    #[test]
    fn action_url_handles_a_base_path_and_trailing_slash() {
        let url = build_action_url(
            &cs_api("https://hs.example.com/matrix/", false),
            "id",
            DelayEventAction::Restart,
        )
        .unwrap();

        assert_eq!(
            url.as_str(),
            "https://hs.example.com/matrix/_matrix/client/unstable/org.matrix.msc4140/delayed_events/id/restart"
        );
    }

    #[test]
    fn action_url_escapes_path_traversal_in_delay_id() {
        let url = build_action_url(
            &cs_api("https://hs.example.com", false),
            "../../evil",
            DelayEventAction::Send,
        )
        .unwrap();

        assert!(
            url.path().ends_with("/delayed_events/..%2F..%2Fevil/send"),
            "{}",
            url.path()
        );
    }

    /// MSC4140: 409 means the event was finalised the other way, and 401/403
    /// mean the homeserver requires auth we do not have. Retrying any of them
    /// is a storm against an answer that will not change.
    #[test]
    fn terminal_statuses_are_not_retriable() {
        for status in [401, 403, 409] {
            assert!(matches!(
                classify(status, DelayEventAction::Restart),
                Err(ActionError::Terminal(_))
            ));
        }

        assert!(matches!(
            classify(404, DelayEventAction::Restart),
            Err(ActionError::NotFound)
        ));
        assert!(classify(404, DelayEventAction::Send).is_ok());

        for status in [500, 502, 408, 425] {
            assert!(matches!(
                classify(status, DelayEventAction::Send),
                Err(ActionError::Transient(_))
            ));
        }
    }

    #[test]
    fn cache_returns_a_live_entry_and_drops_an_expired_one() {
        let cache = CsApiUrlCache::new();

        cache.set(
            "a.example",
            cs_api("https://a", false),
            Duration::from_secs(60),
        );
        assert_eq!(cache.get("a.example"), Some(cs_api("https://a", false)));

        cache.set("b.example", cs_api("https://b", false), Duration::ZERO);
        assert_eq!(cache.get("b.example"), None);
        assert_eq!(cache.get("missing.example"), None);
    }

    #[test]
    fn cache_ttl_defaults_without_a_usable_header() {
        assert_eq!(
            cache_ttl(&reqwest::header::HeaderMap::new()),
            DEFAULT_CS_API_CACHE_TTL
        );
        assert_eq!(cache_ttl(&headers("no-cache")), DEFAULT_CS_API_CACHE_TTL);
    }

    #[test]
    fn cache_ttl_honours_max_age_within_bounds() {
        assert_eq!(cache_ttl(&headers("max-age=7200")), Duration::from_hours(2));
        assert_eq!(
            cache_ttl(&headers("public, max-age=7200, must-revalidate")),
            Duration::from_hours(2)
        );
    }

    /// A tiny max-age would have us hammering the server; an absurd one would
    /// pin a stale URL.
    #[test]
    fn cache_ttl_clamps_hostile_values() {
        assert_eq!(cache_ttl(&headers("max-age=1")), MIN_CS_API_CACHE_TTL);
        assert_eq!(
            cache_ttl(&headers("max-age=99999999")),
            MAX_CS_API_CACHE_TTL
        );
    }
}
