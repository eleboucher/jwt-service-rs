//! Request and response bodies. Plain `String` fields, so a homeserver can
//! parse them into its own types.

use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize, Debug, Default, Clone)]
#[serde(deny_unknown_fields)]
pub struct OpenIdToken {
    pub access_token: String,
    #[serde(default)]
    pub token_type: String,
    pub matrix_server_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_in: Option<i32>,
}

#[derive(Deserialize, Serialize, Debug, Default, Clone)]
#[serde(deny_unknown_fields)]
pub struct RtcMember {
    pub id: String,
    /// Absent on the MSC4195 endpoint.
    #[serde(default)]
    pub claimed_user_id: String,
    pub claimed_device_id: String,
}

/// Deprecated: later MSC revisions moved delegation to its own endpoint.
#[derive(Deserialize, Serialize, Debug, Default, Clone)]
pub struct DelayParams {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delay_id: Option<String>,
    /// Milliseconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delay_timeout: Option<i64>,
    /// Accepted and ignored.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delay_cs_api_url: Option<String>,
}

impl DelayParams {
    #[must_use]
    pub fn requested(&self) -> Option<(&str, i64)> {
        match (self.delay_id.as_deref(), self.delay_timeout) {
            (Some(id), Some(timeout)) if !id.is_empty() && timeout > 0 => Some((id, timeout)),
            _ => None,
        }
    }

    #[must_use]
    pub fn is_half_specified(&self) -> bool {
        let has_id = self.delay_id.as_deref().is_some_and(|id| !id.is_empty());
        let has_timeout = self.delay_timeout.is_some_and(|t| t > 0);

        has_id != has_timeout
    }
}

#[derive(Deserialize, Serialize, Debug, Default, Clone)]
#[serde(deny_unknown_fields)]
pub struct GetTokenRequest {
    pub room_id: String,
    pub slot_id: String,
    pub openid_token: OpenIdToken,
    pub member: RtcMember,
    #[serde(flatten)]
    pub delay: DelayParams,
}

/// Deprecated: predates slots and per-member identities.
#[derive(Deserialize, Serialize, Debug, Default, Clone)]
#[serde(deny_unknown_fields)]
pub struct LegacySfuRequest {
    pub room: String,
    pub openid_token: OpenIdToken,
    pub device_id: String,
    #[serde(flatten)]
    pub delay: DelayParams,
}

#[derive(Deserialize, Serialize, Debug, Default, Clone)]
#[serde(deny_unknown_fields)]
pub struct Msc4195GetTokenRequest {
    /// Defaults to the receiving server.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_name: Option<String>,
    pub room_id: String,
    pub slot_id: String,
    pub member: RtcMember,
}

/// No token is issued, so the delayed-event fields are mandatory.
#[derive(Deserialize, Serialize, Debug, Default, Clone)]
#[serde(deny_unknown_fields)]
pub struct DelegateDelayedLeaveRequest {
    pub room_id: String,
    pub slot_id: String,
    pub openid_token: OpenIdToken,
    pub member: RtcMember,
    pub delay_id: String,
    /// Milliseconds.
    pub delay_timeout: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delay_cs_api_url: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SfuResponse {
    pub url: String,
    pub jwt: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MatrixError {
    pub errcode: String,
    pub error: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_token_request_accepts_an_element_call_body() {
        let body = serde_json::json!({
            "room_id": "!abc:example.com",
            "slot_id": "m.call#ROOM",
            "openid_token": {
                "access_token": "tok",
                "token_type": "Bearer",
                "matrix_server_name": "example.com",
                "expires_in": 3600
            },
            "member": {
                "id": "xyz",
                "claimed_user_id": "@alice:example.com",
                "claimed_device_id": "DEV"
            }
        });

        let parsed: GetTokenRequest = serde_json::from_value(body).unwrap();
        assert_eq!(parsed.room_id, "!abc:example.com");
        assert_eq!(parsed.member.claimed_device_id, "DEV");
        assert!(parsed.delay.requested().is_none());
    }

    #[test]
    fn delay_params_are_accepted_and_paired() {
        let body = serde_json::json!({
            "room": "!abc:example.com",
            "openid_token": { "access_token": "tok", "matrix_server_name": "example.com" },
            "device_id": "DEV",
            "delay_id": "1234",
            "delay_timeout": 3_600_000,
            "delay_cs_api_url": "https://matrix.example.com"
        });

        let parsed: LegacySfuRequest = serde_json::from_value(body).unwrap();
        assert_eq!(parsed.delay.requested(), Some(("1234", 3_600_000)));
        assert!(!parsed.delay.is_half_specified());
    }

    #[test]
    fn half_specified_delay_params_are_detected() {
        let only_id = DelayParams {
            delay_id: Some("x".into()),
            ..Default::default()
        };
        let only_timeout = DelayParams {
            delay_timeout: Some(1000),
            ..Default::default()
        };

        assert!(only_id.is_half_specified());
        assert!(only_timeout.is_half_specified());
        assert!(!DelayParams::default().is_half_specified());
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let body = serde_json::json!({
            "room_id": "!abc:example.com",
            "slot_id": "s",
            "openid_token": { "access_token": "t", "matrix_server_name": "example.com" },
            "member": { "id": "x", "claimed_device_id": "D" },
            "surprise": true
        });

        assert!(serde_json::from_value::<GetTokenRequest>(body).is_err());
    }

    #[test]
    fn sfu_response_serialises_to_url_and_jwt() {
        let json = serde_json::to_value(SfuResponse {
            url: "wss://sfu".into(),
            jwt: "tok".into(),
        })
        .unwrap();

        assert_eq!(
            json,
            serde_json::json!({ "url": "wss://sfu", "jwt": "tok" })
        );
    }
}
