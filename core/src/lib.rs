//! The parts of a MatrixRTC LiveKit focus that are the same wherever it runs:
//! the MSC4195 identifier derivations and LiveKit access-token minting.
//!
//! Kept free of HTTP, OpenID and Matrix server resolution so a homeserver can
//! reuse it without inheriting a standalone service's dependencies.

pub mod wire;

use std::time::Duration;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use livekit_api::access_token::{AccessToken, AccessTokenError, VideoGrants};
use serde::Serialize;
use sha2::{Digest, Sha256};

/// The slot the pre-Matrix-2.0 `/sfu/get` endpoint assumes, since it predates
/// slots.
pub const LEGACY_SLOT_ID: &str = "m.call#ROOM";

const TOKEN_TTL: Duration = Duration::from_hours(1);

/// The LiveKit room name for a MatrixRTC slot in a Matrix room.
#[must_use]
pub fn room_alias(room_id: &str, slot_id: &str) -> String {
    hashed_id(&[room_id, slot_id])
}

/// The pseudonymous LiveKit participant identity for an RTC member, so the
/// Matrix user ID is not exposed to the SFU.
#[must_use]
pub fn participant_identity(user_id: &str, device_id: &str, member_id: &str) -> String {
    hashed_id(&[user_id, device_id, member_id])
}

/// `unpadded_base64(sha256(json_serialize(parts)))`, per MSC4195.
///
/// The base64 alphabet is the standard one, not URL-safe. Together with the
/// encoding below, both details have to match or peers land in different
/// LiveKit rooms.
fn hashed_id(parts: &[&str]) -> String {
    STANDARD
        .encode(Sha256::digest(marshal_strings(parts)))
        .trim_end_matches('=')
        .to_string()
}

/// Serialises like Go's `json.Marshal([]string{...})`.
///
/// Go's encoder HTML-escapes `<`, `>` and `&`, and spells backspace and form
/// feed in the `\u00XX` form. serde_json does neither, so without this an id
/// containing one of those would hash differently here than in lk-jwt-service.
fn marshal_strings(parts: &[&str]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut serializer = serde_json::Serializer::with_formatter(&mut out, GoFormatter);

    parts
        .serialize(&mut serializer)
        .expect("serializing a string array to a Vec cannot fail");

    out
}

struct GoFormatter;

impl serde_json::ser::Formatter for GoFormatter {
    fn write_string_fragment<W>(&mut self, writer: &mut W, fragment: &str) -> std::io::Result<()>
    where
        W: ?Sized + std::io::Write,
    {
        let mut rest = fragment;

        while let Some(at) = rest.find(['<', '>', '&']) {
            let (before, tail) = rest.split_at(at);
            let escaped = tail.chars().next().expect("find returns a char boundary");

            writer.write_all(before.as_bytes())?;
            write!(writer, "\\u{:04x}", escaped as u32)?;

            rest = &tail[escaped.len_utf8()..];
        }

        writer.write_all(rest.as_bytes())
    }

    fn write_char_escape<W>(
        &mut self,
        writer: &mut W,
        char_escape: serde_json::ser::CharEscape,
    ) -> std::io::Result<()>
    where
        W: ?Sized + std::io::Write,
    {
        use serde_json::ser::CharEscape::{Backspace, FormFeed};

        match char_escape {
            Backspace => write!(writer, "\\u0008"),
            FormFeed => write!(writer, "\\u000c"),
            other => serde_json::ser::Formatter::write_char_escape(
                &mut serde_json::ser::CompactFormatter,
                writer,
                other,
            ),
        }
    }
}

/// Mints a LiveKit access token valid for an hour.
///
/// `room_create` is never granted: rooms are created server-side via the
/// RoomService API, which is what Element Call expects when the SFU runs with
/// `auto_create: false`.
///
/// # Errors
///
/// Returns an error if the API secret cannot be used to sign the token.
pub fn join_token(
    api_key: &str,
    api_secret: &str,
    room: &str,
    identity: &str,
) -> Result<String, AccessTokenError> {
    AccessToken::with_api_key(api_key, api_secret)
        .with_grants(VideoGrants {
            room: room.to_owned(),
            room_create: false,
            room_join: true,
            can_publish: true,
            can_subscribe: true,
            can_update_own_metadata: true,
            ..Default::default()
        })
        .with_identity(identity)
        .with_ttl(TOKEN_TTL)
        .to_jwt()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// MSC4195 test vector.
    #[test]
    fn room_alias_matches_the_msc_vector() {
        assert_eq!(
            room_alias("!roomid:example.com", "slot1234"),
            "O8437W3+jmzMVjoIP3tNwbm+XxHQk2iKpOA7aqw3qSc"
        );
    }

    /// MSC4195 test vector.
    #[test]
    fn participant_identity_matches_the_msc_vector() {
        assert_eq!(
            participant_identity("@alice:example.com", "DEVICE123", "memberABC"),
            "J+T45tGruxc+HrUOqJJlyQSV33m728Cme4+vt8/SWrU"
        );
    }

    /// Go HTML-escapes these and serde_json does not; a mismatch would put
    /// peers in different LiveKit rooms.
    #[test]
    fn marshal_strings_matches_go_html_escaping() {
        let encoded =
            String::from_utf8(marshal_strings(&["!a&b:example.com", "m.call#ROOM"])).unwrap();

        for raw in ['&', '<', '>'] {
            assert!(!encoded.contains(raw), "{raw} not escaped in {encoded}");
        }
        assert!(encoded.contains("u0026"), "{encoded}");

        // Computed by Go: json.Marshal, sha256, unpadded base64.
        assert_eq!(
            room_alias("!a&b:example.com", "m.call#ROOM"),
            "BlPHg/JCOxLQr20ttEizBQLd7Bhh5m+r3M8rO3ejvzo"
        );
    }

    #[test]
    fn marshal_strings_escapes_control_characters_like_go() {
        let encoded = String::from_utf8(marshal_strings(&["a\u{8}b\u{c}c"])).unwrap();

        // Go uses the \u00XX form where serde_json would emit \b and \f.
        assert!(encoded.contains("u0008"), "{encoded}");
        assert!(encoded.contains("u000c"), "{encoded}");
        assert!(!encoded.contains('\u{8}'), "{encoded}");

        let quoted = String::from_utf8(marshal_strings(&["a\"b"])).unwrap();
        assert_eq!(quoted, r#"["a\"b"]"#);
    }

    /// A delimiter-joined input would let parts bleed into each other.
    #[test]
    fn hashed_id_is_not_delimiter_joined() {
        assert_ne!(room_alias("a", "b|c"), room_alias("a|b", "c"));
        assert_ne!(room_alias("a", "bc"), room_alias("ab", "c"));
    }

    #[test]
    fn hashed_id_uses_the_standard_alphabet() {
        let alias = room_alias("!roomid:example.com", "slot1234");
        assert!(alias.contains('+'));
        assert!(!alias.contains('='));
    }

    #[test]
    fn join_token_grants_join_but_never_create() {
        let jwt = join_token("devkey", "secret", "myroom", "myidentity").unwrap();
        let segments: Vec<_> = jwt.split('.').collect();
        assert_eq!(segments.len(), 3);

        let claims: serde_json::Value = serde_json::from_slice(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(segments[1])
                .unwrap(),
        )
        .unwrap();

        assert_eq!(claims["sub"], "myidentity");
        assert_eq!(claims["video"]["room"], "myroom");
        assert_eq!(claims["video"]["roomJoin"], true);
        assert_eq!(claims["video"]["roomCreate"], false);
        assert_eq!(claims["video"]["canPublish"], true);
        assert_eq!(claims["video"]["canSubscribe"], true);
    }
}
