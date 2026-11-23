mod common;

use base64::prelude::*;
use common::TestPki;
use ishare::{DecodeTokenError, GetFirstX5CError, VerifyTokenError};
use jsonwebtoken::errors::ErrorKind;
use serde_json::json;

fn payload() -> serde_json::Value {
    let now = chrono::Utc::now().timestamp();
    json!({"iss":"SENDER","sub":"SENDER","aud":"RECEIVER","iat":now,"exp":now+30,"jti":"test-assertion"})
}

#[test]
fn untrusted_certificate_has_a_typed_reason_and_legacy_false_is_preserved() {
    let trusted = TestPki::new();
    let foreign = TestPki::new();
    let token = foreign.sign(&payload());
    let anchor = trusted.trust_anchor();
    let error = anchor.verify_token(&token).unwrap_err();
    assert!(matches!(error, VerifyTokenError::UntrustedCertificate));
    assert!(error
        .to_string()
        .contains("not signed by the configured trust anchor"));
    assert!(!format!("{error:?}").contains(&token));
    assert!(!anchor.validate_token(&token).unwrap());
    assert!(anchor.verify_token(&trusted.sign(&payload())).is_ok());
}

#[test]
fn missing_and_empty_certificate_headers_are_typed_failures_not_panics() {
    let pki = TestPki::new();
    for header in [
        json!({"alg":"RS256","typ":"JWT"}),
        json!({"alg":"RS256","typ":"JWT","x5c":[]}),
    ] {
        let token = format!(
            "{}.e30.c2lnbmF0dXJl",
            BASE64_URL_SAFE_NO_PAD.encode(header.to_string())
        );
        let error = pki.trust_anchor().verify_token(&token).unwrap_err();
        assert!(matches!(
            error,
            VerifyTokenError::GetFirstX5CError(GetFirstX5CError::MissingX5CHeader)
        ));
        assert!(!format!("{error:?}").contains(&token));
    }
}

#[test]
fn malformed_assertions_preserve_the_error_source_without_exposing_the_token() {
    use std::error::Error;
    let pki = TestPki::new();
    let header = json!({"alg":"RS256","typ":"JWT","x5c":["not-a-certificate"]});
    let malformed_certificate = format!(
        "{}.e30.c2lnbmF0dXJl",
        BASE64_URL_SAFE_NO_PAD.encode(header.to_string())
    );
    for token in [
        "sensitive-invalid-assertion".to_owned(),
        malformed_certificate,
    ] {
        let error = pki.trust_anchor().verify_token(&token).unwrap_err();
        assert!(matches!(error, VerifyTokenError::GetFirstX5CError(_)));
        assert!(error.source().is_some());
        assert!(!format!("{error:?}").contains(&token));
    }
}

#[test]
fn jwt_validation_preserves_typed_audience_expiry_signature_and_issuer_reasons() {
    let pki = TestPki::new();
    let (receiver, _) = pki.identity("RECEIVER");
    let mut wrong_audience = payload();
    wrong_audience["aud"] = json!("OTHER");
    let mut expired = payload();
    expired["iat"] = json!(chrono::Utc::now().timestamp() - 3600);
    expired["exp"] = json!(chrono::Utc::now().timestamp() - 3570);
    for (claims, kind) in [
        (wrong_audience, ErrorKind::InvalidAudience),
        (expired, ErrorKind::ExpiredSignature),
    ] {
        let token = pki.sign(&claims);
        let error = receiver
            .decode_token(chrono::Utc::now(), &token, "SENDER", None)
            .unwrap_err();
        match error {
            DecodeTokenError::DecodingError(ref source) => assert_eq!(source.kind(), &kind),
            _ => panic!("unexpected validation error: {error:?}"),
        }
        assert!(!format!("{error:?}").contains(&token));
    }
    let token = pki.sign(&payload());
    let mut parts: Vec<_> = token.split('.').map(str::to_owned).collect();
    let replacement = if parts[2].starts_with('A') { "B" } else { "A" };
    parts[2].replace_range(0..1, replacement);
    let forged = parts.join(".");
    let error = receiver
        .decode_token(chrono::Utc::now(), &forged, "SENDER", None)
        .unwrap_err();
    assert!(
        matches!(error,DecodeTokenError::DecodingError(ref source) if source.kind()==&ErrorKind::InvalidSignature)
    );
    let mut wrong_issuer = payload();
    wrong_issuer["iss"] = json!("OTHER");
    wrong_issuer["sub"] = json!("OTHER");
    assert!(matches!(
        receiver.decode_token(chrono::Utc::now(), &pki.sign(&wrong_issuer), "SENDER", None),
        Err(DecodeTokenError::IssDoesntMatchClientId)
    ));
}
