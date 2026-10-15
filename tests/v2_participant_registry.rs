mod common;

use common::TestPki;
use ishare::v2::ParticipantRegistry;
use serde_json::{json, Value};
use tracing_test::traced_test;
use wiremock::{
    matchers::{body_string_contains, header, method, path},
    Mock, MockServer, ResponseTemplate,
};

const REGISTRY_EORI: &str = "EU.EORI.TESTSAT";
const CLIENT_EORI: &str = "EU.EORI.TESTCLIENT";

fn trusted_list_payload(iss: &str) -> Value {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    json!({
        "iss": iss,
        "sub": iss,
        "aud": CLIENT_EORI,
        "jti": "9774d924b8c04b97bd3f0807deb154b6",
        "iat": now,
        "nbf": now,
        "exp": now + 30,
        "trusted_list": [{
            "subject": "CN=TEST iSHARE EU Issuing Certification Authority G5",
            "certificate_fingerprint": "FD5593DC874ECC1133C21A77259C3592552EC0C89DFCD7AB3C0BDCFD73F0F5CC",
            "validity": "Valid",
            "status": "Granted"
        }]
    })
}

#[tokio::test]
#[traced_test]
async fn get_trusted_list_warns_about_unexpected_issuer() {
    let pki = TestPki::new();
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/trusted_list"))
        .and(header("Authorization", "Bearer access-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(
            json!({ "trusted_list_token": pki.sign(&trusted_list_payload("EU.EORI.SOMEONEELSE")) }),
        ))
        .mount(&server)
        .await;
    let (identity, _) = pki.identity(CLIENT_EORI);
    let registry = ParticipantRegistry::new(
        identity,
        Some(pki.trust_anchor()),
        server.uri(),
        REGISTRY_EORI.to_owned(),
        None,
    );

    registry.get_trusted_list("access-token").await.unwrap();

    assert!(logs_contain("issued by EU.EORI.SOMEONEELSE"));
}

fn registry(pki: &TestPki, url: &str) -> ParticipantRegistry {
    let (identity, _) = pki.identity(CLIENT_EORI);
    ParticipantRegistry::new(
        identity,
        Some(pki.trust_anchor()),
        url.to_owned(),
        REGISTRY_EORI.to_owned(),
        None,
    )
}

#[tokio::test]
async fn get_satellite_access_token_posts_single_form_content_type() {
    let pki = TestPki::new();
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/connect/token"))
        .and(header("Content-Type", "application/x-www-form-urlencoded"))
        .and(body_string_contains("grant_type=client_credentials"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "access-token",
            "token_type": "Bearer",
            "expires_in": 3600
        })))
        .expect(1)
        .mount(&server)
        .await;

    let response = registry(&pki, &server.uri())
        .get_satellite_access_token("assertion")
        .await
        .unwrap();

    assert_eq!(response.access_token, "access-token");
}

#[tokio::test]
async fn get_satellite_access_token_reports_error_description_without_retrying() {
    let pki = TestPki::new();
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/connect/token"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "error": "invalid_request",
            "error_description": "Invalid client assertion"
        })))
        .expect(1)
        .mount(&server)
        .await;

    let error = registry(&pki, &server.uri())
        .get_satellite_access_token("rejected-assertion")
        .await
        .unwrap_err();

    assert!(error.message.contains("400"), "{}", error.message);
    assert!(
        error.message.contains("Invalid client assertion"),
        "{}",
        error.message
    );
}
