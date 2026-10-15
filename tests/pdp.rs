mod common;

use common::TestPki;
use ishare::pdp::PDP;
use serde_json::json;
use wiremock::{
    matchers::{body_string_contains, header, method, path},
    Mock, MockServer, ResponseTemplate,
};

fn login_response() -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(json!({
        "access_token": "access-token",
        "expires_in": 3600
    }))
}

#[tokio::test]
async fn connect_posts_single_form_content_type() {
    let pki = TestPki::new();
    let (identity, _) = pki.identity("EU.EORI.TESTCLIENT");
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/connect/machine/token"))
        .and(header("Content-Type", "application/x-www-form-urlencoded"))
        .and(body_string_contains("grant_type=client_credentials"))
        .respond_with(login_response())
        .expect(1)
        .mount(&server)
        .await;
    let pdp = PDP::new(&identity, "EU.EORI.TESTAR".to_owned(), server.uri());

    let response = pdp.connect().await.unwrap();

    assert_eq!(response.access_token, "access-token");
}

#[tokio::test]
async fn connect_admin_posts_single_form_content_type() {
    let pki = TestPki::new();
    let (identity, _) = pki.identity("EU.EORI.TESTCLIENT");
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/oauth2/token"))
        .and(header("Content-Type", "application/x-www-form-urlencoded"))
        .and(header("Authorization", "Basic YXBwOnNlY3JldA=="))
        .and(body_string_contains("grant_type=password"))
        .respond_with(login_response())
        .expect(1)
        .mount(&server)
        .await;
    let pdp = PDP::new(&identity, "EU.EORI.TESTAR".to_owned(), server.uri());

    let response = pdp
        .connect_admin("admin", "password", "app", "secret")
        .await
        .unwrap();

    assert_eq!(response.access_token, "access-token");
}
