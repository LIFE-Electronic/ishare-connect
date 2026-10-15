mod common;

use common::{documented_payload, TestPki};
use ishare::v3::delegation_evidence::{verify_delegation_evidence, DelegationEvidenceContainer};
use ishare::v3::delegation_request::{build_simple_delegation_request, DelegationRequestContainer};
use ishare::v3::pdp::PDP;
use serde_json::{json, Value};
use wiremock::{
    matchers::{method, path},
    Mock, MockServer, ResponseTemplate,
};

const REQUEST: &str = include_str!("fixtures/v3/delegation_request.json");
const EVIDENCE_PAYLOAD: &str = include_str!("fixtures/v3/delegation_evidence_token_payload.json");

#[test]
fn documented_delegation_request_round_trips() {
    let documented: Value = serde_json::from_str(REQUEST).unwrap();

    let request: DelegationRequestContainer = serde_json::from_value(documented.clone()).unwrap();

    assert_eq!(serde_json::to_value(&request).unwrap(), documented);
}

#[test]
fn simple_delegation_request_puts_service_provider_in_context() {
    let request = build_simple_delegation_request(
        "did:ishare:EU.NL.NTRNL-10000005".to_owned(),
        "did:ishare:EU.NL.NTRNL-10000001".to_owned(),
        "GS1.CONTAINER".to_owned(),
        "did:ishare:EU.NL.NTRNL-10000003".to_owned(),
        vec!["ISHARE.READ".to_owned()],
        Some(vec!["180621.CONTAINER-Z".to_owned()]),
        None,
    );

    let target = &serde_json::to_value(&request).unwrap()["delegationRequest"]["policySets"][0]
        ["policies"][0]["target"];

    assert_eq!(
        target["context"],
        json!({ "serviceProvider": "did:ishare:EU.NL.NTRNL-10000003" })
    );
    assert!(target.get("environment").is_none());
}

#[test]
fn documented_delegation_evidence_permits() {
    let payload: Value = serde_json::from_str(EVIDENCE_PAYLOAD).unwrap();

    let evidence: DelegationEvidenceContainer = serde_json::from_value(payload).unwrap();

    assert!(verify_delegation_evidence(
        &evidence.delegation_evidence,
        "GS1.CONTAINER".to_owned()
    ));
}

#[tokio::test]
async fn authorize_reads_delegation_token() {
    let pki = TestPki::new();
    let payload = documented_payload(EVIDENCE_PAYLOAD);
    let (identity, _) = pki.identity(payload["aud"].as_str().unwrap());
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/delegation"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({ "delegationToken": pki.sign(&payload) })),
        )
        .expect(1)
        .mount(&server)
        .await;
    let pdp = PDP::new(
        &identity,
        "did:ishare:EU.NL.NTRNL-10000004".to_owned(),
        server.uri(),
    );

    let authorized = pdp
        .authorize(
            "access-token",
            "ISHARE.READ",
            "did:ishare:EU.NL.NTRNL-10000001",
            "did:ishare:EU.NL.NTRNL-10000005",
            "GS1.CONTAINER",
            Some(vec!["180621.ABC1234".to_owned()]),
            None,
        )
        .await
        .unwrap();

    assert!(authorized);
}
