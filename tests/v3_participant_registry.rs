mod common;

use base64::prelude::*;
use common::{documented_payload, TestPki};
use ishare::{
    v3::{Capabilities, ParticipantRegistry, PartiesQuery, Party, ValidatePartyError},
    AllowedDataspaces,
};
use openssl::x509::X509;
use serde_json::{json, Value};
use tracing_test::traced_test;
use wiremock::{
    matchers::{body_string_contains, header, method, path, query_param},
    Mock, MockServer, ResponseTemplate,
};

// Decoded payloads of the example responses on https://dev.ishare.eu/participant-registry-role/,
// copied verbatim.
const PARTIES_PAYLOAD: &str = include_str!("fixtures/v3/parties_token_payload.json");
const PARTY_PAYLOAD: &str = include_str!("fixtures/v3/party_token_payload.json");
const CAPABILITIES_PAYLOAD: &str = include_str!("fixtures/v3/capabilities_token_payload.json");
const TRUSTED_LIST_PAYLOAD: &str = include_str!("fixtures/v3/trusted_list_token_payload.json");

/// A registry client for `payload`'s audience, against a mock answering `GET endpoint` with `body`.
/// Also returns the client's own certificate.
async fn registry_serving(
    pki: &TestPki,
    payload: &Value,
    endpoint: &str,
    body: Value,
    allowed_dataspaces: Option<AllowedDataspaces>,
) -> (MockServer, ParticipantRegistry, X509) {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(endpoint))
        .and(header("Authorization", "Bearer access-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(&server)
        .await;
    let (registry, client_cert) = registry_for(pki, payload, &server.uri(), allowed_dataspaces);
    (server, registry, client_cert)
}

/// A registry client for `payload`'s audience against the registry at `url`, plus the client's
/// own certificate.
fn registry_for(
    pki: &TestPki,
    payload: &Value,
    url: &str,
    allowed_dataspaces: Option<AllowedDataspaces>,
) -> (ParticipantRegistry, X509) {
    let (identity, client_cert) = pki.identity(payload["aud"].as_str().unwrap());
    let registry = ParticipantRegistry::new(
        identity,
        Some(pki.trust_anchor()),
        url.to_owned(),
        payload["iss"].as_str().unwrap().to_owned(),
        allowed_dataspaces,
    );
    (registry, client_cert)
}

#[tokio::test]
async fn get_all_parties_returns_documented_parties_info() {
    let pki = TestPki::new();
    let payload = documented_payload(PARTIES_PAYLOAD);
    let (_server, registry, _) = registry_serving(
        &pki,
        &payload,
        "/parties",
        json!({ "partiesToken": pki.sign(&payload) }),
        None,
    )
    .await;

    let parties_info = registry
        .get_all_parties("access-token", &PartiesQuery::default())
        .await
        .unwrap();

    assert_eq!(
        serde_json::to_value(&parties_info).unwrap(),
        payload["partiesInfo"]
    );
}

#[tokio::test]
async fn get_party_returns_documented_party_info() {
    let pki = TestPki::new();
    let payload = documented_payload(PARTY_PAYLOAD);
    let party_id = payload["partyInfo"]["id"].as_str().unwrap().to_owned();
    let (_server, registry, _) = registry_serving(
        &pki,
        &payload,
        &format!("/parties/{party_id}"),
        json!({ "partyToken": pki.sign(&payload) }),
        None,
    )
    .await;

    let party = registry.get_party(&party_id, "access-token").await.unwrap();

    assert_eq!(serde_json::to_value(&party).unwrap(), payload["partyInfo"]);
}

const DOCUMENTED_PARTY_ID: &str = "did:ishare:EU.NL.NTRNL-12345678";

/// Runs `validate_party` for the documented party against a registry serving `payload`.
async fn validate_party(
    payload: &Value,
    allowed_dataspaces: Option<AllowedDataspaces>,
) -> Result<Party, ValidatePartyError> {
    let pki = TestPki::new();
    let (_server, registry, _) = registry_serving(
        &pki,
        payload,
        &format!("/parties/{DOCUMENTED_PARTY_ID}"),
        json!({ "partyToken": pki.sign(payload) }),
        allowed_dataspaces,
    )
    .await;
    registry
        .validate_party(chrono::Utc::now(), DOCUMENTED_PARTY_ID, "access-token")
        .await
}

fn example_dataspace() -> AllowedDataspaces {
    AllowedDataspaces {
        dataspace_ids: vec!["EU.DSP.EXAMPLE".to_owned()],
        required_agreement_types: vec!["TermsOfUse".to_owned()],
    }
}

fn example_dataspace_without_agreements() -> AllowedDataspaces {
    AllowedDataspaces {
        dataspace_ids: vec!["EU.DSP.EXAMPLE".to_owned()],
        required_agreement_types: vec![],
    }
}

fn membership_claim(dataspace_id: &str, status: &str) -> Value {
    json!({
        "id": "6a0f8f0e-2a4e-4c55-9f5e-0c1b7d1e9b21",
        "status": status,
        "registrarId": "did:ishare:EU.NL.NTRNL-10000000",
        "startDate": "2025-01-01T00:00:00.000Z",
        "type": "dataspaceMembership",
        "dataspaceId": dataspace_id,
        "legalAdherence": "yes"
    })
}

fn add_claim(payload: &mut Value, claim: Value) {
    payload["partyInfo"]["claims"]
        .as_array_mut()
        .unwrap()
        .push(claim);
}

#[tokio::test]
async fn validate_party_accepts_documented_party() {
    let payload = documented_payload(PARTY_PAYLOAD);

    let party = validate_party(&payload, None).await.unwrap();

    assert_eq!(serde_json::to_value(&party).unwrap(), payload["partyInfo"]);
}

#[tokio::test]
async fn validate_party_reports_empty_party_info_as_not_found() {
    let mut payload = documented_payload(PARTY_PAYLOAD);
    payload["partyInfo"] = json!({ "alsoKnownAs": [], "claims": [] });

    let result = validate_party(&payload, None).await;

    assert!(matches!(result, Err(ValidatePartyError::NotFound(id)) if id == DOCUMENTED_PARTY_ID));
}

#[tokio::test]
async fn validate_party_rejects_party_without_active_framework_compliance() {
    let mut payload = documented_payload(PARTY_PAYLOAD);
    payload["partyInfo"]["claims"][0]["status"] = json!("inactive");

    let result = validate_party(&payload, None).await;

    assert!(matches!(result, Err(ValidatePartyError::Inactive(_))));
}

#[tokio::test]
async fn validate_party_requires_agreement_for_allowed_dataspace() {
    let payload = documented_payload(PARTY_PAYLOAD);

    let result = validate_party(&payload, Some(example_dataspace())).await;

    assert!(matches!(
        result,
        Err(ValidatePartyError::DataspaceMembershipNotFound(_))
    ));
}

#[tokio::test]
async fn validate_party_accepts_member_with_required_agreements() {
    let mut payload = documented_payload(PARTY_PAYLOAD);
    add_claim(&mut payload, membership_claim("EU.DSP.EXAMPLE", "active"));
    add_claim(
        &mut payload,
        json!({
            "id": "0b6c1a52-6f0e-4b8e-9d0a-3f1f3c2e7a11",
            "status": "active",
            "registrarId": "did:ishare:EU.NL.NTRNL-10000000",
            "type": "dataspaceAgreement",
            "agreementType": "TermsOfUse",
            "agreementId": "3cde6ff3-243d-48c0-8003-31d3fea3c1f1",
            "title": "Terms of Use",
            "dataspaceId": "EU.DSP.EXAMPLE"
        }),
    );

    let result = validate_party(&payload, Some(example_dataspace())).await;

    assert!(result.is_ok(), "{result:?}");
}

#[tokio::test]
async fn validate_party_rejects_agreements_without_membership() {
    let mut payload = documented_payload(PARTY_PAYLOAD);
    add_claim(
        &mut payload,
        json!({
            "id": "0b6c1a52-6f0e-4b8e-9d0a-3f1f3c2e7a11",
            "status": "active",
            "registrarId": "did:ishare:EU.NL.NTRNL-10000000",
            "type": "dataspaceAgreement",
            "agreementType": "TermsOfUse",
            "agreementId": "3cde6ff3-243d-48c0-8003-31d3fea3c1f1",
            "title": "Terms of Use",
            "dataspaceId": "EU.DSP.EXAMPLE"
        }),
    );

    let result = validate_party(&payload, Some(example_dataspace())).await;

    assert!(matches!(
        result,
        Err(ValidatePartyError::DataspaceMembershipNotFound(_))
    ));
}

#[tokio::test]
async fn validate_party_requires_membership_of_allowed_dataspace() {
    let mut payload = documented_payload(PARTY_PAYLOAD);
    add_claim(&mut payload, membership_claim("EU.DSP.OTHER", "active"));

    let result = validate_party(&payload, Some(example_dataspace_without_agreements())).await;

    assert!(matches!(
        result,
        Err(ValidatePartyError::DataspaceMembershipNotFound(_))
    ));
}

#[tokio::test]
async fn validate_party_rejects_inactive_membership() {
    let mut payload = documented_payload(PARTY_PAYLOAD);
    add_claim(&mut payload, membership_claim("EU.DSP.EXAMPLE", "inactive"));

    let result = validate_party(&payload, Some(example_dataspace_without_agreements())).await;

    assert!(matches!(
        result,
        Err(ValidatePartyError::DataspaceMembershipNotFound(_))
    ));
}

#[tokio::test]
async fn validate_party_accepts_active_membership_without_required_agreements() {
    let mut payload = documented_payload(PARTY_PAYLOAD);
    add_claim(&mut payload, membership_claim("EU.DSP.EXAMPLE", "active"));

    let result = validate_party(&payload, Some(example_dataspace_without_agreements())).await;

    assert!(result.is_ok(), "{result:?}");
}

#[tokio::test]
async fn validate_party_certificate_matches_x509_certificate_claim() {
    let pki = TestPki::new();
    let mut payload = documented_payload(PARTY_PAYLOAD);
    let (_server, registry, client_cert) =
        registry_serving(&pki, &payload, "/unused", json!({}), None).await;
    let client_id = registry.identity().eori().to_owned();
    let assertion = registry
        .identity()
        .create_client_assertion(client_id.clone())
        .unwrap();
    let decoded = registry
        .identity()
        .decode_token(chrono::Utc::now(), &assertion, &client_id, Some(&client_id))
        .unwrap();
    let documented: Party = serde_json::from_value(payload["partyInfo"].clone()).unwrap();
    payload["partyInfo"]["claims"][4]["x5c"] =
        json!(BASE64_STANDARD.encode(client_cert.to_der().unwrap()));
    let with_client_cert: Party = serde_json::from_value(payload["partyInfo"].clone()).unwrap();

    assert!(registry
        .validate_party_certificate(&decoded, &with_client_cert)
        .unwrap());
    assert!(!registry
        .validate_party_certificate(&decoded, &documented)
        .unwrap());
}

/// Runs `get_public_capabilities` against an unauthenticated mock `/capabilities` serving `payload`.
async fn public_capabilities(payload: &Value) -> Value {
    let pki = TestPki::new();
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/capabilities"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({ "capabilitiesToken": pki.sign(payload) })),
        )
        .mount(&server)
        .await;
    let (registry, _) = registry_for(&pki, payload, &server.uri(), None);

    let capabilities = registry
        .get_public_capabilities(&format!("{}/capabilities", server.uri()))
        .await
        .unwrap();

    serde_json::to_value(&capabilities).unwrap()
}

#[tokio::test]
async fn get_public_capabilities_returns_documented_capabilities_info() {
    let payload = documented_payload(CAPABILITIES_PAYLOAD);

    assert_eq!(
        public_capabilities(&payload).await,
        payload["capabilities_info"]
    );
}

// The OpenAPI model (jwtPayloadCapabilitiesToken) names the claim capabilitiesInfo, as registries
// such as the DMI gen2 one send it; the documented example uses capabilities_info.
#[tokio::test]
async fn get_public_capabilities_accepts_capabilities_info_as_in_openapi_model() {
    let mut payload = documented_payload(CAPABILITIES_PAYLOAD);
    let info = payload
        .as_object_mut()
        .unwrap()
        .remove("capabilities_info")
        .unwrap();
    payload["capabilitiesInfo"] = info.clone();

    assert_eq!(public_capabilities(&payload).await, info);
}

/// Runs `get_trusted_list` against a mock `/trustedList` answering `{ envelope: <signed payload> }`.
async fn trusted_list(payload: &Value, envelope: &str) -> Value {
    let pki = TestPki::new();
    let (_server, registry, _) = registry_serving(
        &pki,
        payload,
        "/trustedList",
        json!({ envelope: pki.sign(payload) }),
        None,
    )
    .await;

    let trusted_list = registry.get_trusted_list("access-token").await.unwrap();

    serde_json::to_value(&trusted_list).unwrap()
}

// Path and envelope as in the OpenAPI model (and the DMI gen2 registry).
#[tokio::test]
async fn get_trusted_list_returns_documented_trusted_list() {
    let payload = documented_payload(TRUSTED_LIST_PAYLOAD);

    assert_eq!(
        trusted_list(&payload, "trustedListToken").await,
        payload["trustedList"]
    );
}

// The documented example response wraps the token as trusted_list_token.
#[tokio::test]
async fn get_trusted_list_accepts_documented_envelope() {
    let payload = documented_payload(TRUSTED_LIST_PAYLOAD);

    assert_eq!(
        trusted_list(&payload, "trusted_list_token").await,
        payload["trustedList"]
    );
}

#[tokio::test]
async fn get_all_parties_sends_documented_query_parameters() {
    let pki = TestPki::new();
    let payload = documented_payload(PARTIES_PAYLOAD);
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/parties"))
        .and(query_param("id", "did:ishare:EU.NL.NTRNL-12345678"))
        .and(query_param(
            "alsoKnownAs",
            "did:elsi:LEIXG-724500AZSGBRY55MNS59",
        ))
        .and(query_param("name", "*corporation"))
        .and(query_param(
            "claimFilter[frameworkRole.roleId]",
            "ServiceConsumer",
        ))
        .and(query_param(
            "claimFilter[dataspaceMembership.dataspaceId]",
            "EU.DSP.EXAMPLE",
        ))
        .and(query_param("page", "2"))
        .and(query_param("pageSize", "20"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({ "partiesToken": pki.sign(&payload) })),
        )
        .mount(&server)
        .await;
    let (registry, _) = registry_for(&pki, &payload, &server.uri(), None);

    let parties_info = registry
        .get_all_parties(
            "access-token",
            &PartiesQuery {
                id: Some("did:ishare:EU.NL.NTRNL-12345678".to_owned()),
                also_known_as: Some("did:elsi:LEIXG-724500AZSGBRY55MNS59".to_owned()),
                name: Some("*corporation".to_owned()),
                claim_filter: vec![
                    (
                        "frameworkRole.roleId".to_owned(),
                        "ServiceConsumer".to_owned(),
                    ),
                    (
                        "dataspaceMembership.dataspaceId".to_owned(),
                        "EU.DSP.EXAMPLE".to_owned(),
                    ),
                ],
                page: Some(2),
                page_size: Some(20),
            },
        )
        .await
        .unwrap();

    assert_eq!(parties_info.total_count, 47);
}

const OTHER_ISSUER: &str = "did:ishare:EU.NL.NTRNL-99999999";

fn issued_by(payload: &Value, iss: &str) -> Value {
    let mut payload = payload.clone();
    payload["iss"] = json!(iss);
    payload["sub"] = json!(iss);
    payload
}

#[tokio::test]
#[traced_test]
async fn get_all_parties_warns_about_unexpected_issuer() {
    let pki = TestPki::new();
    let payload = documented_payload(PARTIES_PAYLOAD);
    let (_server, registry, _) = registry_serving(
        &pki,
        &payload,
        "/parties",
        json!({ "partiesToken": pki.sign(&issued_by(&payload, OTHER_ISSUER)) }),
        None,
    )
    .await;

    registry
        .get_all_parties("access-token", &PartiesQuery::default())
        .await
        .unwrap();

    assert!(logs_contain(&format!("issued by {OTHER_ISSUER}")));
}

#[tokio::test]
#[traced_test]
async fn get_all_parties_does_not_warn_about_expected_issuer() {
    let pki = TestPki::new();
    let payload = documented_payload(PARTIES_PAYLOAD);
    let (_server, registry, _) = registry_serving(
        &pki,
        &payload,
        "/parties",
        json!({ "partiesToken": pki.sign(&payload) }),
        None,
    )
    .await;

    registry
        .get_all_parties("access-token", &PartiesQuery::default())
        .await
        .unwrap();

    assert!(!logs_contain("issued by"));
}

#[tokio::test]
#[traced_test]
async fn get_party_warns_about_unexpected_issuer() {
    let pki = TestPki::new();
    let payload = documented_payload(PARTY_PAYLOAD);
    let (_server, registry, _) = registry_serving(
        &pki,
        &payload,
        &format!("/parties/{DOCUMENTED_PARTY_ID}"),
        json!({ "partyToken": pki.sign(&issued_by(&payload, OTHER_ISSUER)) }),
        None,
    )
    .await;

    registry
        .get_party(DOCUMENTED_PARTY_ID, "access-token")
        .await
        .unwrap();

    assert!(logs_contain(&format!("issued by {OTHER_ISSUER}")));
}

#[tokio::test]
#[traced_test]
async fn get_trusted_list_warns_about_unexpected_issuer() {
    let pki = TestPki::new();
    let payload = documented_payload(TRUSTED_LIST_PAYLOAD);
    let (_server, registry, _) = registry_serving(
        &pki,
        &payload,
        "/trustedList",
        json!({ "trustedListToken": pki.sign(&issued_by(&payload, OTHER_ISSUER)) }),
        None,
    )
    .await;

    registry.get_trusted_list("access-token").await.unwrap();

    assert!(logs_contain(&format!("issued by {OTHER_ISSUER}")));
}

#[tokio::test]
#[traced_test]
async fn get_public_capabilities_warns_about_unexpected_issuer() {
    let pki = TestPki::new();
    let payload = documented_payload(CAPABILITIES_PAYLOAD);
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/capabilities"))
        .respond_with(ResponseTemplate::new(200).set_body_json(
            json!({ "capabilitiesToken": pki.sign(&issued_by(&payload, OTHER_ISSUER)) }),
        ))
        .mount(&server)
        .await;
    let (registry, _) = registry_for(&pki, &payload, &server.uri(), None);

    registry
        .get_public_capabilities(&format!("{}/capabilities", server.uri()))
        .await
        .unwrap();

    assert!(logs_contain(&format!("issued by {OTHER_ISSUER}")));
}

#[tokio::test]
async fn get_satellite_access_token_posts_documented_form() {
    let pki = TestPki::new();
    let payload = documented_payload(PARTY_PAYLOAD);
    let server = MockServer::start().await;
    let (registry, _) = registry_for(&pki, &payload, &server.uri(), None);
    let client_id = registry.identity().eori().to_owned();
    let assertion = registry
        .identity()
        .create_client_assertion(registry.eori().to_owned())
        .unwrap();
    let form = |pairs: &[(&str, &str)]| {
        url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(pairs)
            .finish()
    };
    Mock::given(method("POST"))
        .and(path("/connect/token"))
        .and(header("Content-Type", "application/x-www-form-urlencoded"))
        .and(body_string_contains(form(&[(
            "grant_type",
            "client_credentials",
        )])))
        .and(body_string_contains(form(&[("scope", "iSHARE")])))
        .and(body_string_contains(form(&[("client_id", &client_id)])))
        .and(body_string_contains(form(&[(
            "client_assertion_type",
            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        )])))
        .and(body_string_contains(form(&[(
            "client_assertion",
            &assertion,
        )])))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "access-token",
            "token_type": "Bearer",
            "expires_in": 3600
        })))
        .expect(1)
        .mount(&server)
        .await;

    let response = registry
        .get_satellite_access_token(&assertion)
        .await
        .unwrap();

    assert_eq!(response.access_token, "access-token");
    assert_eq!(response.expires_in, 3600);
}

#[tokio::test]
async fn get_satellite_access_token_reports_error_description_without_retrying() {
    let pki = TestPki::new();
    let payload = documented_payload(PARTY_PAYLOAD);
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
    let (registry, _) = registry_for(&pki, &payload, &server.uri(), None);

    let error = registry
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

fn decoded_claims(token: &str) -> Value {
    let payload = token.split('.').nth(1).unwrap();
    serde_json::from_slice(&BASE64_URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap()
}

/// Serves `token` as a party's own `/capabilities` and reads it back as a v3 consumer would.
async fn read_back_capabilities(pki: &TestPki, issuer: &str, token: &str) -> Value {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/capabilities"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({ "capabilitiesToken": token })),
        )
        .mount(&server)
        .await;
    let (consumer, _) = pki.identity("did:ishare:EU.NL.NTRNL-10000001");
    let registry = ParticipantRegistry::new(
        consumer,
        Some(pki.trust_anchor()),
        server.uri(),
        issuer.to_owned(),
        None,
    );
    let capabilities = registry
        .get_public_capabilities(&format!("{}/capabilities", server.uri()))
        .await
        .unwrap();
    serde_json::to_value(&capabilities).unwrap()
}

#[tokio::test]
async fn produced_public_capabilities_token_is_read_back_by_v3_consumer() {
    let pki = TestPki::new();
    let provider_id = "did:ishare:EU.NL.NTRNL-10000003";
    let (provider, _) = pki.identity(provider_id);
    let info = documented_payload(CAPABILITIES_PAYLOAD)["capabilities_info"].clone();
    let capabilities = Capabilities {
        capabilities_info: serde_json::from_value(info.clone()).unwrap(),
    };

    let token = provider
        .create_token_with_extra_claims(None, &capabilities)
        .unwrap();

    let claims = decoded_claims(&token);
    assert_eq!(claims["iss"], provider_id);
    assert_eq!(claims["sub"], provider_id);
    assert!(claims.get("aud").is_none(), "{claims}");
    assert_eq!(claims["capabilitiesInfo"], info);
    assert_eq!(
        read_back_capabilities(&pki, provider_id, &token).await,
        info
    );
}

#[tokio::test]
async fn produced_capabilities_token_for_requester_has_audience() {
    let pki = TestPki::new();
    let (provider, _) = pki.identity("did:ishare:EU.NL.NTRNL-10000003");
    let info = documented_payload(CAPABILITIES_PAYLOAD)["capabilities_info"].clone();
    let capabilities = Capabilities {
        capabilities_info: serde_json::from_value(info).unwrap(),
    };

    let token = provider
        .create_token_with_extra_claims(
            Some("did:ishare:EU.NL.NTRNL-10000001".to_owned()),
            &capabilities,
        )
        .unwrap();

    assert_eq!(
        decoded_claims(&token)["aud"],
        "did:ishare:EU.NL.NTRNL-10000001"
    );
}
