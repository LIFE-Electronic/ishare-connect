use anyhow::Context;
use jsonwebtoken::{decode, Algorithm, DecodingKey, TokenData, Validation};
use reqwest_middleware::ClientBuilder;
use reqwest_retry::{policies::ExponentialBackoff, RetryTransientMiddleware};
use serde::{Deserialize, Serialize};

use crate::common::{
    get_first_x5c, token_request_error, warn_on_unexpected_issuer, AllowedDataspaces, Identity,
    IshareClaims, IshareError, LoggingMiddleware, LoginResponse, RetryOnError, TrustAnchor,
    ValidateTokenError,
};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PartyResponse {
    party_token: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CapabilitiesResponse {
    capabilities_token: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PartiesResponse {
    parties_token: String,
}

#[derive(Deserialize)]
struct TrustedListResponse {
    // the OpenAPI model says trustedListToken, the documented example trusted_list_token
    #[serde(rename = "trustedListToken", alias = "trusted_list_token")]
    trusted_list_token: String,
}

/// The services a party offers, from its `GET /capabilities`.
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct CapabilitiesInfo {
    pub public_services: Vec<Service>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub restricted_services: Option<Vec<Service>>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Service {
    pub identifier: String,
    pub title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint_description: Option<String>,
    #[serde(rename = "endpointURL")]
    pub endpoint_url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_endpoint: Option<String>,
    pub status: String,
    pub service_type: String,
    pub version: ServiceVersion,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub methods: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_registry: Option<ServiceAuthRegistry>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ServiceVersion {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub complies_with_framework_versions: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub complies_with_dataspace_versions: Option<Vec<String>>,
    pub capability_version: String,
}

/// The authorisation registry that must be used for a service.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ServiceAuthRegistry {
    pub party_id: String,
    pub url: String,
}

/// The capabilities claim, for a party signing its own capabilities token with
/// [`Identity::create_token_with_extra_claims`](crate::Identity::create_token_with_extra_claims).
#[derive(Serialize, Deserialize, Debug)]
pub struct Capabilities {
    #[serde(rename = "capabilitiesInfo", alias = "capabilities_info")]
    pub capabilities_info: CapabilitiesInfo,
}

#[derive(Deserialize)]
struct CapabilitiesToken {
    iss: String,
    // the OpenAPI model says capabilitiesInfo, the documented examples capabilities_info
    #[serde(rename = "capabilitiesInfo", alias = "capabilities_info")]
    capabilities_info: CapabilitiesInfo,
}

/// Client for an iSHARE participant registry (satellite), acting as `identity`.
#[derive(Debug)]
pub struct ParticipantRegistry {
    identity: Identity,
    trust_anchor: Option<TrustAnchor>,
    url: String,
    eori: String,
    allowed_dataspaces: Option<AllowedDataspaces>,
}

impl ParticipantRegistry {
    pub fn new(
        identity: Identity,
        trust_anchor: Option<TrustAnchor>,
        url: String,
        eori: String,
        allowed_dataspaces: Option<AllowedDataspaces>,
    ) -> Self {
        Self {
            identity,
            trust_anchor,
            url,
            eori,
            allowed_dataspaces,
        }
    }

    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    pub fn trust_anchor(&self) -> Option<&TrustAnchor> {
        self.trust_anchor.as_ref()
    }

    pub fn eori(&self) -> &str {
        &self.eori
    }

    fn validate_token(&self, token: &String) -> Result<bool, ValidateTokenError> {
        self.trust_anchor
            .as_ref()
            .context("Error dereferencing ishare_cert")?
            .validate_token(token)
    }

    #[tracing::instrument(skip(client_assertion))]
    pub async fn get_satellite_access_token(
        &self,
        client_assertion: &str,
    ) -> Result<LoginResponse, IshareError> {
        let form_data = vec![
            ("grant_type", "client_credentials"),
            (
                "client_assertion_type",
                "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            ),
            ("scope", "iSHARE"),
            ("client_id", self.identity.eori()),
            ("client_assertion", client_assertion),
        ];

        let retry_policy = ExponentialBackoff::builder().build_with_max_retries(5);
        let ret_s =
            RetryTransientMiddleware::new_with_policy_and_strategy(retry_policy, RetryOnError);

        let client = ClientBuilder::new(reqwest::Client::new())
            .with(ret_s)
            .with(LoggingMiddleware)
            .build();

        let response = client
            .post(format!("{}/connect/token", self.url))
            .form(&form_data)
            .send()
            .await
            .map_err(|e| IshareError {
                message: e.to_string(),
            })?;

        if !response.status().is_success() {
            return Err(token_request_error(response).await);
        }

        let bytes = response.bytes().await.unwrap();
        let body = serde_json::from_slice::<LoginResponse>(&bytes).map_err(|e| IshareError {
            message: e.to_string(),
        })?;

        return Ok(body);
    }

    pub async fn get_all_parties(
        &self,
        satellite_access_token: &str,
        query: &PartiesQuery,
    ) -> anyhow::Result<PartiesInfo> {
        let mut url = url::Url::parse(&format!("{}/parties", self.url))?;

        {
            let mut pairs = url.query_pairs_mut();
            if let Some(id) = &query.id {
                pairs.append_pair("id", id);
            }
            if let Some(also_known_as) = &query.also_known_as {
                pairs.append_pair("alsoKnownAs", also_known_as);
            }
            if let Some(name) = &query.name {
                pairs.append_pair("name", name);
            }
            for (property, value) in &query.claim_filter {
                pairs.append_pair(&format!("claimFilter[{property}]"), value);
            }
            if let Some(page) = query.page {
                pairs.append_pair("page", &page.to_string());
            }
            if let Some(page_size) = query.page_size {
                pairs.append_pair("pageSize", &page_size.to_string());
            }
        }

        let formatted_url = url.to_string();

        let response = reqwest::Client::new()
            .get(&formatted_url)
            .header(
                "Authorization",
                format!("Bearer {}", &satellite_access_token),
            )
            .send()
            .await
            .context(format!("Error fetching parties at {}", &formatted_url))?;

        let json = response
            .json::<PartiesResponse>()
            .await
            .context("Error deserializing response from parties endpoint")?;

        if !(self
            .validate_token(&json.parties_token)
            .context("Error validating parties token")?)
        {
            return Err(anyhow::anyhow!("Party token is invalid"));
        }

        let mut validation = Validation::new(Algorithm::RS256);

        let first_x5c =
            get_first_x5c(&json.parties_token).context("Error retrieving x5c from party token")?;

        validation.set_audience(&[self.identity.eori()]);
        let decoding_key =
            &DecodingKey::from_rsa_pem(&first_x5c.to_pem().context("Error converting x5c to pem")?)
                .context("Error creating decoding key from rsa pem")?;

        validation.set_audience(&[self.identity.eori()]);

        let decoded = decode::<PartiesToken>(&json.parties_token, &decoding_key, &validation)
            .context("Error decoding party token".to_owned())?;
        warn_on_unexpected_issuer("partiesToken", &decoded.claims.iss, &self.eori);

        return Ok(decoded.claims.parties_info);
    }

    /// Fetches the registry's trusted list: fingerprints and status of the CAs it trusts.
    pub async fn get_trusted_list(
        &self,
        satellite_access_token: &str,
    ) -> anyhow::Result<Vec<TrustedListEntry>> {
        let url = format!("{}/trustedList", self.url);

        let response = reqwest::Client::new()
            .get(&url)
            .header(
                "Authorization",
                format!("Bearer {}", &satellite_access_token),
            )
            .send()
            .await
            .context(format!("Error fetching trusted list at {}", &url))?;

        let json = response
            .json::<TrustedListResponse>()
            .await
            .context("Error deserializing response from trusted list endpoint")?;

        if !(self
            .validate_token(&json.trusted_list_token)
            .context("Error validating trusted list token")?)
        {
            return Err(anyhow::anyhow!("Trusted list token is invalid"));
        }

        let mut validation = Validation::new(Algorithm::RS256);

        let first_x5c = get_first_x5c(&json.trusted_list_token)
            .context("Error retrieving x5c from trusted list token")?;

        validation.set_audience(&[self.identity.eori()]);
        let decoding_key =
            &DecodingKey::from_rsa_pem(&first_x5c.to_pem().context("Error converting x5c to pem")?)
                .context("Error creating decoding key from rsa pem")?;

        let decoded =
            decode::<TrustedListToken>(&json.trusted_list_token, &decoding_key, &validation)
                .context("Error decoding trusted list token")?;
        warn_on_unexpected_issuer("trustedListToken", &decoded.claims.iss, &self.eori);

        return Ok(decoded.claims.trusted_list);
    }

    /// Fetches and verifies a single party from `GET /parties/{party_id}`.
    pub async fn get_party(
        &self,
        party_id: &str,
        satellite_access_token: &str,
    ) -> anyhow::Result<Party> {
        self.fetch_party(party_id, satellite_access_token)
            .await?
            .ok_or_else(|| anyhow::anyhow!("The ishare party {party_id} does not seem to exist"))
    }

    /// Fetches and verifies a party token; `None` when the registry returns an empty party.
    async fn fetch_party(
        &self,
        party_id: &str,
        satellite_access_token: &str,
    ) -> anyhow::Result<Option<Party>> {
        let encoded_party_token = self
            .parties(party_id, satellite_access_token)
            .await
            .context("Error fetching ishare parties information")?;

        if !(self
            .validate_token(&encoded_party_token)
            .context("Error validating party token")?)
        {
            return Err(anyhow::anyhow!("Party token is invalid"));
        }

        let mut validation = Validation::new(Algorithm::RS256);

        let first_x5c =
            get_first_x5c(&encoded_party_token).context("Error retrieving x5c from party token")?;

        validation.set_audience(&[self.identity.eori()]);
        let decoding_key =
            &DecodingKey::from_rsa_pem(&first_x5c.to_pem().context("Error converting x5c to pem")?)
                .context("Error creating decoding key from rsa pem")?;

        let decoded = decode::<PartyInfoToken>(&encoded_party_token, &decoding_key, &validation)
            .context("Error decoding party token")?;
        warn_on_unexpected_issuer("partyToken", &decoded.claims.iss, &self.eori);

        Ok(match decoded.claims.party_info {
            PartyInfoOption::Party(party) => Some(party),
            PartyInfoOption::Empty {} => None,
        })
    }

    pub async fn parties(
        &self,
        caller_client_id: &str,
        satellite_access_token: &str,
    ) -> anyhow::Result<String> {
        let url = format!("{}/parties/{}", self.url, caller_client_id);

        tracing::info!("retrieving iSHARE parties at: {}", url);

        let response = reqwest::Client::new()
            .get(&url)
            .header(
                "Authorization",
                format!("Bearer {}", &satellite_access_token),
            )
            .send()
            .await
            .context(format!("Error fetching parties at {}", &url))?;

        let json = response
            .json::<PartyResponse>()
            .await
            .context("Error deserializing response from parties endpoint")?;

        return Ok(json.party_token);
    }

    pub async fn get_public_capabilities(&self, url: &str) -> anyhow::Result<CapabilitiesInfo> {
        let response = reqwest::get(url)
            .await
            .context(format!("Error retrieving capabilities at: {}", url))?;

        let json = response
            .json::<CapabilitiesResponse>()
            .await
            .context("Error deserializing response from capabilities endpoint")?;

        if !(self
            .validate_token(&json.capabilities_token)
            .context("Error validating capabilities token")?)
        {
            return Err(anyhow::anyhow!("Capabilities token is not valid"));
        }

        let mut validation = Validation::new(Algorithm::RS256);

        let first_x5c = get_first_x5c(&json.capabilities_token)
            .context("Error retrieving x5c from capabilities token")?;

        validation.set_audience(&[self.identity.eori()]);
        let decoding_key =
            &DecodingKey::from_rsa_pem(&first_x5c.to_pem().context("Error converting x5c to pem")?)
                .context("Error creating decoding key from rsa pem")?;

        validation.set_audience(&[self.identity.eori()]);

        let decoded =
            decode::<CapabilitiesToken>(&json.capabilities_token, &decoding_key, &validation)
                .context("Error decoding capabilities token")?;
        warn_on_unexpected_issuer("capabilitiesToken", &decoded.claims.iss, &self.eori);

        return Ok(decoded.claims.capabilities_info);
    }

    pub fn validate_party_certificate(
        &self,
        client_assertion_token: &TokenData<IshareClaims>,
        party: &Party,
    ) -> anyhow::Result<bool> {
        let client_cert = match client_assertion_token.header.x5c.clone() {
            Some(x) => x[0].clone(),
            None => return Err(anyhow::anyhow!("missing x5c header")),
        };

        Ok(party.claims.iter().any(|claim| {
            claim.claim_type == "x509Certificate"
                && claim.attribute("x5c") == Some(client_cert.as_str())
        }))
    }

    // checks if the party is an active member of any of the allowed dataspaces and has
    // all the required agreement types for that dataspace
    // currently does not check if the membership or agreement is still valid
    pub fn dataspace_agreement_exists(&self, party: &Party) -> bool {
        tracing::info!("checking if party is part of allowed dataspaces");
        let allowed_dataspaces = match &self.allowed_dataspaces {
            Some(ad) => ad,
            None => {
                tracing::info!("skip checking. allowed dataspace option was not used");
                return true;
            }
        };

        for dataspace in &allowed_dataspaces.dataspace_ids {
            tracing::info!(
                "checking membership and agreements for dataspace: {}",
                dataspace
            );
            let is_member = party.claims.iter().any(|claim| {
                claim.claim_type == "dataspaceMembership"
                    && claim.status == "active"
                    && claim.attribute("dataspaceId") == Some(dataspace.as_str())
            });

            let agreements_present =
                allowed_dataspaces
                    .required_agreement_types
                    .iter()
                    .all(|agreement_type| {
                        party.claims.iter().any(|claim| {
                            claim.claim_type == "dataspaceAgreement"
                                && claim.attribute("agreementType") == Some(agreement_type.as_str())
                                && claim.attribute("dataspaceId") == Some(dataspace.as_str())
                        })
                    });

            if is_member && agreements_present {
                return true;
            }
        }

        false
    }

    pub async fn validate_party(
        &self,
        now: chrono::DateTime<chrono::Utc>,
        client_id: &str,
        satellite_access_token: &str,
    ) -> Result<Party, ValidatePartyError> {
        let party = match self.fetch_party(client_id, satellite_access_token).await? {
            Some(party) => party,
            None => return Err(ValidatePartyError::NotFound(client_id.to_owned())),
        };

        let compliance = match party
            .claims
            .iter()
            .find(|claim| claim.claim_type == "frameworkCompliance" && claim.status == "active")
        {
            Some(compliance) => compliance,
            None => return Err(ValidatePartyError::Inactive(client_id.to_owned())),
        };

        if !self.dataspace_agreement_exists(&party) {
            return Err(ValidatePartyError::DataspaceMembershipNotFound(
                self.allowed_dataspaces
                    .clone()
                    .expect("dataspace check should not fail if self.allowed_dataspaces is none")
                    .dataspace_ids
                    .join(", "),
            ));
        }

        if let Some(end_date) = &compliance.end_date {
            let end_date = chrono::DateTime::parse_from_rfc3339(end_date).context(format!(
                "Error parsing framework compliance end date {end_date}"
            ))?;

            if now > end_date {
                tracing::warn!("end_date of framework compliance is expired");
            }
        }

        Ok(party)
    }
}

#[derive(thiserror::Error, Debug)]
pub enum ValidatePartyError {
    #[error(transparent)]
    Unexpected(#[from] anyhow::Error),
    #[error("The ishare party {0} is currently not active")]
    Inactive(String),
    #[error("The ishare party {0} does not seem to exist")]
    NotFound(String),
    #[error("no active membership with the required agreements found for dataspaces: {0}")]
    DataspaceMembershipNotFound(String),
}

/// Filters and paging for `GET /parties`; empty fields are left out of the request.
#[derive(Debug, Default, Clone)]
pub struct PartiesQuery {
    pub id: Option<String>,
    pub also_known_as: Option<String>,
    /// May contain a single `*` wildcard.
    pub name: Option<String>,
    /// `(<claimType>.<propertyName>, value)` pairs, all of which must match.
    pub claim_filter: Vec<(String, String)>,
    /// Starts at 1.
    pub page: Option<u32>,
    /// At most 100.
    pub page_size: Option<u32>,
}

/// A page of parties from `GET /parties`.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PartiesInfo {
    pub current_page: u32,
    pub page_size: u32,
    pub total_pages: u32,
    pub total_count: u32,
    pub count: u32,
    pub data: Vec<Party>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Party {
    pub id: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub also_known_as: Option<Vec<String>>,
    pub claims: Vec<Claim>,
}

/// A registered claim; the attributes beyond the common ones depend on `claim_type`.
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Claim {
    pub id: String,
    #[serde(rename = "type")]
    pub claim_type: String,
    pub status: String,
    pub registrar_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_date: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_date: Option<String>,
    #[serde(flatten)]
    pub attributes: serde_json::Map<String, serde_json::Value>,
}

impl Claim {
    /// A type-specific string attribute, e.g. `dataspaceId` or `x5c`.
    pub fn attribute(&self, name: &str) -> Option<&str> {
        self.attributes
            .get(name)
            .and_then(serde_json::Value::as_str)
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PartiesToken {
    iss: String,
    sub: String,
    aud: String,
    jti: String,
    exp: u64,
    iat: u64,
    parties_info: PartiesInfo,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct TrustedListEntry {
    pub subject: String,
    pub certificate_fingerprint: String,
    pub validity: String,
    pub status: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TrustedListToken {
    iss: String,
    sub: String,
    aud: String,
    jti: String,
    exp: u64,
    iat: u64,
    trusted_list: Vec<TrustedListEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PartyInfoToken {
    iss: String,
    sub: String,
    aud: String,
    jti: String,
    exp: u64,
    iat: u64,
    party_info: PartyInfoOption,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
enum PartyInfoOption {
    Party(Party),
    Empty {},
}
