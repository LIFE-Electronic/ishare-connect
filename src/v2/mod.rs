pub mod delegation_evidence;
pub mod delegation_request;
pub mod pdp;

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
struct PartyResponse {
    party_token: String,
}

#[derive(Deserialize)]
struct CapabilitiesResponse {
    capabilities_token: String,
}

#[derive(Deserialize)]
struct PartiesResponse {
    parties_token: String,
}

#[derive(Deserialize)]
struct TrustedListResponse {
    trusted_list_token: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SupportedVersion {
    pub version: String,
    pub supported_features: Vec<SupportedFeatures>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SupportedFeature {
    pub id: String,
    pub feature: String,
    pub url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_endpoint: Option<String>,
    pub description: String,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub enum SupportedFeatures {
    Public(Vec<SupportedFeature>),
    Restricted(Vec<SupportedFeature>),
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Role {
    pub role: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CapabilitiesInfo {
    pub party_id: String,
    pub ishare_roles: Vec<Role>,
    pub supported_versions: Vec<SupportedVersion>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Capabilities {
    pub capabilities_info: CapabilitiesInfo,
}

#[derive(Deserialize)]
struct CapabilitiesClaims {
    iss: String,
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
        role: Option<&str>,
        active_only: Option<bool>,
    ) -> anyhow::Result<PartiesInfo> {
        let mut url = url::Url::parse(&format!("{}/parties", self.url))?;

        if let Some(role) = role {
            url.query_pairs_mut().append_pair("role", role);
        }

        if let Some(active_only) = active_only {
            url.query_pairs_mut()
                .append_pair("active_only", &active_only.to_string());
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
        warn_on_unexpected_issuer("parties_token", &decoded.claims.iss, &self.eori);

        return Ok(decoded.claims.parties_info);
    }

    /// Fetches the registry's trusted list: fingerprints and status of the CAs it trusts.
    pub async fn get_trusted_list(
        &self,
        satellite_access_token: &str,
    ) -> anyhow::Result<Vec<TrustedListEntry>> {
        let url = format!("{}/trusted_list", self.url);

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
        warn_on_unexpected_issuer("trusted_list_token", &decoded.claims.iss, &self.eori);

        return Ok(decoded.claims.trusted_list);
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
            .context("Error deserializing response from parties endpoint")?;

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
            decode::<CapabilitiesClaims>(&json.capabilities_token, &decoding_key, &validation)
                .unwrap();
        warn_on_unexpected_issuer("capabilities_token", &decoded.claims.iss, &self.eori);

        return Ok(decoded.claims.capabilities_info);
    }

    pub fn validate_party_certificate(
        &self,
        client_assertion_token: &TokenData<IshareClaims>,
        party_info: &PartyInfo,
    ) -> anyhow::Result<bool> {
        let client_cert = match client_assertion_token.header.x5c.clone() {
            Some(x) => x[0].clone(),
            None => return Err(anyhow::anyhow!("missing x5c header")),
        };

        let certificates = match &party_info.certificates_or_spor {
            CertificatesOrSpor::Spor(_) => {
                return Err(anyhow::anyhow!(
                    "cannot validate party certificate for SPOR"
                ))
            }
            CertificatesOrSpor::Certificates(cert) => cert,
        };

        if !certificates.iter().any(|c| &c.x5c == &client_cert) {
            return Ok(false);
        }

        return Ok(true);
    }

    // checks if any agreement of the party matches all the agreement types of
    // any of the allowed dataspaces
    // currently does not check if the agreement is still valid
    pub fn dataspace_agreement_exists(&self, party_info: &PartyInfo) -> bool {
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
                "checking if agreements are present for dataspace: {}",
                dataspace
            );
            let agreements_present =
                allowed_dataspaces
                    .required_agreement_types
                    .iter()
                    .all(|agreement_type| {
                        party_info.agreements.iter().any(|party_info_agreement| {
                            agreement_type == &party_info_agreement.r#type
                                && &party_info_agreement.dataspace_id == dataspace
                        })
                    });

            if agreements_present {
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
    ) -> Result<PartyInfo, ValidatePartyError> {
        let encoded_party_token = self
            .parties(client_id, satellite_access_token)
            .await
            .context("Error fetching ishare parties information")?;

        if !(self
            .validate_token(&encoded_party_token)
            .context("Error validating parties token")?)
        {
            return Err(ValidatePartyError::Unexpected(anyhow::anyhow!(
                "Party token is invalid"
            )));
        }

        let mut validation = Validation::new(Algorithm::RS256);

        let first_x5c =
            get_first_x5c(&encoded_party_token).context("Error retrieving x5c from party token")?;

        validation.set_audience(&[self.identity.eori()]);
        let decoding_key =
            &DecodingKey::from_rsa_pem(&first_x5c.to_pem().context("Error converting x5c to pem")?)
                .context("Error creating decoding key from rsa pem")?;

        validation.set_audience(&[self.identity.eori()]);

        let decoded = decode::<PartyToken>(&encoded_party_token, &decoding_key, &validation)
            .context("Error decoding party token".to_owned())?;
        warn_on_unexpected_issuer("party_token", &decoded.claims.iss, &self.eori);

        match decoded.claims.party_info {
            PartyInfoOption::Empty {} => Err(ValidatePartyError::NotFound(client_id.to_owned())),
            PartyInfoOption::PartyInfo(party_info) if party_info.adherence.status != "Active" => {
                Err(ValidatePartyError::Inactive(client_id.to_owned()))
            }
            PartyInfoOption::PartyInfo(party_info)
                if !self.dataspace_agreement_exists(&party_info) =>
            {
                Err(ValidatePartyError::DataspaceAgreementNotFound(
                    self.allowed_dataspaces
                        .clone()
                        .expect(
                            "dataspace check should not fail if self.allowed_dataspaces is none",
                        )
                        .dataspace_ids
                        .join(", "),
                ))
            }
            PartyInfoOption::PartyInfo(party_info) => {
                let end_date = chrono::DateTime::parse_from_rfc3339(&party_info.adherence.end_date)
                    .context(format!(
                        "Error parsing adherence end date {}",
                        &party_info.adherence.end_date
                    ))?;

                if now > end_date {
                    tracing::warn!("end_date of adherence is expired");
                }

                Ok(party_info)
            }
        }
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
    #[error("adherence is not active anymore")]
    AdherenceExpired,
    #[error("no matching agreement found for dataspaces: {0}")]
    DataspaceAgreementNotFound(String),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Adherence {
    pub status: String,
    pub end_date: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Certificate {
    pub x5c: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]

pub struct Spor {
    signed_request: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum CertificatesOrSpor {
    Certificates(Vec<Certificate>),
    Spor(Spor),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Agreement {
    dataspace_id: String,
    #[serde(rename = "type")]
    r#type: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PartyInfo {
    pub adherence: Adherence,
    pub party_id: String,
    pub party_name: String,
    #[serde(flatten)]
    pub certificates_or_spor: CertificatesOrSpor,
    pub capability_url: String,
    pub agreements: Vec<Agreement>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
enum PartyInfoOption {
    PartyInfo(PartyInfo),
    Empty {},
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PartyToken {
    iss: String,
    sub: String,
    aud: String,
    jti: String,
    exp: u64,
    iat: u64,
    nbf: u64,
    party_info: PartyInfoOption,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PartiesInfo {
    pub data: Vec<PartyInfo>,
    pub count: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PartiesToken {
    iss: String,
    sub: String,
    aud: String,
    jti: String,
    exp: u64,
    iat: u64,
    nbf: u64,
    parties_info: PartiesInfo,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TrustedListEntry {
    pub subject: String,
    pub certificate_fingerprint: String,
    pub validity: String,
    pub status: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TrustedListToken {
    iss: String,
    sub: String,
    aud: String,
    jti: String,
    exp: u64,
    iat: u64,
    nbf: u64,
    trusted_list: Vec<TrustedListEntry>,
}
