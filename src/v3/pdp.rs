use super::delegation_evidence::{verify_delegation_evidence, DelegationEvidence};

use super::delegation_request::{build_simple_delegation_request, DelegationRequestContainer};
use crate::common::{DecodeTokenError, Identity, IshareClaimsWithExtra, IshareError};
use base64::prelude::*;

use jsonwebtoken::TokenData;
use reqwest::header::AUTHORIZATION;
use serde::Deserialize;

#[derive(Deserialize)]
pub struct LoginResponse {
    pub access_token: String,
    pub expires_in: i64,
}

#[derive(Deserialize)]
pub struct DelegationTokenResponse {
    #[serde(rename = "delegationToken")]
    delegation_token: String,
}

pub struct PDP<'a> {
    identity: &'a Identity,
    eori: String,
    url: String,
}

#[derive(Deserialize)]
struct DelegationTokenClaims {
    #[serde(rename = "delegationEvidence")]
    pub delegation_evidence: DelegationEvidence,
}

impl<'a> PDP<'a> {
    pub fn new(identity: &'a Identity, eori: String, url: String) -> PDP<'a> {
        return Self {
            identity,
            eori,
            url,
        };
    }

    pub async fn authorize(
        &self,
        access_token: &str,
        action: &str,
        access_subject: &str,
        policy_issuer: &str,
        resource_type: &str,
        identifiers: Option<Vec<String>>,
        attributes: Option<Vec<String>>,
    ) -> Result<bool, IshareError> {
        let delegation_request = self.create_delegation_request(
            action,
            access_subject,
            policy_issuer,
            resource_type,
            identifiers,
            attributes,
        );

        let delegation_token = self.call_pdp(access_token, &delegation_request).await?;

        return self
            .check_delegation_token(&delegation_token, resource_type)
            .map_err(|e| IshareError {
                message: format!("{:?}", e),
            });
    }

    fn check_delegation_token(
        &self,
        delegation_token: &str,
        resource_type: &str,
    ) -> Result<bool, DecodeTokenError> {
        let decoded: TokenData<IshareClaimsWithExtra<DelegationTokenClaims>> =
            self.identity
                .decode_token_custom_claims::<DelegationTokenClaims>(delegation_token, None)?;

        let de = decoded.claims.extra.delegation_evidence;

        let authorized = verify_delegation_evidence(&de, resource_type.to_string());

        return Ok(authorized);
    }

    async fn call_pdp(
        &self,
        access_token: &str,
        delegation_request: &DelegationRequestContainer,
    ) -> Result<String, IshareError> {
        let target_url = format!("{}/delegation", self.url);

        let response = reqwest::Client::new()
            .post(target_url)
            .header("Authorization", format!("Bearer {access_token}"))
            .json(delegation_request)
            .send()
            .await
            .map_err(|e| IshareError {
                message: e.to_string(),
            })?
            .error_for_status()
            .map_err(|e| IshareError {
                message: e.to_string(),
            })?
            .json::<DelegationTokenResponse>()
            .await
            .map_err(|e| IshareError {
                message: e.to_string(),
            })?;

        Ok(response.delegation_token)
    }

    fn create_delegation_request(
        &self,
        action: &str,
        access_subject: &str,
        policy_issuer: &str,
        resource_type: &str,
        identifiers: Option<Vec<String>>,
        attributes: Option<Vec<String>>,
    ) -> DelegationRequestContainer {
        let service_provider = self.identity.eori().to_owned();
        let actions = vec![action.to_string()];

        let delegation_request = build_simple_delegation_request(
            policy_issuer.to_string(),
            access_subject.to_string(),
            resource_type.to_string(),
            service_provider,
            actions,
            identifiers,
            attributes,
        );

        delegation_request
    }

    pub async fn connect_admin(
        &self,
        admin_username: &str,
        admin_password: &str,
        pdp_app_id: &str,
        pdp_app_secret: &str,
    ) -> Result<LoginResponse, IshareError> {
        let form_data = vec![
            ("grant_type", "password"),
            ("username", admin_username),
            ("password", admin_password),
        ];

        let target_url = format!("{}/oauth2/token", self.url);
        let basic_auth = base64::engine::general_purpose::STANDARD
            .encode(format!("{pdp_app_id}:{pdp_app_secret}"));

        let response = reqwest::Client::new()
            .post(target_url)
            .form(&form_data)
            .header(AUTHORIZATION, format!("Basic {basic_auth}"))
            .send()
            .await
            .map_err(|e| IshareError {
                message: e.to_string(),
            })?
            .error_for_status()
            .map_err(|e| IshareError {
                message: e.to_string(),
            })?
            .json::<LoginResponse>()
            .await
            .map_err(|e| IshareError {
                message: e.to_string(),
            })?;

        return Ok(response);
    }

    pub async fn connect(&self) -> Result<LoginResponse, IshareError> {
        let client_assertion = self.identity.create_client_assertion(self.eori.clone())?;

        let client_id = self.identity.eori().to_owned();

        let form_data = vec![
            ("grant_type", "client_credentials"),
            (
                "client_assertion_type",
                "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            ),
            ("scope", "iSHARE"),
            ("client_id", &client_id),
            ("client_assertion", &client_assertion),
        ];

        let target_url = format!("{}/connect/machine/token", self.url);

        let response = reqwest::Client::new()
            .post(target_url)
            .form(&form_data)
            .send()
            .await
            .map_err(|e| IshareError {
                message: e.to_string(),
            })?
            .error_for_status()
            .map_err(|e| IshareError {
                message: e.to_string(),
            })?
            .json::<LoginResponse>()
            .await
            .map_err(|e| IshareError {
                message: e.to_string(),
            })?;

        return Ok(response);
    }
}
