use http::Extensions;
use reqwest::{Request, Response};
use reqwest_middleware::{Middleware, Next};
use reqwest_retry::{Retryable, RetryableStrategy};
use serde::{Deserialize, Serialize};

mod identity;
mod trust;

pub use identity::Identity;
pub(crate) use trust::get_first_x5c;
pub use trust::TrustAnchor;

#[derive(Debug, Serialize, Deserialize)]
pub struct Account {
    pub roles: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ResourceAccess {
    pub account: Account,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IshareClaims {
    pub(crate) iss: String,
    pub sub: String,
    pub aud: String,
    pub(crate) jti: String,
    pub exp: u64,
    pub iat: u64,
    #[serde(skip_deserializing)]
    pub(crate) nbf: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IshareClaimsWithExtra<ExtraClaims> {
    #[serde(flatten)]
    pub ishare_claims: IshareClaims,

    #[serde(flatten)]
    pub extra: ExtraClaims,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RealmAccess {
    pub roles: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserinfoClaims {
    iss: String,
    pub sub: String,
    pub aud: String,
    pub realm_access: RealmAccess,
    pub company_id: String,
}

#[derive(Debug, Deserialize)]
pub struct LoginResponse {
    pub access_token: String,
    pub expires_in: i64,
}

#[derive(Debug, Clone)]
pub struct IshareError {
    pub message: String,
}

impl std::fmt::Display for IshareError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for IshareError {}

pub(crate) struct RetryOnError;
impl RetryableStrategy for RetryOnError {
    fn handle(&self, res: &reqwest_middleware::Result<reqwest::Response>) -> Option<Retryable> {
        match res {
            Ok(res) if res.status().is_server_error() => Some(Retryable::Transient),
            Ok(_res) => None,
            Err(_error) => Some(Retryable::Transient),
        }
    }
}

pub(crate) struct LoggingMiddleware;

#[async_trait::async_trait]
impl Middleware for LoggingMiddleware {
    async fn handle(
        &self,
        req: Request,
        extensions: &mut Extensions,
        next: Next<'_>,
    ) -> reqwest_middleware::Result<Response> {
        let res = next.run(req, extensions).await;

        match &res {
            Ok(res) if res.status().is_success() => {
                tracing::info!("Request finished: status [{}]", res.status())
            }
            Ok(res) => {
                tracing::error!("Request finished: status [{}]", res.status())
            }
            Err(err) => {
                tracing::error!("Request finished with error [{:?}]", err)
            }
        }

        res
    }
}

#[derive(Deserialize)]
struct OAuthError {
    error: Option<String>,
    error_description: Option<String>,
}

/// Turns a failed token request into an error carrying the status and the server's explanation.
pub(crate) async fn token_request_error(response: reqwest::Response) -> IshareError {
    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    let reason = match serde_json::from_str::<OAuthError>(&body) {
        Ok(OAuthError {
            error_description: Some(description),
            ..
        }) => description,
        Ok(OAuthError {
            error: Some(error), ..
        }) => error,
        _ => body,
    };
    IshareError {
        message: format!("token request returned {status}: {reason}"),
    }
}

/// Logs a warning when a registry response was not issued by the registry itself.
pub(crate) fn warn_on_unexpected_issuer(token: &str, iss: &str, registry_eori: &str) {
    if iss != registry_eori {
        tracing::warn!(
            "{token} was issued by {iss}, expected the participant registry {registry_eori}"
        );
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AllowedDataspaces {
    pub dataspace_ids: Vec<String>,
    pub required_agreement_types: Vec<String>,
}

#[derive(thiserror::Error, Debug)]
pub enum GetFirstX5CError {
    #[error("x5c is missing from header")]
    MissingX5CHeader,
    #[error(transparent)]
    Unexpected(#[from] anyhow::Error),
}

#[derive(thiserror::Error, Debug)]
pub enum ValidateTokenError {
    #[error(transparent)]
    GetFirstX5CError(#[from] GetFirstX5CError),
    #[error(transparent)]
    Unexpected(#[from] anyhow::Error),
}

#[derive(thiserror::Error, Debug)]
pub enum DecodeTokenError {
    #[error(transparent)]
    GetFirstX5CError(#[from] GetFirstX5CError),
    #[error(transparent)]
    Unexpected(#[from] anyhow::Error),
    #[error(transparent)]
    DecodingError(#[from] jsonwebtoken::errors::Error),
    #[error("typ is missing from header")]
    MissingTypHeader,
    #[error("typ should be 'JWT'")]
    InvalidTypeHeader,
    #[error("exp field is not iat + 30 seconds")]
    ExpNotIatPlus30,
    #[error("iss does not match client_id")]
    IssDoesntMatchClientId,
    #[error("sub does not match iss")]
    SubDoesNotMatchIss,
    #[error("serial number not found in x5c certificate")]
    SerialNotFound,
    #[error("serial does not match client id")]
    SerialDoesntMatchClientId,
    #[error("issued at is in the future")]
    IatAfterNow,
}

pub fn validate_request_arguments(
    grant_type: &str,
    client_assertion_type: &str,
    scope: &str,
) -> Result<(), String> {
    if grant_type != "client_credentials" {
        return Err("grant type should be 'client_credentials'".to_owned());
    }

    if client_assertion_type != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
        return Err("client assertion type should be 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'".to_owned());
    }

    if scope != "iSHARE" {
        return Err("scope should be iSHARE".to_owned());
    }

    return Ok(());
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_validate_request_arguments() {
        assert!(matches!(
            validate_request_arguments(
                "",
                "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                "iSHARE"
            ),
            Err(m) if m == "grant type should be 'client_credentials'"
        ));

        assert!(matches!(
            validate_request_arguments(
                "client_credentials",
                "",
                "iSHARE"
            ),
            Err(m) if m == "client assertion type should be 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'"
        ));

        assert!(matches!(
            validate_request_arguments(
                "client_credentials",
                "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                ""
            ),
            Err(m) if m == "scope should be iSHARE"
        ));
    }
}
