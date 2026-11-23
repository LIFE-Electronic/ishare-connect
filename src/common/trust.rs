use anyhow::Context;
use openssl::x509::X509;

use super::{GetFirstX5CError, IshareError, ValidateTokenError, VerifyTokenError};

/// The CA certificate that x5c chains of received tokens must be signed by.
#[derive(Debug, Clone)]
pub struct TrustAnchor {
    cert: X509,
}

impl TrustAnchor {
    pub fn from_pem_file(path: &str) -> Result<Self, IshareError> {
        let content = std::fs::read(path).map_err(|e| IshareError {
            message: e.to_string(),
        })?;

        let cert = X509::from_pem(&content).map_err(|e| IshareError {
            message: e.to_string(),
        })?;

        Ok(Self { cert })
    }

    pub fn validate_token(&self, token: &String) -> Result<bool, ValidateTokenError> {
        match self.verify_token(token) {
            Ok(()) => Ok(true),
            Err(VerifyTokenError::UntrustedCertificate) => Ok(false),
            Err(VerifyTokenError::GetFirstX5CError(error)) => Err(error.into()),
            Err(VerifyTokenError::Unexpected(error)) => Err(error.into()),
        }
    }

    /// Verifies the signing certificate against this trust anchor, returning a typed
    /// rejection instead of `false`. JWT signature and claims are checked separately
    /// by `Identity::decode_token`.
    pub fn verify_token(&self, token: &str) -> Result<(), VerifyTokenError> {
        let cert = get_first_x5c(token)?;

        let public_key = self.cert.public_key().context("Error getting public key")?;

        if !cert
            .verify(&public_key)
            .context("Error verifying certificate with public key")?
        {
            return Err(VerifyTokenError::UntrustedCertificate);
        }

        Ok(())
    }
}

pub(crate) fn get_first_x5c(token: &str) -> Result<X509, GetFirstX5CError> {
    let header = jsonwebtoken::decode_header(&token).context("Error decoding header")?;

    let x5c = match header.x5c {
        Some(x5c) => x5c,
        None => return Err(GetFirstX5CError::MissingX5CHeader),
    };

    let certificate = x5c.first().ok_or(GetFirstX5CError::MissingX5CHeader)?;
    let cert = openssl::x509::X509::from_pem(
        format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----",
            certificate
        )
        .as_bytes(),
    )
    .context("Error creating certificate from pem")?;

    return Ok(cert);
}
