use anyhow::Context;
use openssl::x509::X509;

use super::{GetFirstX5CError, IshareError, ValidateTokenError};

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
        let cert = get_first_x5c(token)?;

        let public_key = self.cert.public_key().context("Error getting public key")?;

        if !cert
            .verify(&public_key)
            .context("Error verifying certificate with public key")?
        {
            return Ok(false);
        }

        return Ok(true);
    }
}

pub(crate) fn get_first_x5c(token: &str) -> Result<X509, GetFirstX5CError> {
    let header = jsonwebtoken::decode_header(&token).context("Error decoding header")?;

    let x5c = match header.x5c {
        Some(x5c) => x5c,
        None => return Err(GetFirstX5CError::MissingX5CHeader),
    };

    let cert = openssl::x509::X509::from_pem(
        format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----",
            x5c[0]
        )
        .as_bytes(),
    )
    .context("Error creating certificate from pem")?;

    return Ok(cert);
}
