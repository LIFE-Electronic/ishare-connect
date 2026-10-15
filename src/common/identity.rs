use anyhow::Context;
use core::str;
use josekit::{
    jwe::{self, JweHeader, RSA_OAEP_256},
    jws::{alg::rsassa::RsassaJwsAlgorithm, JwsHeader},
    jwt::{encode_with_signer, JwtPayload},
};
use jsonwebtoken::{
    decode, encode, Algorithm, DecodingKey, EncodingKey, Header, TokenData, Validation,
};
use openssl::{
    pkcs12::ParsedPkcs12_2,
    pkey::{PKey, Private},
};
use serde::{de::DeserializeOwned, Serialize};
use serde_json::Value;
use std::{collections::HashMap, time::UNIX_EPOCH};

use super::{get_first_x5c, DecodeTokenError, IshareClaims, IshareClaimsWithExtra, IshareError};

#[derive(Serialize)]
struct TokenClaims<'a, T> {
    iss: &'a str,
    sub: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    aud: Option<String>,
    jti: String,
    iat: u64,
    nbf: u64,
    exp: u64,
    #[serde(flatten)]
    extra: T,
}

/// Our own iSHARE party: EORI plus the key and certificate chain from its `.p12`.
pub struct Identity {
    client_cert: ParsedPkcs12_2,
    eori: String,
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Identity")
            .field("eori", &self.eori)
            .finish_non_exhaustive()
    }
}

fn parse_private_key(pkey: &PKey<Private>) -> Result<String, IshareError> {
    let private_key =
        String::from_utf8(pkey.private_key_to_pem_pkcs8().map_err(|e| IshareError {
            message: e.to_string(),
        })?)
        .map_err(|e| IshareError {
            message: e.to_string(),
        })?;

    let mut result = "".to_owned();
    let splitted: Vec<&str> = private_key.split('\n').collect();

    for (idx, part) in splitted.iter().enumerate() {
        if idx == splitted.len() - 2 {
            result += "\n";
        }
        result += part;
        if idx == 0 {
            result += "\n";
        }
    }

    return Ok(result.to_owned());
}

fn parse_certificate(pem: Vec<u8>) -> Result<String, IshareError> {
    let certificate = String::from_utf8(pem)
        .map_err(|e| IshareError {
            message: e.to_string(),
        })?
        .replace("-----BEGIN CERTIFICATE-----\n", "")
        .replace("-----END CERTIFICATE-----", "")
        .replace("\n", "");

    Ok(certificate)
}

impl Identity {
    pub fn from_p12(path: &str, pass: &str, eori: &str) -> Result<Self, IshareError> {
        let _provider =
            openssl::provider::Provider::try_load(None, "legacy", true).map_err(|e| {
                IshareError {
                    message: e.to_string(),
                }
            })?;

        let client_cert_content = std::fs::read(path).map_err(|e| IshareError {
            message: format!("could not read {path}: {e}"),
        })?;
        let pkcs12 =
            openssl::pkcs12::Pkcs12::from_der(&client_cert_content).map_err(|e| IshareError {
                message: e.to_string(),
            })?;
        let client_cert = pkcs12.parse2(pass).map_err(|e| IshareError {
            message: e.to_string(),
        })?;

        Ok(Self {
            client_cert,
            eori: eori.to_owned(),
        })
    }

    pub fn eori(&self) -> &str {
        &self.eori
    }

    fn create_ishare_header(&self) -> Result<Header, IshareError> {
        let cert = self.client_cert.cert.as_ref().unwrap();

        let mut certs = vec![parse_certificate(cert.to_pem().map_err(|e| {
            IshareError {
                message: e.to_string(),
            }
        })?)?];

        for ca in self
            .client_cert
            .ca
            .as_ref()
            .ok_or({
                IshareError {
                    message: "Unexpected error".to_owned(),
                }
            })?
            .iter()
        {
            certs.push(parse_certificate(ca.to_pem().map_err(|e| {
                IshareError {
                    message: e.to_string(),
                }
            })?)?);
        }

        let header = Header {
            typ: Some("JWT".to_owned()),
            x5c: Some(certs),
            alg: Algorithm::RS256,
            ..Default::default()
        };

        return Ok(header);
    }

    fn get_encoding_key(&self) -> Result<EncodingKey, IshareError> {
        let private_key =
            parse_private_key(self.client_cert.pkey.as_ref().ok_or(IshareError {
                message: "unable to find client certificate".to_owned(),
            })?)?;

        let encoding_key = EncodingKey::from_rsa_pem(private_key.as_bytes()).unwrap();

        return Ok(encoding_key);
    }

    fn create_ishare_claims(
        &self,
        target_id: String,
        client_id: &String,
    ) -> Result<IshareClaims, IshareError> {
        let iat = std::time::SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| IshareError {
                message: e.to_string(),
            })?
            .as_secs();

        let claims = IshareClaims {
            iss: client_id.clone(),
            aud: target_id.to_owned(),
            sub: client_id.clone(),
            iat,
            nbf: iat,
            exp: iat + 30,
            jti: uuid::Uuid::new_v4().to_string(),
        };

        return Ok(claims);
    }

    pub fn create_client_assertion(&self, target_id: String) -> Result<String, IshareError> {
        let header = self.create_ishare_header()?;
        let claims = self.create_ishare_claims(target_id, &self.eori)?;
        let encoding_key = self.get_encoding_key()?;
        let token = encode(&header, &claims, &encoding_key).unwrap();

        return Ok(token);
    }

    /// Signs an iSHARE JWT issued by this party carrying `extra_claims`, e.g. a capabilities
    /// token. `aud` is left out when there is no audience, as for unauthenticated requests.
    pub fn create_token_with_extra_claims<T: Serialize>(
        &self,
        audience: Option<String>,
        extra_claims: T,
    ) -> Result<String, IshareError> {
        let header = self.create_ishare_header()?;
        let encoding_key = self.get_encoding_key()?;
        let iat = std::time::SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| IshareError {
                message: e.to_string(),
            })?
            .as_secs();

        let claims = TokenClaims {
            iss: &self.eori,
            sub: &self.eori,
            aud: audience,
            jti: uuid::Uuid::new_v4().to_string(),
            iat,
            nbf: iat,
            exp: iat + 30,
            extra: extra_claims,
        };

        encode(&header, &claims, &encoding_key).map_err(|e| IshareError {
            message: e.to_string(),
        })
    }

    pub fn create_client_assertion_with_extra_claims<T: Serialize>(
        &self,
        target_id: String,
        extra_claims: T,
    ) -> Result<String, IshareError> {
        let header = self.create_ishare_header()?;
        let ishare_claims = self.create_ishare_claims(target_id, &self.eori)?;
        let encoding_key = self.get_encoding_key()?;

        let claims = IshareClaimsWithExtra {
            ishare_claims,

            extra: extra_claims,
        };

        let token = encode(&header, &claims, &encoding_key).unwrap();

        return Ok(token);
    }

    /// Signs the assertion, then encrypts it for the recipient whose certificate is `recipient_x5c`.
    pub fn create_client_assertion_with_extra_claims_encrypted<T: Serialize>(
        &self,
        target_id: String,
        extra_claims: T,
        recipient_x5c: &str,
    ) -> Result<String, IshareError> {
        let header = self.create_ishare_header()?;
        let ishare_claims = self.create_ishare_claims(target_id, &self.eori)?;

        let claims = IshareClaimsWithExtra {
            ishare_claims,
            extra: extra_claims,
        };

        let header_str = serde_json::to_string(&header).map_err(|e| IshareError {
            message: e.to_string(),
        })?;
        let claims_str = serde_json::to_string(&claims).map_err(|e| IshareError {
            message: e.to_string(),
        })?;

        let header_map: HashMap<&str, Value> =
            serde_json::from_str(&header_str).map_err(|e| IshareError {
                message: e.to_string(),
            })?;
        let claims_map: HashMap<&str, Value> =
            serde_json::from_str(&claims_str).map_err(|e| IshareError {
                message: e.to_string(),
            })?;

        let mut jws_header = JwsHeader::new();
        for claim in header_map {
            let _ = jws_header.set_claim(claim.0, Some(claim.1.clone()));
        }

        let mut jwt_payload = JwtPayload::new();
        for claim in claims_map {
            let _ = jwt_payload.set_claim(claim.0, Some(claim.1.clone()));
        }

        // create the JWT
        let private_key =
            parse_private_key(self.client_cert.pkey.as_ref().ok_or(IshareError {
                message: "unable to find client certificate".to_owned(),
            })?)?;

        let signer = RsassaJwsAlgorithm::Rs256
            .signer_from_pem(&private_key)
            .unwrap();
        let jws_payload = encode_with_signer(&jwt_payload, &jws_header, &signer).unwrap();

        // encrypt the JWS payload
        let cert = openssl::x509::X509::from_pem(
            format!(
                "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----",
                recipient_x5c
            )
            .as_bytes(),
        )
        .map_err(|e| IshareError {
            message: e.to_string(),
        })?;

        let public_key = cert.public_key().map_err(|e| IshareError {
            message: e.to_string(),
        })?;
        let pkey_bytes = public_key.public_key_to_pem().map_err(|e| IshareError {
            message: e.to_string(),
        })?;

        let encrypter = RSA_OAEP_256
            .encrypter_from_pem(&pkey_bytes)
            .map_err(|e| IshareError {
                message: e.to_string(),
            })?;

        let mut jwe_header = JweHeader::new();

        jwe_header.set_content_encryption("A128CBC-HS256");
        jwe_header.set_content_type("JWT");

        let jwe_compact = jwe::serialize_compact(
            jws_payload.as_bytes(), // encrypt the *entire* signed JWT string
            &jwe_header,
            &encrypter,
        )
        .unwrap();

        return Ok(jwe_compact);
    }

    pub fn decode_token(
        &self,
        now: chrono::DateTime<chrono::Utc>,
        token: &str,
        client_id: &str,
        audience: Option<&str>,
    ) -> Result<TokenData<IshareClaims>, DecodeTokenError> {
        let mut validation = Validation::new(Algorithm::RS256);

        let audience = match audience {
            None => &self.eori,
            Some(aud) => aud,
        };

        validation.set_audience(&[audience]);
        let first_x5c = get_first_x5c(token)?;
        let decoding_key =
            &DecodingKey::from_rsa_pem(&first_x5c.to_pem().context("Error converting x5c to pem")?)
                .context("Error creating decoding key from rsa pem")?;

        let decoded = decode::<IshareClaims>(&token, decoding_key, &validation)?;

        match decoded.header.typ {
            None => return Err(DecodeTokenError::MissingTypHeader),
            Some(t) if t != "JWT" => return Err(DecodeTokenError::InvalidTypeHeader),
            Some(_) => {}
        }

        if decoded.claims.exp != (decoded.claims.iat + 30) {
            return Err(DecodeTokenError::ExpNotIatPlus30);
        }

        if decoded.claims.iat
            > now
                .timestamp()
                .try_into()
                .context("error converting timestamp to i64")?
        {
            return Err(DecodeTokenError::IatAfterNow);
        }

        if decoded.claims.iss != client_id {
            return Err(DecodeTokenError::IssDoesntMatchClientId);
        }

        if decoded.claims.sub != decoded.claims.iss {
            return Err(DecodeTokenError::SubDoesNotMatchIss);
        }

        Ok(decoded)
    }

    pub fn decode_token_custom_claims<CustomClaims: DeserializeOwned>(
        &self,
        token: &str,
        audience: Option<&str>,
    ) -> Result<TokenData<IshareClaimsWithExtra<CustomClaims>>, DecodeTokenError> {
        let mut validation = Validation::new(Algorithm::RS256);

        match audience {
            Some(aud) => validation.set_audience(&[aud]),
            None => validation.set_audience(&[&self.eori]),
        }

        let first_x5c = get_first_x5c(token)?;
        let decoding_key =
            &DecodingKey::from_rsa_pem(&first_x5c.to_pem().context("Error converting x5c to pem")?)
                .context("Error creating decoding key from rsa pem")?;

        let decoded =
            decode::<IshareClaimsWithExtra<CustomClaims>>(&token, decoding_key, &validation)?;

        Ok(decoded)
    }
}
