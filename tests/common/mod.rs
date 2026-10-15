#![allow(dead_code)]

use std::time::{SystemTime, UNIX_EPOCH};

use base64::prelude::*;
use ishare::{Identity, TrustAnchor};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use openssl::{
    asn1::Asn1Time,
    bn::BigNum,
    hash::MessageDigest,
    pkcs12::Pkcs12,
    pkey::{PKey, Private},
    rsa::Rsa,
    stack::Stack,
    x509::{extension::BasicConstraints, X509Name, X509},
};
use serde_json::{json, Value};

fn name(cn: &str) -> X509Name {
    let mut name = X509Name::builder().unwrap();
    name.append_entry_by_text("CN", cn).unwrap();
    name.build()
}

fn certificate(cn: &str, key: &PKey<Private>, issuer: Option<(&X509, &PKey<Private>)>) -> X509 {
    let mut builder = X509::builder().unwrap();
    builder.set_version(2).unwrap();
    let serial = BigNum::from_u32(rand_serial()).unwrap();
    builder
        .set_serial_number(&serial.to_asn1_integer().unwrap())
        .unwrap();
    builder.set_subject_name(&name(cn)).unwrap();
    builder.set_pubkey(key).unwrap();
    builder
        .set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    builder
        .set_not_after(&Asn1Time::days_from_now(1).unwrap())
        .unwrap();
    match issuer {
        None => {
            builder.set_issuer_name(&name(cn)).unwrap();
            builder
                .append_extension(BasicConstraints::new().critical().ca().build().unwrap())
                .unwrap();
            builder.sign(key, MessageDigest::sha256()).unwrap();
        }
        Some((issuer_cert, issuer_key)) => {
            builder.set_issuer_name(issuer_cert.subject_name()).unwrap();
            builder.sign(issuer_key, MessageDigest::sha256()).unwrap();
        }
    }
    builder.build()
}

fn rand_serial() -> u32 {
    uuid::Uuid::new_v4().as_u128() as u32
}

fn rsa_key() -> PKey<Private> {
    PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap()
}

pub struct TestPki {
    dir: std::path::PathBuf,
    ca: X509,
    ca_key: PKey<Private>,
    registry_key: PKey<Private>,
    registry_cert: X509,
}

impl TestPki {
    pub fn new() -> Self {
        let dir = std::env::temp_dir().join(format!("ishare-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&dir).unwrap();
        let ca_key = rsa_key();
        let ca = certificate("Test Dataspace Authority", &ca_key, None);
        let registry_key = rsa_key();
        let registry_cert = certificate(
            "Test Participant Registry",
            &registry_key,
            Some((&ca, &ca_key)),
        );
        Self {
            dir,
            ca,
            ca_key,
            registry_key,
            registry_cert,
        }
    }

    pub fn trust_anchor(&self) -> TrustAnchor {
        let path = self.dir.join("ca.pem");
        std::fs::write(&path, self.ca.to_pem().unwrap()).unwrap();
        TrustAnchor::from_pem_file(path.to_str().unwrap()).unwrap()
    }

    pub fn identity(&self, eori: &str) -> (Identity, X509) {
        let key = rsa_key();
        let cert = certificate(eori, &key, Some((&self.ca, &self.ca_key)));
        let mut chain = Stack::new().unwrap();
        chain.push(self.ca.clone()).unwrap();
        let p12 = Pkcs12::builder()
            .name(eori)
            .pkey(&key)
            .cert(&cert)
            .ca(chain)
            .build2("test")
            .unwrap();
        let path = self.dir.join("client.p12");
        std::fs::write(&path, p12.to_der().unwrap()).unwrap();
        let identity = Identity::from_p12(path.to_str().unwrap(), "test", eori).unwrap();
        (identity, cert)
    }

    /// Signs `payload` as the registry, with the registry certificate in the x5c header.
    pub fn sign(&self, payload: &Value) -> String {
        let header = Header {
            typ: Some("JWT".to_owned()),
            alg: Algorithm::RS256,
            x5c: Some(vec![
                BASE64_STANDARD.encode(self.registry_cert.to_der().unwrap())
            ]),
            ..Default::default()
        };
        let key = EncodingKey::from_rsa_pem(&self.registry_key.private_key_to_pem_pkcs8().unwrap())
            .unwrap();
        encode(&header, payload, &key).unwrap()
    }
}

impl Drop for TestPki {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// A documented payload with `iat`/`exp` moved to now, since the examples have long expired.
pub fn documented_payload(fixture: &str) -> Value {
    let mut payload: Value = serde_json::from_str(fixture).unwrap();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    payload["iat"] = json!(now);
    payload["exp"] = json!(now + 30);
    payload
}
