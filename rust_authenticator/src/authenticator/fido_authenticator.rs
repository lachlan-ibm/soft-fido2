use std::result::Result;
use client::fido2_client;
use ring::signature::{self, KeyPair};
use openssl::x509::X509;

extern crate serde_json;
extern crate serde_cbor;

#[derive(Clone, Copy)]
struct Authenticator {
    keyPair: KeyPair,
    cert: X509,
    caCert: X509,
    caKeyPair: KeyPair,
    aaguid: Vec<u8>,
    counter: i32,
}

#[derive(Clone, Copy)]
struct AuthenticatorData {
    clientDataHash: Vec<u8>,
    rp: String,
    flags: u8,
    counter: u8,
    aaguid: Vec<u8>,
    credentialId: Vec<u8>,
    coseKey: Vec<u8>,
}

pub trait Fido2Sign {

    fn attestation(&self) -> Result<()>;

    fn assertion(&self) -> Result<()>;

    fn sign(&self) -> Result<()>;
}

pub trait AttestationObject {

    fn authenticator_data(&self) -> Result<()>;

    fn extensions(&self) -> Result<()>;

    fn attestation_object(&self) -> Result<()>;

    fn client_data_hash(&self) -> Result<()>;
}


pub trait Fido2Authenticator {

    pub fn create(&self, file: &mut File, authenticator: Authenticator) -> Result<()>;

    pub fn register(&self, authenticator: Authenticator, cco: fido2_client::CredCreateOptions) -> Result<()>;

    pub fn assert(&self, cro: fido2_client::CredRequestOptions) -> Result<()>;

    pub fn set_pin(&self, pin: Vec<u8>) -> Result<()>;

    pub fn reset(&self) -> Result<()>;
}
