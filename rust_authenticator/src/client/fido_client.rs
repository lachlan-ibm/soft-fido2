    pp

use std::io;

#[derive(Clone, Copy)]
pub struct RelyingParty {
    id: &str,
    name: &str,
}

#[derive(Clone, Copy)]
pub struct User {
    id: &str,
    name: &str,
    displayName: &str,
}

#[derive(Clone, Copy)]
pub struct AuthenticatorSelection {
    requireResidentKey: bool,
    authenticatorAttachment: str,
    userVerification: str,
}

#[derive(Clone, Copy)]
pub struct PubKeyCred {
    alg: i8,
    _type: str,
}

#[derive(Clone, Copy)]
pub struct CredCreateOptions {
    rp: RelyingParty
    user: User,
    timeout: u32,
    challenge: Vec[u8],
    authSel: AuthenticatorSelection,
    attestation: str,
    pubKeyCredParams: Vec[PubKeyCred],
}

#[derive(Clone, Copy)]
pub struct CredRequestOptions{
    rpId: str,
    userId: str,
    displayName: str,
    authSel: AuthenticatorSelection,
    attestation: str,
}

pub trait Fido2Client {

    fn credential_make(&self, cco: CredCreateOptions) -> io::Result<()>;

    fn credential_get(&self, cro: CredRequestOptions) -> io::Result<()>;

    fn authentiator_create(&self) -> io::Result<()>;

    fn authenticator_destroy(&self) -> io::Result<()>;

    fn authenticator_reset(&self) -> io::Result<()>;

    fn authenticator_set_pin(&self, Vec<u8>) -> io::Result<()>;
}
