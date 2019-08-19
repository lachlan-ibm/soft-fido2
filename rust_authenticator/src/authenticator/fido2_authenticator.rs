

extern crate serde_json;
extern crate serde_cbor;

struct AuthenticatorData {
    clientDataHash: Vec<u8>,
    rp: String,
    flags: u8,
    counter: u8,
    credentialId: Vec<u8>,
}


fn authenticator_data(authData: &AuthenticatorData) -> Vec<u8> {

}

pub fn credential_create() ->  {

}

pub fn credential_get(jsonOptions: &str) -> {

}
