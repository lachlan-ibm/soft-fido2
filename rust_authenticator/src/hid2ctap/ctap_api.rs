use super::ctap_api;
use std::io;


pub fn ctap_event(ctap_api::CTAP_EVENT: event, input: [u8]) -> io::Result<()> {
    match event {
        ctap_api::CTAP_EVENT::AUTHENTICATOR_MAKE_CRED => authenticator_make_cred(input),
        ctap_api::CTAP_EVENT::AUTHENTICATOR_GET_ASSERT => authenticator_get_assert(input),
        ctap_api::CTAP_EVENT::AUTHENTICATOR_CANCEL => authenticator_cancel(input),
        ctap_api::CTAP_EVENT::AUTHENTICATOR_GET_INFO => authenticator_get_info(input),
        ctap_api::CTAP_EVENT::AUTHENTICATOR_CLIENT_PIN => authenticator_client_pin(input),
        ctap_api::CTAP_EVENT::AUTHENTICATOR_RESET => authenticator_reset(input),
        ctap_api::CTAP_EVENT::AUTHENTICATOR_GET_NEXT_ASSERT => authenticator_get_next_assert(input),
        _ => authenticator_error(input)
    }
}


pub fn authenticator_make_cred(input: [u8]) -> io::Result<()> {
    Ok(())
}

pub fn authenticator_get_assert(input: [u8]) -> io::Result<()> {
    Ok(())
}

pub fn authenticator_cancel(input: [u8]) -> io::Result<()> {
    Ok(())
}

pub fn authenticator_get_info(input: [u8]) -> io::Result<()> {
    Ok(())
}

pub fn authenticator_client_pin(input: [u8]) -> io::Result<()> {
    Ok(())
}

pub fn authenticator_reset(input: [u8]) -> io::Result<()> {
    Ok(())
}

pub fn authenticator_get_next_assert(input: [u8]) -> io::Result<()> {
    Ok(())
}

pub fn authenticator_error(input: [u8]) -> io::Result<()> {
    Err(io::Error::new(err.kind(), format!("Unknown input: {}", input)))
}
