
pub struct TPMAttestation {
    x5c: Vec<_>,
    alg: i8 = -257,
    sig: Vec<u8>,
}

impl Fido2Sign for TPMAttestation {
    fn sign(&self) -> Result<()> {
        self.sig = [-1];
        Ok(())
    }
}

impl AttestationObject for TPMAttestation {

}
