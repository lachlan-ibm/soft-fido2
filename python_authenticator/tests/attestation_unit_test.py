#!/bin/python3

from fido2_authenticator import Fido2Authenticator
import pytest

server = fido2.Fido2Server(rp)


def E2E_Unit_Test(fido2_server, fido2_rp, fido2_user):
    attestation_options = fido2_server.register_begin(fido2_user)
    authenticator = Fido2Authenticator()
    attestation = authenticator.credential_create(attestation_options)
    fido2_server.register_complete(attesation)
