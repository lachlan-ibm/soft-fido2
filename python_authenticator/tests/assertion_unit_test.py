#!/bin/python3

from fido2_authenticator import Fido2Authenticator
import pytest

server = fido2.Fido2Server(rp)


def E2E_Unit_Test(fido2_server, fido2_authenticator):
    assertion_options = fido2_server.authenticate_begin(fido2_user)
    assertion = authenticator.credential_request(assertion_options)
    fido2_server.authenticate_complete(assertion)
