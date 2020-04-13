#!/bin/python3

from soft_FIDO2 import Fido2Authenticator
import pytest
import fido2

server = fido2.Fido2Server(rp)


def E2E_Unit_Test(fido2_server, fido2_authenticator):
    assertion_options = fido2_server.authenticate_begin(fido2_user)
    assertion = authenticator.credential_request(assertion_options)
    fido2_server.authenticate_complete(assertion)


def Signing_Test(fido2_server, fido2_authenticator):
    pass


def Client_Data_JSON_Test(fido2_sever, fido2_authenticator):
    pass


def Authenticator_Data_Test(fido2_server, fido2_authenticator):
    pass


def Attestation_Object_Test(fido2_server, fido2_authenticator):
    pass


def Key_Reconstruction_Test(fido2_server, fido2_authenticator):
    pass
