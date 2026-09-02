# Copyright IBM Corp. 2022, 2025
# IBM Confidential

"""CTAP1 / U2F APDU handlers, isolated from CTAP2 framing.

U2FHandler is stateless — all methods are @staticmethod.  A
``cbor_cmd_factory`` callable is passed in so this module does not need
to import CBORCommand (avoids a circular dependency).
"""

from .packet import bcolors, colour_print

from ..key_pair import KeyUtils
from ..symmetric_key import SymmetricKey
from ..u2f_authenticator import U2FAuthenticator
from ..authenticator import Fido2Authenticator


class U2FHandler:
    """Stateless U2F (CTAP1) APDU dispatcher."""

    @staticmethod
    def build_response(cid, cmd_byte, payload, cbor_cmd_factory, sw=b'\x90\x00'):
        """Build a U2F APDU response wrapped in a CBORCommand-like object."""
        rsp = cbor_cmd_factory(cid, None, skip_init=True)
        rsp.ctaphid_cmd = cmd_byte
        data = payload + sw
        rsp.response = list(data)
        rsp.bcnt = len(data)
        return rsp

    @staticmethod
    def dispatch(cid, cmd_byte, apdu, cbor_cmd_factory):
        """
        Parse the CTAPHID_MSG APDU and dispatch to the appropriate U2F handler.
        UP is not re-checked — already established during _get_info.
        """
        u2f_cla  = apdu[0:1]
        u2f_ins  = apdu[1:2]
        u2f_p1   = apdu[2:3]
        u2f_p2   = apdu[3:4]
        lc = int.from_bytes(apdu[5:7], 'big') if len(apdu) >= 7 else 0
        u2f_data = apdu[7:7 + lc] if lc > 0 else apdu[7:]

        colour_print(colour=bcolors.OKGREEN, component='U2FHandler.dispatch',
                     msg='CLA={}; INS={}; P1={}; P2={}; Lc={}'.format(
                         u2f_cla.hex(), u2f_ins.hex(), u2f_p1.hex(), u2f_p2.hex(), lc))
        colour_print(colour=bcolors.OKGREEN, component='U2FHandler.dispatch',
                     msg='apdu total len={}; u2f_data len={}'.format(len(apdu), len(u2f_data)))

        if u2f_cla != b'\x00':
            colour_print(colour=bcolors.FAIL, component='U2FHandler.dispatch',
                         msg='Unexpected CLA {}'.format(u2f_cla.hex()))
            return U2FHandler.build_response(cid, cmd_byte, b'', cbor_cmd_factory, sw=b'\x69\x00')

        if u2f_ins == b'\x03':
            return U2FHandler.version(cid, cmd_byte, cbor_cmd_factory)
        if u2f_ins == b'\x01':
            return U2FHandler.register(cid, cmd_byte, u2f_data, cbor_cmd_factory)
        if u2f_ins == b'\x02':
            return U2FHandler.authenticate(cid, cmd_byte, u2f_p1, u2f_data, cbor_cmd_factory)

        colour_print(colour=bcolors.FAIL, component='U2FHandler.dispatch',
                     msg='Unknown INS {}'.format(u2f_ins.hex()))
        return U2FHandler.build_response(cid, cmd_byte, b'', cbor_cmd_factory, sw=b'\x69\x00')

    @staticmethod
    def version(cid, cmd_byte, cbor_cmd_factory):
        return U2FHandler.build_response(cid, cmd_byte, b'U2F_V2', cbor_cmd_factory)

    @staticmethod
    def register(cid, cmd_byte, u2f_data, cbor_cmd_factory):
        """
        Handle U2F_REGISTER (INS=0x01).

        u2f_data layout:
            [0:32]  clientDataHash
            [32:64] appIdHash
        """
        from .api import AuthenticatorAPI
        if len(u2f_data) < 64:
            colour_print(colour=bcolors.FAIL, component='U2FHandler.register',
                         msg=f'REGISTER data too short: {len(u2f_data)} bytes')
            return U2FHandler.build_response(cid, cmd_byte, b'', cbor_cmd_factory, sw=b'\x6a\x80')

        client_data_hash = u2f_data[0:32]
        app_id_hash      = u2f_data[32:64]

        colour_print(colour=bcolors.OKPURPLE, component='U2FHandler.register',
                     msg='clientDataHash={}'.format(client_data_hash.hex()))
        colour_print(colour=bcolors.OKPURPLE, component='U2FHandler.register',
                     msg='appIdHash={}'.format(app_id_hash.hex()))

        plat_kp = KeyUtils._get_platform_kp()
        seed = KeyUtils.get_passkey_seed(
            app_id_hash.hex().encode(),
            plat_kp if hasattr(plat_kp, 'is_tpm') else plat_kp.get_private(),
            info=AuthenticatorAPI._get_hkdf_info()
        )
        skey = SymmetricKey(seed.decode())

        auth = U2FAuthenticator(keyPair=plat_kp, sKey=skey)
        try:
            payload = auth.register(app_id_hash, client_data_hash)
        except Exception as e:
            colour_print(colour=bcolors.FAIL, component='U2FHandler.register',
                         msg=f'register() failed: {e}')
            return U2FHandler.build_response(cid, cmd_byte, b'', cbor_cmd_factory, sw=b'\x69\x00')
        if auth.cib:
            colour_print(colour=bcolors.OKGREEN, component='U2FHandler.register',
                        msg=f'Registration complete, cred_id={auth.cib.hex()}')
        return U2FHandler.build_response(cid, cmd_byte, payload, cbor_cmd_factory)

    @staticmethod
    def authenticate(cid, cmd_byte, p1, u2f_data, cbor_cmd_factory):
        """
        Handle U2F_AUTHENTICATE (INS=0x02).

        u2f_data layout:
            [0:32]  clientDataHash
            [32:64] appIdHash
            [64]    key handle length (1 byte)
            [65:]   key handle bytes

        P1=0x07 → check-only (return 0x6985 if key handle is ours)
        P1=0x03 → sign
        """
        from .api import AuthenticatorAPI
        if len(u2f_data) < 65:
            colour_print(colour=bcolors.FAIL, component='U2FHandler.authenticate',
                         msg=f'AUTHENTICATE data too short: {len(u2f_data)} bytes')
            return U2FHandler.build_response(cid, cmd_byte, b'', cbor_cmd_factory, sw=b'\x6a\x80')

        client_data_hash = u2f_data[0:32]
        app_id_hash      = u2f_data[32:64]
        kh_len           = u2f_data[64]
        key_handle       = u2f_data[65:65 + kh_len]

        if p1 == b'\x07': # confirm we own this key handle
            if key_handle.startswith(Fido2Authenticator.CRED_PREFIX):
                return U2FHandler.build_response(cid, cmd_byte, b'', cbor_cmd_factory, sw=b'\x69\x85')
            return U2FHandler.build_response(cid, cmd_byte, b'', cbor_cmd_factory, sw=b'\x6a\x80')

        plat_kp = KeyUtils._get_platform_kp()
        seed = KeyUtils.get_passkey_seed(
            app_id_hash.hex().encode(),
            plat_kp if hasattr(plat_kp, 'is_tpm') else plat_kp.get_private(),
            info=AuthenticatorAPI._get_hkdf_info()
        )
        skey = SymmetricKey(seed.decode())

        try:
            auth = U2FAuthenticator(credId=key_handle, sKey=skey)
            payload = auth.authenticate(app_id_hash, client_data_hash)
        except Exception as e:
            colour_print(colour=bcolors.FAIL, component='U2FHandler.authenticate',
                         msg=f'authenticate() failed: {e}')
            return U2FHandler.build_response(cid, cmd_byte, b'', cbor_cmd_factory, sw=b'\x69\x00')

        colour_print(colour=bcolors.OKGREEN, component='U2FHandler.authenticate',
                     msg='Authentication complete')
        return U2FHandler.build_response(cid, cmd_byte, payload, cbor_cmd_factory)
