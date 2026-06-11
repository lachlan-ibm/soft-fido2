


import pytest
from unittest.mock import patch, MagicMock
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from soft_fido2.key_pair import KeyPair, KeyUtils
import tempfile, os, shutil, uuid

@pytest.fixture
def mock_platform_key():
    """Mock platform key retrieval for tests that don't have qt_app running"""
    # Create a real EC key pair for testing
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    
    # Create a mock KeyPair
    mock_kp = MagicMock()
    mock_kp.get_private.return_value = private_key
    
    # Patch the __request_platform_kp method
    with patch('soft_fido2.key_pair.KeyUtils._KeyUtils__request_platform_kp', return_value=mock_kp):
        yield mock_kp

def _cleanup(temp_dir):
    if os.path.exists(temp_dir):
        shutil.rmtree(temp_dir)

def _write_key_to_tmp(key, x5c, resCreds, pinHash):
    passkeyFilename = str(uuid.uuid4()) + '.passkey'
    KeyUtils._save_passkey(key, x5c, resCreds, pinHash, passkeyFilename)
    return passkeyFilename

def test_generate_passkey(mock_platform_key):
    tdir = tempfile.TemporaryDirectory()
    os.environ['FIDO_HOME'] = tdir.name
    KeyUtils.create_platform_key()
    passkey = KeyUtils.generate_passkey()
    passkey_name = _write_key_to_tmp(passkey['key'],
                                            passkey['x5c'],
                                            [],
                                            KeyUtils.get_pin_hash('1234567890abcdef1234567890abcdef'))
    passkey_path = os.path.join(tdir.name, passkey_name)
    print(os.listdir(tdir.name))
    assert os.path.exists( passkey_path ), f"{passkey_path} does not exist"
    _cleanup(tdir.name)

def test_passkey_roundtrip(mock_platform_key):
    tdir = tempfile.TemporaryDirectory()
    os.environ['FIDO_HOME'] = tdir.name
    KeyUtils.create_platform_key()
    passkey = KeyUtils.generate_passkey()

    phrase = 'pirate.passkey.secret'
    pin_hash = KeyUtils.get_pin_hash(phrase)
    passkey_name = _write_key_to_tmp(passkey['key'],
                           passkey['x5c'],
                           [],
                           pin_hash)
    passkey_path = os.path.join(tdir.name, passkey_name)
    print(os.listdir(tdir.name))
    assert os.path.exists( passkey_path ), f"{passkey_path} does not exist"
    reloaded = KeyUtils._load_passkey(pin_hash, passkey_name)
    passkey_bytes = KeyPair(passkey['key'], passkey['key'].public_key()).get_private_bytes()
    reloaded_bytes = KeyPair(reloaded['key'], reloaded['key'].public_key()).get_private_bytes()
    assert reloaded_bytes == passkey_bytes
    assert reloaded['x5c'].fingerprint(hashes.SHA256()) == passkey['x5c'].fingerprint(hashes.SHA256())
    assert reloaded['pin.hash'] == pin_hash
    _cleanup(tdir.name)

def test_load_java_passkey():

    return None