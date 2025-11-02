
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from cryptography.x509 import Certificate
from soft_fido2.key_pair import KeyPair


java_passkey = '''AAAAsi0tLS0tQkVHSU4gUFVCTElDIEtFWS0tLS0tCk1Ga3dFd1lIS29aSXpqMENBUVlJS29aSXpq
MERBUWNEUWdBRXR2Mzh0NU80YzIxNnA0cWE4K2ZUdVl1M2tYMUQKancrMUZqamF4WTdCSEszeHdT
UDN5RlJ1TW9scHFqZGsvaTVMT3l6T2R1TFpmT1ZxOVZHTTg4b2h6UT09Ci0tLS0tRU5EIFBVQkxJ
QyBLRVktLS0tLQrnyjdX1ZjIyTrantw6kKYCrK/rBgGBthGf/coJM91qgNR0hiMzmmgPUJ0nvf4p
tj3IAwAAMIACAQMwgAYJKoZIhvcNAQcBoIAkgASCA2YwgDCABgkqhkiG9w0BBwGggCSABIIBGzCC
ARcwggETBgsqhkiG9w0BDAoBAqCByTCBxjApBgoqhkiG9w0BDAEDMBsEFJlibMeQR32ZpPv3yWwE
JkqYqn0nAgMAyAAEgZgX8Wq61MuCNRUtwcCtv4zBV+PwS5XEcePblci2ObsZy1aQCbLu47UkcT8W
q+Jrgmqw1iA2T7/YNNpyZMnNmt021PLKUW6wQpiEIkOoJUT6lxeUNbLrwd+ZP9AnQVUomlIRmcqJ
Dn9KyN9E4W/FJuKoCxtjWdXhx+qVjHF+HEdI7F1X68wifJdl6nHIJWLOWRGATXH/kgGHgzE4MBEG
CSqGSIb3DQEJFDEEHgIAMTAjBgkqhkiG9w0BCRUxFgQUlxwPRgqH4UwygKBpR7RbPyylYOkAAAAA
AAAwgAYJKoZIhvcNAQcGoIAwgAIBADCABgkqhkiG9w0BBwEwKQYKKoZIhvcNAQwBBjAbBBQFixgq
Cvjo62yPpFBdkPhWw9QsZAIDAMgAoIAEggHQFbR5OwIZwEOw9vapGSqQHDl7/hh4X29J/36Bc81E
EgObjpoLL7fRB/vySW6dg6rFVfa0xjb+qudZiGjIdWZCfqQOVLtG3oyBLhxyTwOYA/ncsozG6MQf
VntjzNPrNlLexpFue8zZ6G/A16PoGug03ZJP3o+BNH0YrV6O2HERU1ikK2qXwCd4w48/3//KElFU
PcP8K+a+GbLqUjv9GfzxOUfdy+jT28AdUKvNc7NUtORDgHHBY0VWMzHCT5uc579pvb/Vqe6lgqbC
JwZTCLwq0lRQOvVHEFKgw9eKWscmrF30FF94MG2t1fRMyVYrA2PQ8QGzG6QM072VcLOmeOtPq7Vl
XngpySbR71NkX3+r2fRtwSIZmn8QWXdYkglISRs+nkPxCZrMiEbF9WACBGX05oz4UbmmQh5LOGxZ
nKZ6oUGYnoQ0NiQsUys6xohMQzHlAl4Z15TpC6gR6j7sFkI5WzXvxlJPmyVfUhZckE2CjPHA1IgW
0WNAnkJ9ykItnML/19rR1wH8aZxZKrHYG17/VxPVkAX5OnT1IQDJYxTQ4KwZFsGVF7uWjTsaMTUn
OFgWqaZS/LI9pGhxGmWpKIWo91aZxa9744GKp05Ojrb8+DMAAAAAAAAAAAAAAAAAAAAAAAAwPjAh
MAkGBSsOAwIaBQAEFCHBdbnkCY2YIRux9nYkEXWJHR3jBBQ7c+RrD5Gsk5WzhhYZD+ZUN8TdCAID
AZAAAAAAAACyLS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUZrd0V3WUhLb1pJemowQ0FRWUlL
b1pJemowREFRY0RRZ0FFQkllRjZlbGt3WFhxalduUHI4a04vdXRUc1BMUgp0a0ZvdGZLYmJKY2tl
TE1kWC9RL0FiUDBSVmhydGZPcmJyNnZtSjBPalEwVS9zQjUxdTZSYTRoSldRPT0KLS0tLS1FTkQg
UFVCTElDIEtFWS0tLS0tCsiEj5ZJmVJykAgLHcbAn8hXvomm3+6W8IWKf5KtEa8bDQ=='''

def test_load_java_passkey():
    """Test that a Java-generated passkey can be loaded by Python KeyUtils"""
    import base64
    import tempfile
    import os
    from soft_fido2.key_pair import KeyUtils
    
    # Remove newlines and decode the base64-encoded Java passkey
    java_passkey_unwrapped = java_passkey.replace('\n', '')
    java_passkey_bytes = base64.b64decode(java_passkey_unwrapped)

    print(f"{java_passkey_bytes}")
    
    # Create temporary directory and write passkey file
    tdir = tempfile.TemporaryDirectory()
    
    try:
        os.environ['FIDO_HOME'] = tdir.name
        
        # Create platform key needed for decryption
        KeyUtils.create_platform_key()
        
        # Write the Java passkey to a file
        passkey_filename = 'java_test.passkey'
        passkey_path = os.path.join(tdir.name, passkey_filename)
        with open(passkey_path, 'wb') as f:
            f.write(java_passkey_bytes)
        
        pin_hash = KeyUtils.get_pin_hash('00000000')
        passkey = KeyUtils._load_passkey(pin_hash, passkey_filename)
        
        # Verify we got valid objects back
        assert passkey is not None, "Failed to load passkey"
        assert passkey['key'] is not None, "Private key is None"
        assert passkey['x5c'] is not None, "Certificate is None"
        assert isinstance(passkey['key'], EllipticCurvePrivateKey), f"Private key is not EllipticCurvePrivateKey"
        assert isinstance(passkey['x5c'], Certificate), f"Certificate is not X509Certificate"
    finally:
        # Cleanup
        tdir.cleanup()
