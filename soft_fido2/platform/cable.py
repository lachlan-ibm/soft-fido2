# Copyrite IBM 2022, 2025
# IBM Confidential

import cbor2 as cbor
import hashlib
import struct


class CaBLE(object):
    """
    Client to Authenticator Protocol (CTAP) caBLE (Cloud-Assisted BLE) implementation.
    
    Handles QR code parsing and tunnel server domain decoding according to
    CTAP v2.3 specification (fido-client-to-authenticator-protocol-v2.3-rd-20251023.pdf).
    """
    
    ASSIGNED_TUNNEL_SERVER_DOMAINS = ["cable.ua5v.com", "cable.auth.com"]
    
    def __init__(self):
        return

    def decode_qr_data(self, data):
        """
        Decode QR code data from FIDO:/ URI format.
        
        The QR code contains a URI of the form "FIDO:/" followed by digit-encoded data.
        The encoding uses 7-byte chunks interpreted as little-endian values and encoded
        as 17-digit base-10 numbers. Remaining bytes use minimum digits needed.
        
        Args:
            data: String of digits from the QR code (after "FIDO:/" prefix)
            
        Returns:
            dict: CBOR-decoded map containing:
                - Key 0: 33-byte P-256 X9.62 compressed public key
                - Key 1: 16-byte random QR secret
                - Key 2: Number of assigned tunnel server domains
                - Key 3: (optional) Current time in epoch seconds
                - Key 4: (optional) Boolean for state-assisted transactions support
                - Key 5: (optional) User flow hint value
                - Key 6: (optional) List of supported transport channels
        """
        chunk_size = 17
        chunk_bytes = 7
        buff = b''
        
        # Process full 17-digit chunks (representing 7 bytes each)
        for i in range(int(len(data) / chunk_size)):
            chunk_str = data[i * chunk_size: (i + 1) * chunk_size]
            chunk_value = int(chunk_str)
            buff += chunk_value.to_bytes(chunk_bytes, 'little')
        
        # Process trailing bytes if any
        if len(data) % chunk_size != 0:
            trailing_str = data[int(len(data) / chunk_size) * chunk_size:]
            trailing_len = len(trailing_str)
            
            # Determine number of bytes based on digit count
            # 3 digits -> 1 byte, 5 -> 2, 8 -> 3, 10 -> 4, 13 -> 5, 15 -> 6
            if trailing_len == 3:
                num_bytes = 1
            elif trailing_len == 5:
                num_bytes = 2
            elif trailing_len == 8:
                num_bytes = 3
            elif trailing_len == 10:
                num_bytes = 4
            elif trailing_len == 13:
                num_bytes = 5
            elif trailing_len == 15:
                num_bytes = 6
            else:
                num_bytes = chunk_bytes
            
            trailing_value = int(trailing_str)
            buff += trailing_value.to_bytes(num_bytes, 'little')
        
        return cbor.loads(buff)

    def decode_tunnel_server_domain(self, encoded):
        """
        Decode tunnel server domain from encoded value.
        
        Args:
            encoded: uint16 value representing the tunnel server
            
        Returns:
            tuple: (domain_string, success_bool)
                - If encoded < 256: returns assigned domain from list
                - If encoded >= 256: generates domain using SHA-256 hash
        """
        if encoded < 256:
            if encoded >= len(self.ASSIGNED_TUNNEL_SERVER_DOMAINS):
                return "", False
            return self.ASSIGNED_TUNNEL_SERVER_DOMAINS[encoded], True
        
        # Generate domain for encoded values >= 256
        # SHA input: "caBLEv2 tunnel server domain" + encoded (little-endian) + 0x00
        sha_input = b'caBLEv2 tunnel server domain'
        sha_input += struct.pack('<H', encoded)
        sha_input += b'\x00'
        
        digest = hashlib.sha256(sha_input).digest()
        v = struct.unpack('<Q', digest[:8])[0]
        
        # Extract TLD index from lower 2 bits
        tld_index = v & 3
        v >>= 2
        
        # Build domain name using base32 encoding
        ret = "cable."
        base32_chars = "abcdefghijklmnopqrstuvwxyz234567"
        
        while v != 0:
            ret += base32_chars[v & 31]
            v >>= 5
        
        # Append TLD
        tlds = [".com", ".org", ".net", ".info"]
        ret += tlds[tld_index & 3]
        
        return ret, True

    def parse_qr_contents(self, qr_uri):
        """
        Parse complete QR code URI and extract all fields.
        
        Args:
            qr_uri: Complete QR code string (e.g., "FIDO:/123456...")
            
        Returns:
            dict: Parsed QR code data with decoded fields including:
                - public_key: 33-byte compressed P-256 public key
                - qr_secret: 16-byte random secret
                - tunnel_server_domain: Decoded domain string
                - timestamp: Optional epoch seconds
                - state_assisted: Optional boolean
                - user_flow: Optional flow hint
                - transport_channels: Optional list of supported channels
        """
        if not qr_uri.startswith("FIDO:/"):
            raise ValueError("Invalid QR code format: must start with 'FIDO:/'")
        
        # Extract digit-encoded data after "FIDO:/" prefix
        digit_data = qr_uri[6:]
        
        # Decode to CBOR map
        cbor_map = self.decode_qr_data(digit_data)
        
        # Parse required fields
        result = {
            'public_key': cbor_map.get(0),  # Key 0: 33-byte public key
            'qr_secret': cbor_map.get(1),   # Key 1: 16-byte secret
        }
        
        # Decode tunnel server domain (Key 2)
        num_domains = cbor_map.get(2, 0)
        if num_domains > 0:
            domain, success = self.decode_tunnel_server_domain(num_domains)
            result['tunnel_server_domain'] = domain if success else None
        
        # Parse optional fields
        if 3 in cbor_map:
            result['timestamp'] = cbor_map[3]
        
        if 4 in cbor_map:
            result['state_assisted'] = cbor_map[4]
        
        if 5 in cbor_map:
            result['user_flow'] = cbor_map[5]
        
        if 6 in cbor_map:
            result['transport_channels'] = cbor_map[6]
        
        return result
