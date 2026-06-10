"""
Unit tests for hash storage refactor - two-file passkey storage (.passkey + .stash)

Tests the new functionality where passkey files are split into:
- .passkey file: Contains the body (PKCS12 + encrypted credentials)
- .stash file: Contains the encrypted upper hash header (230 bytes)
"""

import pytest
import os
import tempfile
import shutil
import uuid
from unittest.mock import patch, MagicMock
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from soft_fido2.key_pair import KeyUtils


@pytest.fixture
def mock_platform_key():
    """Mock platform key retrieval for tests that don't have qt_app running"""
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    mock_kp = MagicMock()
    mock_kp.get_private.return_value = private_key
    
    with patch('soft_fido2.key_pair.KeyUtils._KeyUtils__request_platform_kp', return_value=mock_kp):
        yield mock_kp


@pytest.fixture
def temp_fido_home():
    """Create a temporary FIDO_HOME directory for testing"""
    tdir = tempfile.mkdtemp()
    old_fido_home = os.environ.get('FIDO_HOME')
    os.environ['FIDO_HOME'] = tdir
    
    yield tdir
    
    # Cleanup
    if os.path.exists(tdir):
        shutil.rmtree(tdir)
    
    # Restore original FIDO_HOME
    if old_fido_home:
        os.environ['FIDO_HOME'] = old_fido_home
    elif 'FIDO_HOME' in os.environ:
        del os.environ['FIDO_HOME']


@pytest.fixture
def sample_passkey(mock_platform_key, temp_fido_home):
    """Generate a sample passkey for testing"""
    KeyUtils.create_platform_key()
    passkey = KeyUtils.generate_passkey()
    pin_hash = KeyUtils.get_pin_hash('1234567890abcdef1234567890abcdef')
    
    return {
        'key': passkey['key'],
        'x5c': passkey['x5c'],
        'resCreds': [],
        'pinHash': pin_hash,
        'filename': str(uuid.uuid4()) + '.passkey'
    }


class TestGetStashPath:
    """Tests for __get_stash_path helper method"""
    
    def test_with_passkey_extension(self, temp_fido_home):
        """Test stash path generation with .passkey extension"""
        # Access private method using name mangling
        get_stash_path = getattr(KeyUtils, '_KeyUtils__get_stash_path')
        result = get_stash_path('test.passkey')
        expected = os.path.join(temp_fido_home, 'test.stash')
        assert result == expected
    
    def test_without_passkey_extension(self, temp_fido_home):
        """Test stash path generation without .passkey extension"""
        get_stash_path = getattr(KeyUtils, '_KeyUtils__get_stash_path')
        result = get_stash_path('test')
        expected = os.path.join(temp_fido_home, 'test.stash')
        assert result == expected
    
    def test_with_custom_fido_home(self):
        """Test stash path respects FIDO_HOME environment variable"""
        custom_home = '/custom/fido/home'
        os.environ['FIDO_HOME'] = custom_home
        
        get_stash_path = getattr(KeyUtils, '_KeyUtils__get_stash_path')
        result = get_stash_path('test.passkey')
        expected = os.path.join(custom_home, 'test.stash')
        assert result == expected


class TestSavePasskey:
    """Tests for _save_passkey method - writing two files"""
    
    def test_creates_both_files(self, sample_passkey, temp_fido_home):
        """Test that both .passkey and .stash files are created"""
        KeyUtils._save_passkey(
            sample_passkey['key'],
            sample_passkey['x5c'],
            sample_passkey['resCreds'],
            sample_passkey['pinHash'],
            sample_passkey['filename']
        )
        
        passkey_path = os.path.join(temp_fido_home, sample_passkey['filename'])
        stash_path = os.path.join(temp_fido_home, sample_passkey['filename'][:-8] + '.stash')
        
        assert os.path.exists(passkey_path), "Passkey file not created"
        assert os.path.exists(stash_path), "Stash file not created"
    
    def test_stash_file_size(self, sample_passkey, temp_fido_home):
        """Test that stash file is exactly 230 bytes"""
        KeyUtils._save_passkey(
            sample_passkey['key'],
            sample_passkey['x5c'],
            sample_passkey['resCreds'],
            sample_passkey['pinHash'],
            sample_passkey['filename']
        )
        
        stash_path = os.path.join(temp_fido_home, sample_passkey['filename'][:-8] + '.stash')
        stash_size = os.path.getsize(stash_path)
        
        assert stash_size == 230, f"Stash file should be 230 bytes, got {stash_size}"
    
    def test_passkey_file_not_empty(self, sample_passkey, temp_fido_home):
        """Test that passkey file contains data"""
        KeyUtils._save_passkey(
            sample_passkey['key'],
            sample_passkey['x5c'],
            sample_passkey['resCreds'],
            sample_passkey['pinHash'],
            sample_passkey['filename']
        )
        
        passkey_path = os.path.join(temp_fido_home, sample_passkey['filename'])
        passkey_size = os.path.getsize(passkey_path)
        
        assert passkey_size > 0, "Passkey file should not be empty"
    
    def test_adds_passkey_extension(self, sample_passkey, temp_fido_home):
        """Test that .passkey extension is added if missing"""
        filename_without_ext = sample_passkey['filename'][:-8]  # Remove .passkey
        
        KeyUtils._save_passkey(
            sample_passkey['key'],
            sample_passkey['x5c'],
            sample_passkey['resCreds'],
            sample_passkey['pinHash'],
            filename_without_ext
        )
        
        passkey_path = os.path.join(temp_fido_home, filename_without_ext + '.passkey')
        assert os.path.exists(passkey_path), "Should add .passkey extension"


class TestReadPasskey:
    """Tests for __read_passkey method - reading two files"""
    
    def test_reads_valid_files(self, sample_passkey, temp_fido_home):
        """Test reading valid passkey and stash files"""
        # First save the passkey
        KeyUtils._save_passkey(
            sample_passkey['key'],
            sample_passkey['x5c'],
            sample_passkey['resCreds'],
            sample_passkey['pinHash'],
            sample_passkey['filename']
        )
        
        # Then read it back
        read_passkey = getattr(KeyUtils, '_KeyUtils__read_passkey')
        header, body = read_passkey(sample_passkey['filename'])
        
        assert header is not None, "Header should not be None"
        assert body is not None, "Body should not be None"
        assert len(header) == 230, f"Header should be 230 bytes, got {len(header)}"
        assert len(body) > 0, "Body should not be empty"
    
    def test_missing_passkey_file_error(self, temp_fido_home):
        """Test error when .passkey file is missing"""
        read_passkey = getattr(KeyUtils, '_KeyUtils__read_passkey')
        with pytest.raises(FileNotFoundError) as exc_info:
            read_passkey('nonexistent.passkey')
        
        assert "Passkey file not found" in str(exc_info.value)
    
    def test_missing_stash_file_error(self, sample_passkey, temp_fido_home):
        """Test error when .stash file is missing (old format)"""
        # Create only the passkey file (simulate old format)
        passkey_path = os.path.join(temp_fido_home, sample_passkey['filename'])
        with open(passkey_path, 'wb') as f:
            f.write(b'dummy data')
        
        read_passkey = getattr(KeyUtils, '_KeyUtils__read_passkey')
        with pytest.raises(FileNotFoundError) as exc_info:
            read_passkey(sample_passkey['filename'])
        
        error_msg = str(exc_info.value)
        assert "Stash file not found" in error_msg
        assert "old format" in error_msg
        assert "regenerate" in error_msg
    
    def test_invalid_stash_size_error(self, sample_passkey, temp_fido_home):
        """Test error when stash file has incorrect size"""
        # Create passkey file
        passkey_path = os.path.join(temp_fido_home, sample_passkey['filename'])
        with open(passkey_path, 'wb') as f:
            f.write(b'dummy data')
        
        # Create stash file with wrong size
        stash_path = os.path.join(temp_fido_home, sample_passkey['filename'][:-8] + '.stash')
        with open(stash_path, 'wb') as f:
            f.write(b'wrong size data')  # Not 230 bytes
        
        read_passkey = getattr(KeyUtils, '_KeyUtils__read_passkey')
        with pytest.raises(ValueError) as exc_info:
            read_passkey(sample_passkey['filename'])
        
        error_msg = str(exc_info.value)
        assert "Invalid stash file size" in error_msg
        assert "expected 230" in error_msg
        assert "corrupted" in error_msg
    
    def test_adds_passkey_extension_on_read(self, sample_passkey, temp_fido_home):
        """Test that .passkey extension is added if missing during read"""
        # Save with extension
        KeyUtils._save_passkey(
            sample_passkey['key'],
            sample_passkey['x5c'],
            sample_passkey['resCreds'],
            sample_passkey['pinHash'],
            sample_passkey['filename']
        )
        
        # Read without extension
        filename_without_ext = sample_passkey['filename'][:-8]
        read_passkey = getattr(KeyUtils, '_KeyUtils__read_passkey')
        header, body = read_passkey(filename_without_ext)
        
        assert header is not None
        assert body is not None


class TestDeletePasskey:
    """Tests for delete_passkey method - deleting both files"""
    
    def test_deletes_both_files(self, sample_passkey, temp_fido_home):
        """Test that both .passkey and .stash files are deleted"""
        # Create files
        KeyUtils._save_passkey(
            sample_passkey['key'],
            sample_passkey['x5c'],
            sample_passkey['resCreds'],
            sample_passkey['pinHash'],
            sample_passkey['filename']
        )
        
        passkey_path = os.path.join(temp_fido_home, sample_passkey['filename'])
        stash_path = os.path.join(temp_fido_home, sample_passkey['filename'][:-8] + '.stash')
        
        # Verify files exist
        assert os.path.exists(passkey_path)
        assert os.path.exists(stash_path)
        
        # Delete
        KeyUtils.delete_passkey(sample_passkey['filename'])
        
        # Verify files are gone
        assert not os.path.exists(passkey_path), "Passkey file should be deleted"
        assert not os.path.exists(stash_path), "Stash file should be deleted"
    
    def test_handles_missing_files_gracefully(self, temp_fido_home):
        """Test that deleting non-existent files doesn't raise error"""
        # Should not raise exception
        KeyUtils.delete_passkey('nonexistent.passkey')
    
    def test_handles_partial_deletion(self, sample_passkey, temp_fido_home):
        """Test behavior when only one file exists"""
        # Create only passkey file
        passkey_path = os.path.join(temp_fido_home, sample_passkey['filename'])
        with open(passkey_path, 'wb') as f:
            f.write(b'dummy data')
        
        # Should not raise exception
        KeyUtils.delete_passkey(sample_passkey['filename'])
        
        assert not os.path.exists(passkey_path)
    
    def test_adds_passkey_extension_on_delete(self, sample_passkey, temp_fido_home):
        """Test that .passkey extension is added if missing during delete"""
        # Create files
        KeyUtils._save_passkey(
            sample_passkey['key'],
            sample_passkey['x5c'],
            sample_passkey['resCreds'],
            sample_passkey['pinHash'],
            sample_passkey['filename']
        )
        
        # Delete without extension
        filename_without_ext = sample_passkey['filename'][:-8]
        KeyUtils.delete_passkey(filename_without_ext)
        
        passkey_path = os.path.join(temp_fido_home, sample_passkey['filename'])
        stash_path = os.path.join(temp_fido_home, filename_without_ext + '.stash')
        
        assert not os.path.exists(passkey_path)
        assert not os.path.exists(stash_path)


class TestRoundTrip:
    """Integration tests for save -> read -> delete cycle"""
    
    def test_save_read_roundtrip(self, sample_passkey, temp_fido_home):
        """Test that data can be saved and read back correctly"""
        # Save
        KeyUtils._save_passkey(
            sample_passkey['key'],
            sample_passkey['x5c'],
            sample_passkey['resCreds'],
            sample_passkey['pinHash'],
            sample_passkey['filename']
        )
        
        # Read
        read_passkey = getattr(KeyUtils, '_KeyUtils__read_passkey')
        header, body = read_passkey(sample_passkey['filename'])
        
        # Verify structure
        assert len(header) == 230
        assert len(body) > 0
        
        # Body should start with PKCS12 length (4 bytes)
        assert len(body) >= 4
    
    def test_multiple_passkeys(self, mock_platform_key, temp_fido_home):
        """Test handling multiple passkey files in same directory"""
        KeyUtils.create_platform_key()
        
        # Create multiple passkeys
        passkeys = []
        for i in range(3):
            passkey = KeyUtils.generate_passkey()
            filename = f'test_{i}.passkey'
            KeyUtils._save_passkey(
                passkey['key'],
                passkey['x5c'],
                [],
                KeyUtils.get_pin_hash('1234567890abcdef1234567890abcdef'),
                filename
            )
            passkeys.append(filename)
        
        # Verify all files exist
        for filename in passkeys:
            passkey_path = os.path.join(temp_fido_home, filename)
            stash_path = os.path.join(temp_fido_home, filename[:-8] + '.stash')
            assert os.path.exists(passkey_path)
            assert os.path.exists(stash_path)
        
        # Read all passkeys
        read_passkey = getattr(KeyUtils, '_KeyUtils__read_passkey')
        for filename in passkeys:
            header, body = read_passkey(filename)
            assert len(header) == 230
            assert len(body) > 0
        
        # Delete one passkey
        KeyUtils.delete_passkey(passkeys[1])
        
        # Verify only that one is deleted
        assert os.path.exists(os.path.join(temp_fido_home, passkeys[0]))
        assert not os.path.exists(os.path.join(temp_fido_home, passkeys[1]))
        assert os.path.exists(os.path.join(temp_fido_home, passkeys[2]))


class TestFileDiscovery:
    """Tests for file discovery methods in passkey_device.py and qt_app.py"""
    
    def test_discovery_requires_both_files(self, sample_passkey, temp_fido_home):
        """Test that file discovery only returns passkeys with both files"""
        from soft_fido2.passkey_device import AuthenticatorAPI
        
        # Create complete passkey (both files)
        KeyUtils._save_passkey(
            sample_passkey['key'],
            sample_passkey['x5c'],
            sample_passkey['resCreds'],
            sample_passkey['pinHash'],
            'complete.passkey'
        )
        
        # Create incomplete passkey (only .passkey file)
        incomplete_path = os.path.join(temp_fido_home, 'incomplete.passkey')
        with open(incomplete_path, 'wb') as f:
            f.write(b'dummy data')
        
        # Get passkey files
        files = AuthenticatorAPI._get_passkey_files(temp_fido_home)
        
        # Should only return the complete one
        assert len(files) == 1
        assert 'complete.passkey' in files[0]
        assert 'incomplete.passkey' not in str(files)
    
    def test_discovery_ignores_stash_files(self, temp_fido_home):
        """Test that .stash files are not treated as invalid passkeys"""
        from soft_fido2.passkey_device import AuthenticatorAPI
        
        # Create orphaned .stash file
        stash_path = os.path.join(temp_fido_home, 'orphaned.stash')
        with open(stash_path, 'wb') as f:
            f.write(b'x' * 230)
        
        # Should not raise warnings about .stash files
        files = AuthenticatorAPI._get_passkey_files(temp_fido_home)
        
        # Should return empty list (no valid passkeys)
        assert len(files) == 0


class TestEdgeCases:
    """Tests for edge cases and error conditions"""
    
    def test_empty_filename(self, sample_passkey, temp_fido_home):
        """Test behavior with empty filename - adds .passkey extension"""
        # Empty filename gets .passkey extension added, resulting in '.passkey'
        KeyUtils._save_passkey(
            sample_passkey['key'],
            sample_passkey['x5c'],
            sample_passkey['resCreds'],
            sample_passkey['pinHash'],
            ''
        )
        
        # Should create .passkey and .stash files
        passkey_path = os.path.join(temp_fido_home, '.passkey')
        stash_path = os.path.join(temp_fido_home, '.stash')
        
        assert os.path.exists(passkey_path), "Should create .passkey file"
        assert os.path.exists(stash_path), "Should create .stash file"
        
        # Cleanup
        if os.path.exists(passkey_path):
            os.remove(passkey_path)
        if os.path.exists(stash_path):
            os.remove(stash_path)
    
    def test_special_characters_in_filename(self, sample_passkey, temp_fido_home):
        """Test handling of special characters in filename"""
        # Use safe special characters
        special_filename = 'test-file_123.passkey'
        
        KeyUtils._save_passkey(
            sample_passkey['key'],
            sample_passkey['x5c'],
            sample_passkey['resCreds'],
            sample_passkey['pinHash'],
            special_filename
        )
        
        passkey_path = os.path.join(temp_fido_home, special_filename)
        stash_path = os.path.join(temp_fido_home, 'test-file_123.stash')
        
        assert os.path.exists(passkey_path)
        assert os.path.exists(stash_path)
        
        # Should be able to read back
        read_passkey = getattr(KeyUtils, '_KeyUtils__read_passkey')
        header, body = read_passkey(special_filename)
        assert len(header) == 230
    
    def test_concurrent_file_operations(self, sample_passkey, temp_fido_home):
        """Test that file operations are safe (basic check)"""
        # This is a basic test - full concurrency testing would require threading
        
        # Save
        KeyUtils._save_passkey(
            sample_passkey['key'],
            sample_passkey['x5c'],
            sample_passkey['resCreds'],
            sample_passkey['pinHash'],
            sample_passkey['filename']
        )
        
        # Read multiple times
        read_passkey = getattr(KeyUtils, '_KeyUtils__read_passkey')
        for _ in range(5):
            header, body = read_passkey(sample_passkey['filename'])
            assert len(header) == 230
        
        # Delete
        KeyUtils.delete_passkey(sample_passkey['filename'])
        
        # Verify deleted
        passkey_path = os.path.join(temp_fido_home, sample_passkey['filename'])
        assert not os.path.exists(passkey_path)

# Made with Bob
