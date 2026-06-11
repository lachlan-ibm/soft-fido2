#!/bin/bash

set -e

#compile
python setup.py sdist bdist_wheel
#run tests
export PYTHONPATH="$PYTHONPATH:$(pwd)/build/lib"
cd tests
pytest attestation_unit_test.py
pytest assertion_unit_test.py
pytest cred_id_test.py
pytest symmetric_key_test.py
pytest passkey_device_test.py
pytest passkey_file_test.py
pytest credential_recovery_test.py
pytest hash_storage_test.py
pytest cross_app_test.py
pytest hkdf_seed_test.py
pytest kdf_config_test.py
pytest test_ec_key_types.py
pytest tpm_derivation_test.py
pytest pqc_tests.py
