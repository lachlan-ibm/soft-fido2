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
#pytest pqc_tests.py #TODO enable when better supported