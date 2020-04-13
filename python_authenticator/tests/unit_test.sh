#!/bin/bash

set -e

#compile
pip install -r requirements.txt
python setup.py sdist bdist_wheel
#run tests
export PYTHONPATH="$PYTHONPATH:$(pwd)/build/lib"
cd python_authenticator/tests
python3 attestation_unit_test.py 
python3 assertion_unit_test.py
