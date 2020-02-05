#!/bin/bash

set -e

#compile
python setup.py sdist bdist_wheel

#run tests
PYTHONPATH="$PYTHONPATH:./build/lib" python3 attestation_unit_test.py 
PYTHONPATH="$PYTHONPATH:./build/lib" python3 assertion_unit_test.py
