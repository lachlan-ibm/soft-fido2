#!/bin/bash

export HOME=$( realpath . )

pip install twine wheel

python setup.py sdist bdist_wheel

twine upload - lgleeson@au1.ibm.com -p $ART_API_KEY dist/*
