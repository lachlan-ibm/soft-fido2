#!/bin/bash

export HOME=$( realpath . )

pip install twine wheel

python setup.py sdist bdist_wheel

twine upload --repository-url https://eu.artifactory.swg-devops.com/artifactory/sec-iam-components-pypi-local/legacy/ -u lgleeson@au1.ibm.com -p $ART_API_KEY dist/*
