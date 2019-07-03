#!/bin/bash

export HOME=$( realpath . )

pip install twine wheel

python setup.py sdist bdist_wheel

twine upload --verbose --repository-url https://eu.artifactory.swg-devops.com/artifactory/api/pypi/sec-iam-components-pypi-virtual/ -u lgleeson@au1.ibm.com -p $ART_API_KEY dist/*
