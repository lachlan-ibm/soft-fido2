#!/bin/bash

export HOME=$( realpath . )

pip install twine wheel

python setup.py sdist bdist_wheel upload -r artifactory

#twine upload --verbose --repository-url https://eu.artifactory.swg-devops.com --repository /artifactory/sec-iam-components-pypi-virtual -u lgleeson@au1.ibm.com -p $ART_API_KEY dist/*
