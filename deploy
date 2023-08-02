#!/bin/bash

export HOME=$( realpath . )
python setup.py sdist bdist_wheel
twine upload --verbose --repository-url https://eu.artifactory.swg-devops.com/artifactory/api/pypi/sec-iam-components-pypi-local/ -u $ART_API_USER -p $ART_API_KEY dist/*
