#!/bin/bash

export HOME=$( realpath . )

python setup.py sdist upload -r artifactory
