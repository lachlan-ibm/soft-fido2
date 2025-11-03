#!/bin/bash

export HOME=$( realpath . )
python -m build
twine upload --verbose -u $PYPI_API_USER -p $PYPI_API_KEY dist/*
