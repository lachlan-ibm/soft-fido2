from setuptools import setup
import os

setup(
    name='fido2_authenticator',
    version='0.1.%s' % os.environ.get('TRAVIS_BUILD_NUMBER', 0),
    description='Software based FIDO2 Authenticator',
    author='Lachlan Gleeson',
    author_email='lgleeson@au1.ibm.com',
    license='MIT',
    packages=['fido2_authenticator'],
    url='https://github.ibm.com/ibm-security/fido2_authenticator',
    zip_safe=False
)
