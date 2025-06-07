from setuptools import find_packages, setup
import os

setup(
    name='soft_fido2',
    version='0.3.%s' % os.environ.get('TRAVIS_BUILD_NUMBER', 0),
    description='Software based FIDO2 Authenticator',
    author='Lachlan Gleeson',
    author_email='lgleeson@au1.ibm.com',
    license='MIT',
    package_dir={"": "python_authenticator"},
    packages=find_packages(where="python_authenticator"),
    install_requires=[
        'cbor2>=4.1.2',
        'cryptography>=38.0.1',
        'asn1>=2.2.0',
        'PyJwt>=0.6.1'
    ],
    url='https://github.com/lachlan-ibm/soft-fido2',
    zip_safe=False
)
