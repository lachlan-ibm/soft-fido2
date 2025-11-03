from setuptools import setup, Command
import os

from pathlib import Path
this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text()

class CleanCommand(Command):
    """Custom clean command to tidy up the project root."""
    user_options = []
    def initialize_options(self):
        pass
    def finalize_options(self):
        pass
    def run(self):
        for root, dirs, files in os.walk("./", topdown=False):
            for name in files:
                if name.endswith((".pyc", ".tgz", ".whl")):
                    print("remove {}".format(os.path.join(root, name)))
                    os.remove(os.path.join(root, name))
            for name in dirs:
                if name.endswith((".egg-info", "build", "dist", "__pycache__", "html")):
                    print("remove {}".format(os.path.join(root, name)))
                    #os.rmdir(os.path.join(root, name))
                    os.system('rm -vrf {}'.format(os.path.join(root, name)))


BUILD_ID = os.environ.get('TRAVIS_BUILD_NUMBER', 0)
if BUILD_ID == 0:
    BUILD_ID = os.environ.get('GITHUB_RUN_NUMBER', 0)

setup(
    name='soft_fido2',
    version='0.3.%s' % BUILD_ID,
    description='Software FIDO2 Passkey Authenticator',
    author='Lachlan Gleeson',
    author_email='lgleeson@au1.ibm.com',
    license='MIT',
    packages=["soft_fido2"],
    install_requires=[
        'cbor2>=4.1.2',
        'cryptography>=38.0.1',
        'asn1>=2.2.0',
        'PyJwt>=0.6.1'
        #'liboqs-python' #TODO use cryptography bindings for pqc
    ],
    url='https://github.com/lachlan-ibm/soft-fido2',
    project_urls={
        'Homepage': 'https://github.com/lachlan-ibm/soft-fido2',
        'Documentation': 'https://github.com/lachlan-ibm/soft-fido2/README.md',
        'Source': 'https://github.com/lachlan-ibm/soft-fido2',
        'Tracker': 'https://github.com/lachlan-ibm/soft-fido2/issues'
    },
    zip_safe=False,
        cmdclass={
        'clean': CleanCommand,
    },
    long_description=long_description,
    long_description_content_type='text/markdown'
)
