from setuptools import setup, Command
import os

class CleanCommand(Command):
    """Custom clean command to tidy up the project root."""
    user_options = []
    def initialize_options(self):
        pass
    def finalize_options(self):
        pass
    def run(self):
        # Directories to exclude from cleaning
        exclude_dirs = {'.pyenv', '.git'}
        
        for root, dirs, files in os.walk("./", topdown=True):
            # Remove excluded directories from dirs list to prevent os.walk from traversing them
            dirs[:] = [d for d in dirs if d not in exclude_dirs]
            
            for name in files:
                if name.endswith((".pyc", ".tgz", ".whl")):
                    print("remove {}".format(os.path.join(root, name)))
                    os.remove(os.path.join(root, name))
            for name in dirs:
                if name.endswith((".egg-info", "build", "dist", "__pycache__", "html")):
                    print("remove {}".format(os.path.join(root, name)))
                    #os.rmdir(os.path.join(root, name))
                    os.system('rm -vrf {}'.format(os.path.join(root, name)))



# Most configuration is in pyproject.toml
setup(
    version='0.4.%s' % os.environ.get('GITHUB_RUN_NUMBER', 0),
    cmdclass={
        'clean': CleanCommand,
    }
)
