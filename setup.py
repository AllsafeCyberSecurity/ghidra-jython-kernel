import ast
import json
import os
import re
import shutil
import sys
from pathlib import Path
from distutils.command.install import install
from tempfile import mkdtemp, TemporaryDirectory

try:
    from setuptools import setup, find_packages
except ImportError:
    from distutils.core import setup, find_packages

MYPACKAGE_ROOT = 'ghidra_jython_kernel'

# kernelspec info
KERNELSPEC_JSON = {
    'argv': [
        sys.executable,
        '-m', 'ghidra_jython_kernel',
        '-f', '{connection_file}'
    ],
    'display_name': 'GhidraJython',
    'language': 'python',
    'name': 'ghidra_jython_kernel'
}

def get_home_dir():
    homedir = os.path.expanduser('~')
    homedir = os.path.realpath(homedir)
    return homedir

def jupyter_config_dir():
    env = os.environ
    home_dir = get_home_dir()

    if env.get('JUPYTER_NO_CONFIG'):
        return Path(mkdtemp(prefix='jupyter-clean-cfg' + '-'))

    if env.get('JUPYTER_CONFIG_DIR'):
        return Path(env['JUPYTER_CONFIG_DIR'])

    return Path(home_dir, '.jupyter')

def get_jupyter_data_dir():
    env = os.environ

    if env.get('JUPYTER_DATA_DIR'):
        return Path(env['JUPYTER_DATA_DIR'])

    home = get_home_dir()

    if sys.platform == 'darwin':
        return Path(home, 'Library', 'Jupyter')
    elif os.name == 'nt':
        appdata = env.get('APPDATA', None)
        if appdata:
            return Path(appdata, 'jupyter')
        else:
            return Path(jupyter_config_dir(), 'data')
    else:
        # Linux, non-OS X Unix, AIX, etc.
        xdg = env.get("XDG_DATA_HOME", None)
        if not xdg:
            xdg = Path(home, '.local', 'share')
        return Path(xdg, 'jupyter')

def install_kernelspec(source_dir, kernel_name):
    source_dir = source_dir.rstrip('/\\')
    if not kernel_name:
        kernel_name = os.path.basename(source_dir)
    kernel_name = kernel_name.lower()

    destination = Path(get_jupyter_data_dir() / 'kernels', kernel_name)

    if destination.is_dir():
        shutil.rmtree(str(destination))

    shutil.copytree(source_dir, str(destination))


class install_with_kernelspec(install):
    def run(self):
        install.run(self)
        with TemporaryDirectory() as td:
            with Path(td, 'kernel.json').open('w') as f:
                json.dump(KERNELSPEC_JSON, f, sort_keys=True)

            kernel_name = KERNELSPEC_JSON['name']
            install_kernelspec(td, kernel_name)


# get version
with open(os.path.join(MYPACKAGE_ROOT, '__init__.py')) as f:
    match = re.search(r'__version__\s+=\s+(.*)', f.read())
version = str(ast.literal_eval(match.group(1)))


def main():
    setup(
        name='ghidra-jython-kernel',
        version='0.0.4',
        description='Jupyter kernel for Ghidra\'s Jython Interpreter',
        author='er28-0652',
        author_email='33626923+er28-0652@users.noreply.github.com',
        license='MIT',
        cmdclass={'install': install_with_kernelspec},
        install_requires=[
            'IPython',
            'ipykernel',
            'jupyter_client',
            'pexpect'
        ],
        packages=find_packages(),
        test_suite='tests'
    )

if __name__ == '__main__':
    main()
