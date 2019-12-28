import ast
import json
import os
import re
import sys
from pathlib import Path
from distutils.command.install import install
from IPython.utils.tempdir import TemporaryDirectory

try:
    from setuptools import setup, find_packages
except ImportError:
    from distutils.core import setup, find_packages

try:
    from jupyter_client.kernelspec import install_kernel_spec
except ImportError:
    from IPython.kernel.kernelspec import install_kernel_spec

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


class install_with_kernelspec(install):
    def run(self):
        install.run(self)
        with TemporaryDirectory() as td:
            with Path(td, 'kernel.json').open('w') as f:
                json.dump(KERNELSPEC_JSON, f, sort_keys=True)

            kernel_name = KERNELSPEC_JSON['name']
            try:
                install_kernel_spec(td, kernel_name, user=True, replace=True)
            except:
                install_kernel_spec(td, kernel_name, user=False, replace=True)


# get version
with open(os.path.join(MYPACKAGE_ROOT, '__init__.py')) as f:
    match = re.search(r'__version__\s+=\s+(.*)', f.read())
version = str(ast.literal_eval(match.group(1)))


def main():
    setup(
        name='ghidra_jython_kernel',
        version=version,
        description='Jupyter kernel for Ghidra\'s Jython Interpreter',
        author='er28-0652',
        license='MIT',
        cmdclass={'install': install_with_kernelspec},
        install_requires=[
            'IPython',
            'jupyter_client'
        ],
        packages=find_packages(),
        test_suite='tests'
    )

if __name__ == '__main__':
    main()
