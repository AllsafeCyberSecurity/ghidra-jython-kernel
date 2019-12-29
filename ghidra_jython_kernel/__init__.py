from pkg_resources import get_distribution

__version__ = get_distribution('ghidra_jython_kernel').version

from .kernel import *
from .repl import *
