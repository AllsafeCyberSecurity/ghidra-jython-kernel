import os
import signal
import subprocess
from pathlib import Path
from pexpect import spawn
from ipykernel.kernelbase import Kernel

from .__init__ import __version__
from ghidra_jython_kernel.repl import GhidraJythonRepl


class GhidraJythonKernel(Kernel):
    implementation = 'Ghidra\'s Jython Kernel'
    implementation_version = __version__
    language = 'jython'
    language_version = '2.7.0'
    language_info = {
        'mimetype': 'text/x-python',
        'name': 'jython',
        'file_extension': '.py',
        'codemirror_mode':{
            'version': 2,
            'name': 'ipython'
        },
        'nbconvert_exporter': 'python',
        'pygments_lexer':'ipython2',
    }
    banner = "GhidraJython Kernel"

    def __init__(self, **kwargs):
        Kernel.__init__(self, **kwargs)

        self.jython = None
        self._init_jython()

    def _init_jython(self):
        ''' Initialize Ghidra's Jython interpreter. '''

        sig = signal.signal(signal.SIGINT, signal.SIG_DFL)
        try:
           self.jython = GhidraJythonRepl()
        finally:
            signal.signal(signal.SIGINT, sig)

    def do_execute(self, code, silent, store_history=True, user_expressions=None, allow_stdin=False):
        if not silent:
            stream_content = {'name': 'stdout', 'text': self.jython.repl(code)}
            self.send_response(self.iopub_socket, 'stream', stream_content)

        return {
            'status': 'ok',
            'execution_count': self.execution_count,
            'payload': [],
            'user_expressions': {}
        }

    def do_shutdown(self, restart):
        self.jython.kill()
        return {
            'status':'ok',
            'restart': restart
        }