import signal
import subprocess
import os
from pathlib import Path
from pexpect import spawn


def execute(cmd):
    ''' run any command and get stdout result as utf-8 string. '''

    # execute command
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    stdout, stderr = p.communicate()
    
    # check status code is ok
    # if it's not, will raise RuntimeError exception
    if p.returncode != 0:
        raise RuntimeError('"{0}" run fails, err={1}'.format(
            cmd, stderr.decode('utf-8', errors='replace')))
    
    # return stdout utf-8 string
    return stdout.decode('utf-8').replace('\r\n', '').replace('\n', '')


class GhidraJythonRepl:
    def __init__(self, ghidra_home=None):
        
        # those paths come from "$GHIDRA_HOME/support/launch.sh"
        # User must define "GHIDRA_HOME" for Ghidra's installation directory
        # i.e. GHIDRA_HOME=/path/to/ghidra_9.1_PUBLIC
        self.INSTALL_DIR = Path(ghidra_home or os.environ['GHIDRA_HOME'])

        self._java_home = None
        self._java_vmargs = None
        
        # build pythonRun commandline
        run_cmd = '{java_home}/bin/java {java_vmargs} -showversion -cp "{utility_jar}" \
ghidra.GhidraLauncher "ghidra.python.PythonRun"'.format(
            java_home=self.java_home,
            java_vmargs=self.java_vmargs,
            utility_jar=self.INSTALL_DIR / 'Ghidra/Framework/Utility/lib/Utility.jar'
        )

        # spawn Ghidra's Jython Interpreter (ghidra.python.PythonRun)
        # this is exactly same as running "pythonRun" script
        self.child = spawn(run_cmd, echo=False, encoding='utf-8')

        self.prompt1 = r'>>> '
        self.prompt2 = r'... '

        # wait for first prompt
        self.child.expect(self.prompt1)
    
    @property
    def java_home(self):
        if self._java_home is None:
            self._java_home = execute('java -cp "{0}" LaunchSupport "{1}" -jdk_home -save'.format(
                self.INSTALL_DIR / 'support/LaunchSupport.jar', self.INSTALL_DIR))
        return self._java_home

    @property
    def java_vmargs(self):
        if self._java_vmargs is None:
            self._java_vmargs = execute('java -cp "{0}" LaunchSupport "{1}" -vmargs'.format(
                self.INSTALL_DIR / 'support/LaunchSupport.jar', self.INSTALL_DIR))
        return self._java_vmargs

    def read_output(self):
        ''' Read current output. '''
        
        result = ''

        # read output, expect echo content
        if self.child.before.splitlines()[1:]:
            out = self.child.before.splitlines()[1:]
            result += '\n'.join([line for line in out if line])
        
        return result
    
    def _repl(self, code):
        self.child.sendline(code)

        # idk why tho, Ghidra's jython interpreter should wait twice
        self.child.expect_exact([self.prompt1, self.prompt2])
        self.child.expect_exact([self.prompt1, self.prompt2])

        return  self.read_output()

    def repl(self, code):
        ''' Ghidra's Jython Interpreter REPL function. '''

        code_lines = code.splitlines()

        # if code has new line, should send ENTER('') at last
        if '\n' in code:
            code_lines.append('')

        result = ''
        
        # REPL each line of code
        for c in code_lines:
            result += self._repl(c)
                
        return result
    
    def kill(self):
        self.child.kill(signal.SIGKILL)