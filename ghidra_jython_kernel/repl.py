import signal
import subprocess
import os
import hashlib
import re
import time

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

        # those paths come from "$GHIDRA_INSTALL_DIR/support/launch.sh"
        # User must define "GHIDRA_INSTALL_DIR" for Ghidra's installation directory
        # i.e. GHIDRA_INSTALL_DIR=/path/to/ghidra_9.1_PUBLIC
        self.INSTALL_DIR = Path(ghidra_home or os.environ['GHIDRA_INSTALL_DIR'])

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
        self.child.expect('>>> ')
        self.inital_msg = self.child.before

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

    def repl(self, code):
        ''' Ghidra's Jython Interpreter REPL function. '''

        file = open("/tmp/loglog","w+")

        # We could escape only key chars for efficiency, but brute force is safer and easier
        # e.g., "do_code()" => exec('\\x64\\x6f\\x5f\\x63\\x6f\\x64\\x65\\x28\\x29')
        hex_escaped_code = "exec('{}')".format(''.join(['\\x{:02x}'.format(ord(c)) for c in code]))


        # Insert some unique line to signify completion, this should run
        # eventually, even in any exceptional cases.
        flag = hashlib.md5(str(time.time()).encode("ascii")).hexdigest()
        completed_cmd = "print('# comp'+'lete {}')".format(flag) # plus sign injected so terminal echo wont match expect pattern

        # Run command
        self.child.before = None
        self.child.after = None
        self.child.sendline(hex_escaped_code + "\n" + completed_cmd)

        file.write("sending => {}\n".format(hex_escaped_code + "\n" + completed_cmd))

        file.write("calling expect\n")

        # Wait for completion
        exp = re.compile("# complete {}".format(flag))
        self.child.expect([exp], timeout=1000*1000*1000)

        
        # Return everything that's fit to print
        result = self.child.before

        file.write("raw result = {}\n".format(result))

        # filter all control chars except newline and tab
        ccfiltered = re.sub(r'[\x00-\x08\x0b-\x1F]+', '', result)
        exp = re.compile('^(>>> )+(exec|print).*$', re.MULTILINE)
        metafiltered = re.sub(exp, '', ccfiltered)
        filtered = re.sub(r'# complete [0-9a-f]{32}\n','',metafiltered)

        file.write("processed result = {}\n".format(filtered))

        file.close()

        return filtered

    def kill(self):
        self.child.kill(signal.SIGKILL)

