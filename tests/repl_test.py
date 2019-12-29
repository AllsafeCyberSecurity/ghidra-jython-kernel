import unittest
from ghidra_jython_kernel.repl import GhidraJythonRepl

TEST_CASES = {
    # test case 1
    '1 + 1': '2',
    
    # test case 3
    'print("tesuya")': 'tesuya',

    # test case 3 (nested)
    '''
for i in range(10): 
    if i % 2 == 0: 
        print(i, 'foo') 
    else: 
        print(i, 'bar') 
''': "(0, 'foo')\n(1, 'bar')\n(2, 'foo')\n(3, 'bar')\n(4, 'foo')\n(5, 'bar')\n(6, 'foo')\n(7, 'bar')\n(8, 'foo')\n(9, 'bar')",
    
    # test case 4 (define function)
    '''
def echo(what): 
    print(what)

echo("tesuya") 
''' : 'tesuya'

}


class TestGhidraJythonRepl(unittest.TestCase):
    def setUp(self):
        self.jython = GhidraJythonRepl()

    def test_repl(self):
        for test, expect in TEST_CASES.items():
            ret = self.jython.repl(test)
            self.assertEqual(ret, expect)
