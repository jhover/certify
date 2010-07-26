#!/bin/env python
#
# Test.py
#
'''
    Test.py -- Generic unit test runner. Imports all modules in ./test and runs them all. 

'''


import unittest
import os
import re

TESTFILEGLOB="\S*test\S*.py\Z"

testdirfiles= os.listdir("./test")
p = re.compile(TESTFILEGLOB, re.IGNORECASE)

modulestotest=[]

for pyfile in testdirfiles:
    m = p.match(pyfile)
    if m:
        pyfilebase = os.path.basename(pyfile)
        (modname,ext) = os.path.splitext(pyfilebase)
        modulestotest.append(modname)
        
def suite():
    alltests = unittest.TestSuite()
    for module in modulestotest:
        modulePath="%s.%s" % ("test", module)
        aModule = __import__(modulePath, globals(), locals(), [''])
        alltests.addTest(unittest.findTestCases(aModule))
    return alltests

if __name__ == '__main__':
    unittest.main(defaultTest='suite')