'''
    this is a demo how to use the workspaceip code. 

    version 0.1.0 Oct 10, 2022: changes made for relative path to be found versus an absolute path
'''    
__Author__ = "W.T. Jackson III"
__Version__ = "0.1.0"

from workspaceip import GetPrintSet
import os


nGetPrintSet = GetPrintSet()
dirname = os.path.dirname(__file__)
sfile = os.path.join(dirname, 'printServer.ini')
nGetPrintSet.checkforfile(sfile)