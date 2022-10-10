'''
    this is a demo how to use the workspaceip code. 
'''    

from workspaceip import GetPrintSet


nGetPrintSet = GetPrintSet()
sfile = '/home/pi/Python_Code/ipset/ipsettings/printServer.ini'
nGetPrintSet.checkforfile(sfile)