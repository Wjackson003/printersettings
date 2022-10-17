
'''
About:
This program is used to ask the user for a valid input for an ip address and a port number.

version 0.0.1: Sept 18, 2022
    WT - made changes to verify the ip address by creating a seperate method to call it
         if the ip address was a bad format. Created a method to verify that the ipaddress is in 
         network.I also made spelling corrections.
version 0.0.2: Sept 19, 2022
    WT - made corrections to methods to fix the issue with the ip inputs not being stored or seen
         as a string if the ip address was typed in the first time incorrectly.
version 0.1.0: Sept 24, 2022
    WT - made changes if the printserver ini file is not found, it will be created ask the user for
         their ip address and port. If the document is found it will ask for the ip and not the port.
         It will also verify that here is a working ip address by pinging the ip address give from user.
         I also Included the GUI popups if theres an error.  
version 0.1.1: Sept 28, 2022
    WT - fix to issue with the programing stuck in a loop calling the error message. Also added the 
         a Entry box and window for user friendly entry. Also added feature to press Enter to submit your 
         submission.
version 0.2.0: Oct 7, 2022
    WT - made changes so the code would work on python2 and python3. 
Version 0.2.1: Oct 11, 2022
    WT - made change so that the program would check to make sure that the printer was up by tyring to
         connect to the printer and close it. if it does not connect that means the printer is not up and
         running and there may be an error. if the ini file is already set you can still run the program
         to check to make sure the printer is up and running.
Version 0.2.2: Oct 14, 2022
    WT - made changes so the code would check by the hostname to make sure that the that it was or was not
         the same computer then check the ip and perform the tasks needed that way. also fixed an issue where
         the main window would be called again and ask for an ip address. fixed issue with traceback receiving
         an exception.
'''

__Author__ = "W.T. Jackson III"
__Version__ = "0.2.2" 

import sys
import time
import os.path
import os,struct,socket
from configparser import ConfigParser

import colorama
from colorama import Fore

colorama.init(autoreset=True)

import ipaddress
import subprocess

try:
    import tkinter as tk
    from tkinter import ttk
    from tkinter import *
except ImportError:
    import Tkinter as tk 
    import ttk 
    from Tkinter import *     


class GetPrintSet:  

    def getHostName(self):
        configGet = ConfigParser()
        configGet.read(self.filename) 

        ip = configGet.get('IPINFO', 'ipaddress')
        portNum = configGet.get('IPINFO', 'port')
        hostname = configGet.get('IPINFO', 'hostname')
        
        cHostName = socket.gethostname()

        if hostname == '':
            self.tkwindowset(ip, portNum)
        elif hostname == cHostName:
            if(ip == '0.0.0.0'):
                self.tkwindowset(ip, portNum)
            else:
                self.checkServer()
        else:
            if hostname != cHostName:
                self.fileDNE()
           

    def checkforfile(self, filereceived, filename = ' ', finalIPadd= ' ', sPN = 12349):
        self.finalIPadd = finalIPadd
        self.sPN = sPN 
        self.filename = filereceived

        printServer = os.path.exists(self.filename)

        try:
            if (printServer):
                self.getHostName()
            else:
                self.fileDNE()

        except Exception as e:
            print(e)    


    def fileDNE(self):
        configfiletext = ConfigParser()
        configfiletext['IPINFO'] = {
            'ipaddress' : '0.0.0.0',
            'port' : '12349',
            'hostname' : ''
        }
        with open(self.filename, 'w') as configfile:
            configfiletext.write(configfile)

        self.getHostName()


    def writeToFile(self, ip, portNum):
        portNum = str(portNum)

        configInfo = ConfigParser()
        configInfo.read(self.filename)
        hostname = socket.gethostname()

        configInfo['IPINFO'] = {
            'ipaddress' : ip,
            'port' : portNum,
            'hostname' : str(hostname)
        }

        with open(self.filename, 'w') as configfile:
            configInfo.write(configfile)

        print(Fore.GREEN + '\nYOUR PRINTER SETTINGS HAVE BEEN SET!')
        print('\nChecking to see if printer is available.')
        self.checkServer()


    def checkIpAdd(self, ip):
        
        #self.sPN=self.portNumEnt.get()
        self.mainWindow.destroy()

        isV3 = True
        isV2 = False

        try:   
            #for Py3
            ip3 = ipaddress.ip_address(ip)
            print('Valid ip format')
            print('Checking ip address ' + str(ip3) + ' is in network.')
            self.checkInNet(ip3, isV3)


        except ValueError as e:
            e = str(e)
            try: 
                if (' does not appear to be an IPv4 or IPv6 address. Did you pass in a bytes (str in Python 2) instead of a unicode object?') in e: 
                    ip2 = ipaddress.ip_address(ip.decode())
                    print('Valid ip format')
                    print('Checking ip address ' + str(ip2) + ' is in network.')
                    self.checkInNet(ip2, isV2)

                else:
                    print(e) 
                    self.showerrorMessage('Invalid Format', ip + ' is an invalid format please try again')
                    self.tkwindowset('0.0.0.0')
            except ValueError as e:
                print(e)
                self.showerrorMessage('Invalid Format', ip + ' is an invalid format please try again')
                self.tkwindowset('0.0.0.0')


    def checkInNet(self, ipnetworkCheck, py_v):
        if py_v == True:
            ipaddress.ip_address(ipnetworkCheck) in ipaddress.ip_network('192.168.0.0/16')

        elif py_v == False:
            ipaddress.ip_address(ipnetworkCheck) in ipaddress.ip_network(u'192.168.0.0/16')

        else:
            self.showerrorMessage('Not In Network','\nThis ip address ' + str(ipnetworkCheck) + ' is not in network.')
            self.tkwindowset('0.0.0.0')

            #return ipnetworkCheck

        FNULL = open(os.devnull, 'w')

        #testing ping
        for ping in range(1):
            answer = subprocess.call(['ping', '-c', '4', str(ipnetworkCheck)], 
            stdout = FNULL, 
            stderr = subprocess.STDOUT)

        if(answer == 0):
            print('\nIP Address ' + str(ipnetworkCheck) + ' verified in network')
            self.finalIPadd = ipnetworkCheck
            self.writeToFile(self.finalIPadd, self.sPN)

            #return ipnetworkCheck

        else:
            self.showerrorMessage('ERROR:Not Local','The ip address is in range but is not a local ip address')
            self.tkwindowset('0.0.0.0')


    def showerrorMessage(self, errTitle, errText):
        errorIpAdd = tk.Tk()
        errorIpAdd.configure(bg='red')
        errorIpAdd.title(errTitle)
        errorIpAdd.geometry("750x100")
        errorIpAdd.eval('tk::PlaceWindow . center')

        tk.Label(errorIpAdd, bg='red', text=errText,font='Roman 15').pack()
        Button(errorIpAdd, text='Close', command=errorIpAdd.destroy).pack()
        errorIpAdd.mainloop()


    def getData1(self, event):
        self.getData()


    def getData(self):
    
        ipEntered1 = ' '
        ipEntered1=self.ipEntered.get()

        self.checkIpAdd(ipEntered1)
        

    def tkwindowset(self, ip, mainWindow = None, ipEntered = ' ', portNumEnt = ' '):
        self.mainWindow = mainWindow
        self.ipEntered = ipEntered
        self.portNumEnt = portNumEnt
        
        self.mainWindow = tk.Tk()
        self.mainWindow.geometry('475x100')
        self.mainWindow.title('Printer Settings')
        self.mainWindow.resizable(0, 0)
        self.mainWindow.eval('tk::PlaceWindow . center')

        self.mainWindow.columnconfigure(0, weight=1)
        self.mainWindow.columnconfigure(1, weight=3)

        if ip == '0.0.0.0' :
            ipLabel = ttk.Label(self.mainWindow, text= 'Enter IP Address:')
            ipLabel.grid(column=0, row=0, sticky=tk.W, padx=5, pady=5)

            self.ipEntered = ttk.Entry(self.mainWindow)
            self.ipEntered.grid(column=1, row=0, sticky=tk.E, padx=5, pady=5) 

            portLabel = tk.Label(self.mainWindow, text= 'Port Number: ')
            portLabel.grid(column=0, row=1,sticky=tk.W, padx=5, pady=5)

            self.portNumEnt = ttk.Entry(self.mainWindow)
            self.portNumEnt.insert(0, self.sPN)
            self.portNumEnt.configure(state=tk.DISABLED)
            self.portNumEnt.grid(column=1, row=1, sticky=tk.E, padx=5, pady=5)

        submitbutton = ttk.Button(self.mainWindow, text='Submit', command=self.getData)
        submitbutton.grid(column=1, row=3, sticky=tk.E, padx=5,pady=5)
        
        self.mainWindow.bind('<Return>',self.getData1)

        self.mainWindow.mainloop()


    def checkServer(self):
        connection = False

        configGet = ConfigParser()
        configGet.read(self.filename) 

        finalIPadd = configGet.get('IPINFO', 'ipaddress')
        portNum = configGet.get('IPINFO', 'port')
        portNum = int(portNum)

        print('\nTrying to Connect to: ' + finalIPadd)

        while connection == False:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
                s.settimeout(3)

                s.connect((str(finalIPadd), portNum))
                s.send(b'TEST')
                s.close()
                print('\nPrinter Status: ' + Fore.GREEN + 'CONNECTED') 
                print('\nPrinter is ready to be used!')
                
                connection = True        
        
            except Exception:
                self.checkprinterset()
                break
    

    def checkprinterset(self):
        checkprinter = tk.Tk()
        checkprinter.geometry('575x100')
        checkprinter.title('Printer Not Available')
        checkprinter.resizable(0, 0)
        checkprinter.eval('tk::PlaceWindow . center')

        ttk.Label(checkprinter, text='Please check that printer is plugged in and make a selection\n').pack()

        ttk.Button(checkprinter, text='Continue', command=lambda:[checkprinter.destroy(),self.checkServer()]).pack()
        ttk.Button(checkprinter, text='Quit',command=checkprinter.destroy).pack()

        checkprinter.mainloop()


def main():
    try:
        nGetPrintSet = GetPrintSet()
        dirname = os.path.dirname(__file__)
        sfile = os.path.join(dirname, 'printServer.ini')
        nGetPrintSet.checkforfile(sfile)
    except Exception as e:
        print(e)


if __name__ == '__main__':
    main()
