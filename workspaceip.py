
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
'''

__Author__ = "W.T. Jackson III"
__Version__ = "0.2.1" 

from configparser import ConfigParser
import colorama
from colorama import Fore
colorama.init(autoreset=True)

import os.path
import ipaddress
import subprocess

import os,struct,socket
import time


try:
    import tkinter as tk
    from tkinter import ttk
    from tkinter import *
except ImportError:
    import Tkinter as tk 
    import ttk 
    from Tkinter import *     

class GetPrintSet:  

    def checkforfile(self, filereceived):
        global filename
        self.filereceived =  filereceived
        filename = self.filereceived

        printServer = os.path.exists(filename)
        try:
            if (printServer):
                self.readfile()
            else:
                self.fileDNE()
        except Exception as e:
            print(e)    


    def readfile(self):
        #to read from a ini file:
        configGet = ConfigParser()
        configGet.read(filename) 

        ip = configGet.get('PRINTERSET', 'ipaddress')
        portNum = configGet.get('PRINTERSET', 'port')

        if (ip == '0.0.0.0' or portNum == '00000'):
            self.tkwindowset(ip, portNum)
            self.checkServer()
        else: 
            self.checkServer()    


    def fileDNE(self):

        configfiletext = ConfigParser()
        configfiletext['PRINTERSET'] = {
            'ipaddress' : '0.0.0.0',
            'port' : '12349'
        }
        with open(filename, 'w') as configfile:
            configfiletext.write(configfile)
        
        self.readfile()


    def writeToFile(self, ip, portNum):

        portNum = str(portNum)

        configSetIp = ConfigParser()

        configSetIp['PRINTERSET'] = {
            'ipaddress' : ip,
            'port' : portNum
        }

        with open(filename, 'w') as configfile:
            configSetIp.write(configfile)

        print(Fore.GREEN + '\nYOUR PRINTER SETTINGS HAVE BEEN SET!')
        print('\nChecking to see if printer is available.')
        


    def checkIpAdd(self, ip):
        global finalIPadd     
        isV3 = True
        isV2 = False

        try:   
            #for Py3
            ip3 = ipaddress.ip_address(ip)
            print('Valid ip format')
            print('Checking ip address ' + str(ip3) + ' is in network.')
            finalIPadd = self.checkinNet(ip3, isV3)

        except ValueError as e:
            e = str(e)
            try: 
                if (' does not appear to be an IPv4 or IPv6 address. Did you pass in a bytes (str in Python 2) instead of a unicode object?') in e: 
                    ip2 = ipaddress.ip_address(ip.decode())
                    print('Valid ip format')
                    print('Checking ip address ' + str(ip2) + ' is in network.')
                    finalIPadd = self.checkinNet(ip2, isV2)
                    return   

                else:
                    print(e) 
                    self.showerrorMessage('Invalid Format', ip + ' is an invalid format please try again')
                    self.tkwindowset('0.0.0.0',portNumEnt1)
            except ValueError as e:
                print(e)
                self.showerrorMessage('Invalid Format', ip + ' is an invalid format please try again')
                self.tkwindowset('0.0.0.0',portNumEnt1)
            self.showerrorMessage('Invalid Format', ip + ' is an invalid format please try again')
            self.tkwindowset('0.0.0.0',portNumEnt1)


    def checkinNet(self, ipnetworkCheck, py_v):
        if py_v == True:
            ipaddress.ip_address(ipnetworkCheck) in ipaddress.ip_network('192.168.0.0/16')

        elif py_v == False:
            ipaddress.ip_address(ipnetworkCheck) in ipaddress.ip_network(u'192.168.0.0/16')

        else:
            self.showerrorMessage('Not In Network','\nThis ip address ' + str(ipnetworkCheck) + ' is not in network.')
            self.tkwindowset('0.0.0.0', portNumEnt1)
            return ipnetworkCheck

        FNULL = open(os.devnull, 'w')

        #testing ping
        for ping in range(1,4):
            answer = subprocess.call(['ping', '-c', '4', str(ipnetworkCheck)], 
            stdout = FNULL, 
            stderr = subprocess.STDOUT)

            if(answer == 0):
                print('\nIP Address ' + str(ipnetworkCheck) + ' verified in network')
                return ipnetworkCheck
            else:
                self.showerrorMessage('ERROR:Not Local','The ip address is in range but is not a local ip address')
                self.tkwindowset('0.0.0.0', portNumEnt1)


        
    def checkportNum(self, portNum):
        isvalidinput = False

        if portNum.isdigit() == isvalidinput:
            self.showerrorMessage('Invalid Data', 'You may have typed a string please check your entry.')
            self.tkwindowset(finalIPadd,'00000')

        if len(portNum) < 5 or len(portNum) > 5 :
            self.showerrorMessage('Invalid Length', 'Your port number must be 5 numbers.')
            self.tkwindowset(finalIPadd,'00000')

        isvalidinput = True

        if isvalidinput:
            self.writeToFile(finalIPadd, portNum)

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
        global ipEntered1 
        global portNumEnt1 

        ipEntered1 = ' '
        portNumEnt1 = ' '

        ipEntered1=ipEntered.get()
        portNumEnt1=portNumEnt.get()

        mainWindow.destroy()

        self.checkIpAdd(ipEntered1)
        self.checkportNum(portNumEnt1)


    def tkwindowset(self, ip, portNum):
        global mainWindow
        global ipEntered
        global portNumEnt
        
        mainWindow = tk.Tk()
        mainWindow.geometry('475x100')
        mainWindow.title('Printer Settings')
        mainWindow.resizable(0, 0)
        mainWindow.eval('tk::PlaceWindow . center')

        mainWindow.columnconfigure(0, weight=1)
        mainWindow.columnconfigure(1, weight=3)

        if ip == '0.0.0.0' :
            ipLabel = ttk.Label(mainWindow, text= 'Enter IP Address:')
            ipLabel.grid(column=0, row=0, sticky=tk.W, padx=5, pady=5)

            ipEntered = ttk.Entry(mainWindow)
            ipEntered.grid(column=1, row=0, sticky=tk.E, padx=5, pady=5) 
            if portNum == '00000':
                portLabel = ttk.Label(mainWindow, text= 'Enter Port Number:')
                portLabel.grid(column=0, row=1, sticky=tk.W, padx=5, pady=5)

                portNumEnt = ttk.Entry(mainWindow)
                portNumEnt.grid(column=1, row=1, sticky=tk.E, padx=5, pady=5)
    
            else:
                portLabel = tk.Label(mainWindow, text= 'Port Number: ')
                portLabel.grid(column=0, row=1,sticky=tk.W, padx=5, pady=5)

                portNumEnt = ttk.Entry(mainWindow)
                portNumEnt.insert(0, portNum)
                portNumEnt.configure(state=tk.DISABLED)
                portNumEnt.grid(column=1, row=1, sticky=tk.E, padx=5, pady=5)

        if ip != '0.0.0.0' :
            ipLabel = tk.Label(mainWindow, text= 'IP Address: ')
            ipLabel.grid(column=0, row=0,sticky=tk.W, padx=5, pady=5)

            ipEntered = ttk.Entry(mainWindow)
            ipEntered.insert(0, ip)
            ipEntered.configure(state=tk.DISABLED)
            ipEntered.grid(column=1, row=0, sticky=tk.E, padx=5, pady=5)

            if portNum == '00000':
                portLabel = ttk.Label(mainWindow, text= 'Enter Port Number:')
                portLabel.grid(column=0, row=1, sticky=tk.W, padx=5, pady=5)

                portNumEnt = ttk.Entry(mainWindow)
                portNumEnt.grid(column=1, row=1, sticky=tk.E, padx=5, pady=5)

        submitbutton = ttk.Button(mainWindow, text='Submit', command=self.getData)
        submitbutton.grid(column=1, row=3, sticky=tk.E, padx=5,pady=5)
        
        mainWindow.bind('<Return>',self.getData1)

        mainWindow.mainloop()

    def checkServer(self):
        connection = False
        attempts = 1

        configGet = ConfigParser()
        configGet.read(filename) 

        finalIPadd = configGet.get('PRINTERSET', 'ipaddress')
        portNum = configGet.get('PRINTERSET', 'port')
        portNum = int(portNum)

        while connection == False:
            if attempts > 4:
                print('\n' + Fore.RED + 'Attempts have been met now exiting!')
                break
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
                s.settimeout(30)

                print('\nTrying to Connect to: ' + finalIPadd)
                s.connect((str(finalIPadd), portNum))

                s.close()
                print('\nPrinter Status: ' + Fore.GREEN + 'CONNECTED') 
                print('\nPrinter is ready to be used!')
    
                connection = True

            except Exception as e:
                print ('\nPrinter Status: ' + str(e))
                print(Fore.YELLOW + 'The printer may not be connected')
                attempts += 1
                time.sleep(5)
 

def main():
    nGetPrintSet = GetPrintSet()
    dirname = os.path.dirname(__file__)
    sfile = os.path.join(dirname, 'printServer.ini')
    nGetPrintSet.checkforfile(sfile)


