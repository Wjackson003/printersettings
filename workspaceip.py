
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
'''

__Author__ = "W.T. Jackson III"
__Version__ = "0.1.1" 

from configparser import ConfigParser
#from fileinput import filename
import os.path
import ipaddress
import subprocess
import tkinter as tk
from tkinter import ttk
from tkinter.ttk import *
from turtle import bgcolor

class GetPrintSet:  
          
    def checkforfile(filereceived):
        global filename
        filename = filereceived

        printServer = os.path.exists(filename)
        try:
            if (printServer):
                GetPrintSet.readfile()
            else:
                GetPrintSet.fileDNE()
        except Exception as e:
            print(e)    


    def readfile():
        #to read from a ini file:
    
        configGet = ConfigParser()
        configGet.read(filename) 

        ip = configGet.get('IPINFO', 'ipaddress')
        portNum = configGet.get('IPINFO', 'port')

        if (ip == '0.0.0.0'):
            GetPrintSet.tkwindowset(ip, portNum)


    def fileDNE():

        configfiletext = ConfigParser()
        configfiletext['IPINFO'] = {
            'ipaddress' : '0.0.0.0',
            'port' : '00000'
        }
        with open('/home/pi/Python_Code/ipset/ipsettings/printServer.ini', 'w') as configfile:
            configfiletext.write(configfile)
        
        GetPrintSet.readfile()


    def writeToFile(ip, portNum):

        portNum = str(portNum)

        configSetIp = ConfigParser()

        configSetIp['IPINFO'] = {
            'ipaddress' : ip,
            'port' : portNum
        }

        with open('/home/pi/Python_Code/ipset/ipsettings/printServer.ini', 'w') as configfile:
            configSetIp.write(configfile)

        GetPrintSet.successMessage('IP Settings', 'Your ip settings have been set.')
        exit()


    def checkIpAdd(ip):
        global finalIPadd
        verifyIp = ip
        
        try:
            verifyIp = ipaddress.ip_address(verifyIp)
            print('Valid ip format')
            print(f'Checking ip address {verifyIp} is in network.')
            finalIPadd = GetPrintSet.checkinNet(verifyIp)

        except ValueError:
            GetPrintSet.showerrorMessage('Invalid Format', f'\n{verifyIp} is an invalid format please try again')
            GetPrintSet.tkwindowset('0.0.0.0',portNumEnt1)


    def checkinNet(ipnetworkCheck):
        if ipaddress.ip_address(ipnetworkCheck) in ipaddress.ip_network('192.168.0.0/16'):
            #testing ping
            for ping in range(1,4):
                res = subprocess.call(['ping', '-c', '4', str(ipnetworkCheck)])

                if(res == 0):
                    print(f'ip address {ipnetworkCheck} verified in network')
                    return ipnetworkCheck
                else:
                    GetPrintSet.showerrorMessage('ERROR:Not Local','The ip address is in range but is not a local ip address')
                    GetPrintSet.tkwindowset('0.0.0.0', portNumEnt1)
        else:
            GetPrintSet.showerrorMessage('Not In Network',f'\nThis ip address {ipnetworkCheck} is not in network.')
            GetPrintSet.tkwindowset('0.0.0.0', portNumEnt1)
            return ipnetworkCheck
        
    def checkportNum(portNum):
        isvalidinput = False

        if portNum.isnumeric() == isvalidinput:
            GetPrintSet.showerrorMessage('Invalid Data', 'You may have typed a string please check your entry.')
            GetPrintSet.tkwindowset(finalIPadd,'00000')

        if len(portNum) < 5 or len(portNum) > 5 :
            GetPrintSet.showerrorMessage('Invalid Length', 'Your port number must be 5 numbers.')
            GetPrintSet.tkwindowset(finalIPadd,'00000')
            

        isvalidinput = True

        if isvalidinput:
            GetPrintSet.writeToFile(finalIPadd, portNum)

        #get port of ip address
        '''
        portNum = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        portNum.bind((ip,0))
        portNum = portNum.getsockname()[1]
        print(f'This is your port number: {portNum}')
        '''

        ''' 
        iphost = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        hostname = socket.gethostname()
        ip = socket.gethostbyname(hostname)
        iphost.bind((ip, 0))
        '''

    def showerrorMessage(errTitle, errText):
        errorIpAdd = tk.Tk()
        errorIpAdd.configure(bg='red')
        errorIpAdd.title(errTitle)
        errorIpAdd.geometry("750x100")
        tk.Label(errorIpAdd, bg='red', text=errText,font='Roman 15').pack()
        Button(errorIpAdd, text='Close', command=errorIpAdd.destroy).pack()
        errorIpAdd.mainloop()

    def successMessage(Title, compText):
        compTask = tk.Tk()
        compTask.configure(bg='green')
        compTask.title(Title)
        compTask.geometry("750x100")
        tk.Label(compTask, bg='green', text=compText,font='Roman 15').pack()
        Button(compTask, text='Close', command=compTask.destroy).pack()
        compTask.mainloop()

    def getData(event):
        global ipEntered1 
        global portNumEnt1 

        ipEntered1 = ' '
        portNumEnt1 = ' '

        ipEntered1=ipEntered.get()
        portNumEnt1=portNumEnt.get()

        mainWindow.destroy()

        GetPrintSet.checkIpAdd(ipEntered1)
        GetPrintSet.checkportNum(portNumEnt1)

    def tkwindowset(ip, portNum):
        global mainWindow
        global ipEntered
        global portNumEnt
        
        mainWindow = tk.Tk()
        mainWindow.geometry('475x100')
        mainWindow.title('Printer Settings')
        mainWindow.resizable(0, 0)

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
                portLabel = tk.Label(mainWindow, text= f'Port Number: ')
                portLabel.grid(column=0, row=1,sticky=tk.W, padx=5, pady=5)

                portNumEnt = ttk.Entry(mainWindow)
                portNumEnt.insert(0, portNum)
                portNumEnt.configure(state=tk.DISABLED)
                portNumEnt.grid(column=1, row=1, sticky=tk.E, padx=5, pady=5)

        if ip != '0.0.0.0' :
            ipLabel = tk.Label(mainWindow, text= f'IP Address: ')
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

        submitbutton = ttk.Button(mainWindow, text='Submit', command=GetPrintSet.getData)
        submitbutton.grid(column=1, row=3, sticky=tk.E, padx=5,pady=5)
        
        mainWindow.bind('<Return>',GetPrintSet.getData)

        mainWindow.mainloop()

#if __name__ == "__main__":
#    GetPrintSet.checkforfile()


