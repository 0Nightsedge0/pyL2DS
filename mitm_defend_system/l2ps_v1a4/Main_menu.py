__author__ = 'TKS'
'''internal modules'''
import L2PS_v1a4
import Database_get2insert
import Config
import ciscoconnect
'''external modules''' '''build-in or download'''
from multiprocessing import Process, Queue, Lock, Pool, Manager
import sys
import os
import time


def displaycounting(pname, countpers, total):
    print "Number of %6s packets per second: %5d  | " % (pname, countpers),
    print "     Total %6s packets: %5d" % (pname, total)


def optimer(operation_times):
    if(operation_times < 60):
        return "00:00:%02d" % operation_times
    elif(operation_times > 60 and operation_times < 3600):
        return "00:%02d:%02d" % (operation_times/60, operation_times % 60)
    elif(operation_times > 3600 and operation_times < 86400):
        s = operation_times % 60
        h = operation_times / 3600
        m = operation_times / 60 - h * 60
        return "%02:%02d:%02d" % (h, m, s)
    else:
        s = operation_times % 60
        d = operation_times / 86400
        h = operation_times / 3600 - d * 24
        m = operation_times / 60 - h * 60
        return "%d day:%02d:%02d:%02d" % (d, h, m, s)


def Displayer(q, q2, q3):
    while True:
        try:
            task = q.get(block=False)
            #print "Getter get", task
            timer = optimer(task[9])
            print "-------------------Now data and time : %s --------------------" % (task[10])
            print "-------------------------Operation times : %s----------------------------" % (timer)
            displaycounting('ARP', task[0], task[1])
            displaycounting('ICMP', task[2], task[3])
            displaycounting('DHCP', task[4], task[5])
            displaycounting('DNS', task[6], task[7])
            print "---->> Network Traffic : %6d \n" % task[8]
            if(q2.qsize() > 0):
                for i in range(q2.qsize()):
                    print "Warning No : %04d" % i
                    alert = q2.get(block=False)
                    print alert
        except:
            pass

        try:
            signal = q3.get(block=False)
            if(signal == 's'):
                break
        except:
            pass
    #print "getter finish"


def stop(q, fn, l3):
    sys.stdin = os.fdopen(fn)
    op = raw_input("****You can press (s) to stop****\n")
    if op == 's':
        l3.acquire()
        q.put(op)
        q.put(op)
        l3.release()
        print 'Warning : Stopper get signal'


def cinterface():
    iface = os.popen('ls /sys/class/net/')
    iface = iface.read()
    iface = iface.split()
    print "####Please select your SPAN interface####"
    for i in range(len(iface)):
        print "number %d : %s" % (i, iface[i])
    while True:
        select = int(raw_input("interface (number) > "))
        if (select >= 0 and select <= len(iface)-1):
            print "You selected ", iface[select]
            time.sleep(3)
            return iface[select]
        else:
            print "Input error please try again"


def process_con():
    iface = cinterface()
    time.sleep(1)

    manager = Manager()
    manager2 = Manager()
    manager3 = Manager()

    q = manager.Queue()
    q2 = manager2.Queue()
    q3 = manager3.Queue()

    l = manager.Lock()
    l2 = manager2.Lock()
    l3 = manager3.Lock()
    fn = sys.stdin.fileno()

    ps0 = Process(target=L2PS_v1a4.main, args=(q, l, iface, q2, l2, q3))
    ps1 = Process(target=Displayer, args=(q, q2, q3))
    ps2 = Process(target=stop, args=(q3, fn, l3))

    ps2.start()
    time.sleep(0.5)
    ps0.start()
    ps1.start()

    ps0.join()
    ps1.join()
    ps2.join()


def clearscr():
    print "\n" * 50


def display_banner():
    s = "##                                       ##" + "\n"
    s += "##                     `@@@,             ##" + "\n"
    s += "##     @       `@@@   ;@@`  .@  @@@@@    ##" + "\n"
    s += "##     @      '@: @,    @    @ @;   @    ##" + "\n"
    s += "##    .@      '   @'   :;  `@, @         ##" + "\n"
    s += "##    @@          @    @. @@`  @@.       ##" + "\n"
    s += "##    @.         @`    @@@,     .@@@     ##" + "\n"
    s += "##    @        :@      @           @'    ##" + "\n"
    s += "##    @  .:@  @@@@@@'  @           @`    ##" + "\n"
    s += "##    @@@@@@ @@`  .@,  @      :@@@@`     ##" + "\n"
    s += "##                                       ##"

    print "###########################################"
    print(s)
    print "###########################################"


def display_menu():
    checkin = False
    while checkin is False:

        print "\n--------Layer 2 Prevention System--------\n"
        print "[1] Monitor Network"
        print "[2] View Log"
        print "[3] View Report"
        print "[4] Configuration"
        print "[5] Connect to router/switch"
        print "[9] Exit"

        select = raw_input("\nL2PS  > ")
        if(select == '1'):
            clearscr()
            Config.main('No')
            process_con()
        elif(select == '2'):
            clearscr()
            Database_get2insert.get_Log_list()
        elif(select == '3'):
            clearscr()
            Database_get2insert.get_Report_list()
        elif(select == '4'):
            clearscr()
            Config.main('Add')
        elif(select == '5'):
            clearscr()
            ciscoconnect.remote_shell()
        elif(select == '9'):
            print "Bye Bye"
            checkin = True
        else:
            print "Input Error.Please try again"


if('__main__' == __name__):
    display_banner()
    display_menu()
