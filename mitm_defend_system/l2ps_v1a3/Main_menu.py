__author__ = 'TKS'

import L2PS_v1a3
import Database_get2insert
import Config
import ciscoconnect

from multiprocessing import Process, Queue, Lock
import sys
import os
import time


def consumer(q):
    while True:
        try:
            task = q.get(block=False)
            print "Getter get", task
            print task
            if(task == 's'): break
        except:
            pass
    print "getter finish"


def stop(q, fn):
    sys.stdin = os.fdopen(fn)
    op = raw_input("stop(s)")
    if op == 's':
        q.put(op)
        q.put(op)
        print 'stopper get signal to stop'


def process_con():
    q = Queue()
    l = Lock()
    fn = sys.stdin.fileno()

    ps0 = Process(target=L2PS_v1a3.main, args=(q, l))
    ps1 = Process(target=consumer, args=(q, ))
    ps2 = Process(target=stop, args=(q, fn))

    ps2.start()
    time.sleep(1)
    ps0.start()
    ps1.start()

    ps0.join()
    ps1.join()
    ps2.join()


def clearscr():
    print "\n" * 100


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
    while(checkin is False):

        print "\n--------Layer 2 Prevention System--------\n"
        print "[1] Monitor Network"
        print "[2] View Log"
        print "[3] View Report"
        print "[4] Configuration"
        print "[5] Contect to router/switch"
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
