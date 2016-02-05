__author__ = 'TKS'

import L2PS_v1a2
import Database
import Database_get2insert
import Config


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
    while(checkin == False):
        print "\n--------Layer 2 Prevention System--------\n"
        print "[1] Monitor Network"
        print "[2] View Log"
        print "[3] View Report"
        print "[4] Configuration"
        print "[9] Exit"
        select = raw_input("\nL2PS  > ")
        if(select == '1'):
            clearscr()
            Config.main('No')
            L2PS_v1a2.main()
        elif(select == '2'):
            clearscr()
            Database_get2insert.get_Log_list()
        elif(select == '3'):
            clearscr()
            Database_get2insert.get_Report_list()
        elif(select == '4'):
            clearscr()
            Config.main('Add')
        elif(select == '9'):
            print "Bye Bye"
            checkin = True
        else:
            print "Input Error.Please try again"



if('__main__' == __name__):
    display_banner()
    display_menu()
