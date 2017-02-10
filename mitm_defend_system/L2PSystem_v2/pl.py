__author__ = 'root'

import platform, os


def get_my_macaddress(iface):
    import os
    try:
        script = 'ifconfig %s| grep ether| cut -d" " -f10' % iface
        ip = os.popen(script)
        ip = ip.read()
        if len(ip) == 0:
            return None
        ip = ip.strip()
        ip = ip.rstrip('\n')
        print ip
        return ip
    except:
        return None


def get_my_ipaddress(iface):
    import os
    try:
        script = 'ifconfig %s |grep "inet "|cut -d" " -f10' % iface
        ip = os.popen(script)
        ip = ip.read()
        if len(ip) == 0:
                return None
        ip = ip.strip()
        ip = ip.rstrip('\n')
        return ip
    except:
        return None

def col_info():
    iface = os.popen('ls /sys/class/net/')
    iface = iface.read()
    iface = iface.split()
    platf = platform.platform()


    s = 'Current System Information \n'
    s += 'Current OS : %s\n' % platf
    isodd = False

    length = len(iface)
    if length % 2 == 0:
        end = length
    else:
        end = length-1
        isodd = True

    for i in range(0, end, 2):
        striface = '|%-15s |IP address  : %-17s' % (iface[i], get_my_ipaddress(iface[i]))
        striface += '\t'
        striface += '| %-15s |IP address  : %-17s \n' % (iface[i+1], get_my_ipaddress(iface[i+1]))
        striface += '|%-15s |MAC address : %-17s' % (" ", get_my_macaddress(iface[i]))
        striface += '\t'
        striface += '| %-15s |MAC address : %-17s \n' % (" ", get_my_macaddress(iface[i+1]))
    if isodd:
        striface += '|%-15s |IP address  : %-17s\t|\n' % (iface[end], get_my_ipaddress(iface[end]))
        striface += '|%-15s |MAC address : %-17s' % (" ", get_my_macaddress(iface[end]))
        striface += '\t|'
    return s + striface

#print col_info()