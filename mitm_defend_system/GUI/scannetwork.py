import nmap
import  os,Database_get2insert

nm = nmap.PortScanner()
def pingscan():
    iface = os.popen('ls /sys/class/net/')
    iface = iface.read()
    iface = iface.split()
    script = 'ifconfig %s |grep "inet "|cut -d" " -f10' % iface[0]
    ip = os.popen(script)
    ip = ip.read()
    if len(ip) == 0:
            return None
    ip = ip.strip()
    ip = ip.rstrip('\n')
    print ip
    nm.scan(hosts=ip+ "/24", arguments='-sP')
    hosts_list = [(x, nm[x]['status']['state']) for x in nm.all_hosts()]
    livehost = []
    for host, status in enumerate(hosts_list):
        livehost.append(status[0])
    return livehost
def scanHost():
    ipmacos = []
    livehost = pingscan()
    print livehost
    print('scanning localnet')

    for i, host in enumerate(livehost):
        host =str(host) + "/32"
        nm.scan(host, arguments='-O')
        for h in nm.all_hosts():

            if 'mac' in nm[h]['addresses'] and len(nm[h]['osmatch']) > 0 :
                ipmacos.append([nm[h]['addresses']['ipv4'], nm[h]['addresses']['mac'],
                                nm[h]['osmatch'][0]['osclass'][0]['osfamily']])

            elif 'mac' in nm[h]['addresses']:
                ipmacos.append([nm[h]['addresses']['ipv4'], nm[h]['addresses']['mac'],
                                'null'])
            elif len(nm[h]['osmatch']) > 0:
                ipmacos.append([nm[h]['addresses']['ipv4'],'null',
                                nm[h]['osmatch'][0]['osclass'][0]['osfamily']])
            else:
                ipmacos.append([nm[h]['addresses']['ipv4'], 'null', 'null'])

    return ipmacos

def aliveHost():
    device = Database_get2insert.get_Device2address_list()
    #print device
    result =[]

    for i, host in enumerate(device):
        hostlist = str(host[4]) + "/32"
        nm.scan(hosts=hostlist, arguments='-n -sP -PE -PA')
        hosts_list = [(x, nm[x]['status']['state']) for x in nm.all_hosts()]
        for host, status in enumerate(hosts_list):
                result.append(status)

    return  result

#print scanHost()
#print aliveHost()