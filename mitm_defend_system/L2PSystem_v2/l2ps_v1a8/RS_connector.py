import paramiko
import time


def block_port_iface(remote, port):
    port = 'fa0/' + str(port)

    command = 'conf t\n'
    # print command
    remote.send(command)
    time.sleep(0.5)
    command = 'int %s\n' % port
    # print command
    remote.send(command)
    time.sleep(0.5)
    command = 'shutdown\n'
    # print command
    remote.send(command)


def block_port(remote, mac, mactable):
    port = None

    for n in mactable:
        if n[1] == mac:
            port = n[3]

    command = 'conf t\n'
    #print command
    remote.send(command)
    time.sleep(0.5)
    command = 'int %s\n' % port
    #print command
    remote.send(command)
    time.sleep(0.5)
    command = 'shut\n'
    #print command
    remote.send(command)


def open_port(remote, port):

    port = 'fa0/' + str(port)

    command = 'conf t\n'
    #print command
    remote.send(command)
    time.sleep(0.5)
    command = 'int %s\n' % port
    #print command
    remote.send(command)
    time.sleep(0.5)
    command = 'no shut\n'
    #print command
    remote.send(command)


def command_show_mac_address_table(remote):
    command = 'show mac address-table\n'
    result = []

    remote.send(command)
    time.sleep(1)
    output = remote.recv(10000)
    mactable = output.split('\r\n')
    for mac in mactable:
        if 'terminal' not in mac and '-' not in mac and 'Vlan' not in mac and 'Mac Address Table' not in mac and mac and '#' not in mac and 'Total Mac Addresses' not in mac:
            s = mac.split()
            if s[3] != 'CPU':
                s[1] = s[1].replace('.', '')
                s[1] = ':'.join(a+b for a, b in zip(s[1][::2], s[1][1::2]))
                result.append(s)
    #print result
    return result


def command_show_ip_interface_brief(remote):
    command = 'show ip interface brief\n'
    result = []

    remote.send(command)
    time.sleep(1)
    output = remote.recv(10000)
    intbri = output.split('\r\n')
    for interface in intbri:
        if 'Interface' not in interface and 'Vlan' not in interface and 'terminal' not in interface and '#' not in interface and 'Port-channel' not in interface:
            s = interface.split()

            s.pop(2)
            s.pop(2)
            #print s
            result.append(s)
            #print result
            continue
    #print result
    for r in result:
        if r[2] == 'administratively':
            r[2] = r[2] + ' ' + r[3]
            r.pop(3)
    #print result
    return result


def command_show_run(remote):
    command = 'show run\n'
    result = []

    remote.send(command)
    time.sleep(1)
    output = remote.recv(10000)
    run_config = output.split('\r\n')
    for n in range(0, len(run_config)):
        if 'interface' in run_config[n] and 'Port-channel' not in run_config[n] and 'interface Vlan' not in run_config[n]:
            inter = []
            for i in range(n, len(run_config)):
                if '!' in run_config[i]:
                    for j in range(n, i):
                        inter.append(run_config[j])
                    break
            #print inter
            result.append(inter)
    return result


def ssh_mode(remote):
    str = ''
    while str != 'bye':
        str = raw_input()
        remote.send(str + '\n')
        time.sleep(1)
        output = remote.recv(10000)
        print(output)
        remote.send('\n')


def remote_shell(signal, srcmac, int_port):
    ip = '10.20.9.10'
    port = 22
    username = 'SSHadmin'
    password = 'ciscosshpass'

    #print 's:', signal

    remote_conn = paramiko.SSHClient()
    #print remote_conn

    remote_conn.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    #try:
    remote_conn.connect(ip, port=port, username=username, password=password, look_for_keys=False, allow_agent=False)
    #print 'hi'
    remote = remote_conn.invoke_shell()
    output = remote.recv(1000)
    #print 'hi'
    #print output

    ''' no more! '''
    remote.send("terminal length 0\n")

    if signal == 1:
        ip_int_bri = command_show_ip_interface_brief(remote)
        return ip_int_bri
    elif signal == 2:
        mac_table = command_show_mac_address_table(remote)
        return mac_table
    elif signal == 3:
        run_config = command_show_run(remote)
        return run_config
    elif signal == 4:
        mac_table = command_show_mac_address_table(remote)
        block = block_port(remote, srcmac, mac_table)
    elif signal == 5:
        mac_table = command_show_mac_address_table(remote)
        openport = open_port(remote, int_port)
    elif signal == 6:
        ssh_mode(remote)
    elif signal == 7:
        block_port_iface(remote, int_port)

    remote.send("end\n")
    remote.send("exit\n")

    remote.close()
    remote_conn.close()
    #except IOError as error:
     #   return error

#print 'hi'
#remote_shell(1, '', '')

def remote_menu():
    print "--------Layer 2 Prevention System--------"
    print "--------------Remote Shell---------------"
    ip = raw_input("IP address: ")
    port = int(raw_input("Port: "))
    username = raw_input("Username: ")
    password = raw_input("password: ")
