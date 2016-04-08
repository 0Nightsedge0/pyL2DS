import paramiko
import time


def block_port(remote):
    return 0


def command_show_mac_address_table(remote):
    command = 'show mac address table\n'
    result = []

    remote.send(command)
    time.sleep(1)
    output = remote.recv(10000)
    config = output.split('\r\n')
    for line in config:
        result.append(line)
    output = None
    return result


def command_show_ip_interface_brief(remote):
    command = 'show ip interface brief\n'
    result = []

    remote.send(command)
    time.sleep(1)
    output = remote.recv(10000)
    intbri = output.split('\r\n')
    for interface in intbri:
        if 'Interface' not in int and 'Vlan' not in int and 'terminal' not in int:
            s = interface.split()
            s.pop(2)
            s.pop(2)
            result.append(s)
            continue
    output = None
    return result


def command_show_run(remote):
    command = 'show run\n'
    result = []

    remote.send(command)
    time.sleep(1)
    output = remote.recv(10000)
    config = output.split('\r\n')
    for line in config:
        result.append(line)
    output = None
    return result


def command_show_run(remote):
    command = 'show run\n'
    result = []

    remote.send(command)
    time.sleep(1)
    output = remote.recv(10000)
    config = output.split('\r\n')
    for line in config:
        result.append(line)
    output = None
    return result


def ssh_mode(remote):
    while str == 'bye':
        str = raw_input()
        remote.send(str + '\n')
        time.sleep(1)
        output = remote.recv(10000)
        print(output)
        remote.send('\n')


def remote_shell():
    ip = '192.168.0.1'
    port = 22
    username = 'cisco'
    password = 'cisco'
    print "--------Layer 2 Prevention System--------"
    print "--------------Remote Shell---------------"
    #ip = raw_input("IP address: ")
    #port = int(raw_input("Port: "))
    #username = raw_input("Username: ")
    #password = raw_input("password: ")

    remote_conn = paramiko.SSHClient()
    #print remote_conn

    remote_conn.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    remote_conn.connect(ip, port=port, username=username, password=password, look_for_keys=False, allow_agent=False)
    remote = remote_conn.invoke_shell()
    output = remote.recv(1000)
    #print output

    ''' no more! '''
    remote.send("terminal length 0\n")

    remote.close()


#remote_shell()