import paramiko
import time

def remote_shell():
    ip = '192.168.0.1'
    port = 22
    username = 'admin'
    password = 'admin'
    print "--------Layer 2 Prevention System--------"
    print "--------------Remote Shell---------------"
    ip = raw_input("IP address: ")
    port = raw_input("Port: ")
    username = raw_input("Username: ")
    password = raw_input("password")

    remote_conn = paramiko.SSHClient()
    print remote_conn

    remote_conn.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    remote_conn.connect(ip, port=port, username=username, password=password, look_for_keys=False, allow_agent=False)
    remote = remote_conn.invoke_shell()
    output = remote.recv(1000)
    print output

    remote.send("\n")
    remote.send("show ip int brief\n")
    time.sleep(2)
    output = remote.recv(10000)
    print output

    while True:
        str = raw_input()
        remote.send(str + '\n')
        time.sleep(1)
        output = remote.recv(10000)
        print(output)

