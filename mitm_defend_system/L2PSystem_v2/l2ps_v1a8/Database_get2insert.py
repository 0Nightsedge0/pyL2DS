__author__ = 'TKS'
import MySQLdb


def insert_Log(pkt):
    try:
        db = MySQLdb.connect(host="localhost", user="root", passwd="root", db="mydb")
        cursor = db.cursor()
        for p in pkt:
            #print p
            sql = "insert into Logs_Table(Logs_ID,Datetime,Source_IP,Destination_IP,Source_MAC"
            sql += ",Destination_MAC,Protocol,Data) values('%s','%s','%s','%s','%s','%s','%s','%s')" \
                   % ('l'+p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7])
            #print sql
            cursor.execute(sql)
            db.commit()
        db.close()
    except MySQLdb.Error as e:
        return "Error %d: %s" % (e.args[0], e.args[1])


def insert_Report(pkt):
    try:
        db = MySQLdb.connect(host="localhost", user="root", passwd="root", db="mydb")
        cursor = db.cursor()
        #print pkt
        sql = "insert into Report_Table(Report_ID,Datetime,Source_IP,Destination_IP,Source_MAC"
        sql += ",Destination_MAC,Protocol,Data) values('%s','%s','%s','%s','%s','%s','%s','%s')" \
               % ('r'+pkt[0], pkt[1], pkt[2], pkt[3], pkt[4], pkt[5], pkt[6], pkt[7])
        #print sql
        cursor.execute(sql)
        db.commit()
        db.close()
    except MySQLdb.Error as e:
        return "Error %d: %s" % (e.args[0], e.args[1])


def insert_Gateway(gateway_ip, gateway_mac):
    try:
        db = MySQLdb.connect(host="localhost", user="root", passwd="root", db="mydb")
        cursor = db.cursor()

        sql ="Insert into Default_Gateway_Table(Gateway_IP_Address,Gateway_MAC_Address) " \
             "values('%s','%s')" % (gateway_ip, gateway_mac)
        #print sql
        cursor.execute(sql)
        db.commit()
        db.close()
        return "Query OK"
    except MySQLdb.Error as e:
        return "Error %d: %s" % (e.args[0], e.args[1])


def insert_Device(device_id, device_type, device_name, gateway_ip):
    try:
        db = MySQLdb.connect(host="localhost", user="root", passwd="root", db="mydb")
        cursor = db.cursor()
        sql = "Insert into Device_Table(Device_ID,Device_Type,Device_Name,Gateway_IP) " \
              "values('%s','%s','%s','%s')" % (device_id, device_type, device_name, gateway_ip)
        #print sql
        cursor.execute(sql)
        db.commit()
        db.close()
        return "Query OK"
    except MySQLdb.Error as e:
        return "Error %d: %s" % (e.args[0], e.args[1])


def insert_IPMAC(IPMAC_ID, IP, MAC, Device_id):
    try:
        db = MySQLdb.connect(host="localhost", user="root", passwd="root", db="mydb")
        cursor = db.cursor()
        sql = "Insert into IP_MAC_Table(IP_MAC_ID,IP_address,MAC_address,Device_ID) " \
              "values('%s','%s','%s','%s');" % (IPMAC_ID, IP, MAC, Device_id)
        #print sql
        cursor.execute(sql)
        db.commit()
        db.close()
        return "Query OK"
    except MySQLdb.Error as e:
        return "Error %d: %s" % (e.args[0], e.args[1])


def get_Gateway():
    gateway = []
    try:
        db = MySQLdb.connect(host="localhost", user="root", passwd="root", db="mydb")
        cursor = db.cursor()

        cursor.execute("select * from Default_Gateway_Table")
        result = cursor.fetchall()

        for i in result:
            gateway.append([i[0], i[1]])

        db.close()
        return gateway

    except MySQLdb.Error as e:
        return "Error %d: %s" % (e.args[0], e.args[1])


def get_last_Device():
    try:
        db = MySQLdb.connect(host="localhost", user="root", passwd="root", db="mydb")
        cursor = db.cursor()
        cursor.execute("select * from Device_Table order by Device_ID DESC LIMIT 1")
        result = cursor.fetchall()
        return result
    except MySQLdb.Error as e:
        return "Error %d: %s" % (e.args[0], e.args[1])


def get_last_IMT():
    try:
        db = MySQLdb.connect(host="localhost", user="root", passwd="root", db="mydb")
        cursor = db.cursor()
        cursor.execute("select * from IP_MAC_Table order by IP_MAC_ID DESC LIMIT 1")
        result = cursor.fetchall()
        return result
    except MySQLdb.Error as e:
        return "Error %d: %s" % (e.args[0], e.args[1])


def get_Device2address_list():
    device = []
    try:
        db = MySQLdb.connect(host="localhost", user="root", passwd="root", db="mydb")
        cursor = db.cursor()

        sql = "select IMT.IP_MAC_ID, IMT.Device_ID, DT.Device_Name, DT.Device_Type, IMT.IP_address, IMT.MAC_address, DT.Gateway_IP "
        sql += "from Device_Table DT, IP_MAC_Table IMT where DT.Device_ID = IMT.Device_ID"

        cursor.execute(sql)
        result = cursor.fetchall()

        for i in result:
            device.append([i[0], i[1], i[2], i[3], i[4], i[5], i[6]])

        db.close()
        return device

    except MySQLdb.Error as e:
        return "Error %d: %s" % (e.args[0], e.args[1])


def get_Log_list():
    logs = []
    try:
        db = MySQLdb.connect(host="localhost", user="root", passwd="root", db="mydb")
        cursor = db.cursor()

        cursor.execute("select * from Logs_Table")
        result = cursor.fetchall()

        #print result

        for i in result:
            #print i
            logs.append([i[0], i[1], i[2], i[3], i[4], i[5], i[6], i[7]])
        '''
        print "------------------------Logs---------------------------"
        for i in logs:
            print i
        '''
        db.close()
        return logs

    except MySQLdb.Error as e:
        return "Error %d: %s" % (e.args[0], e.args[1])


def get_Report_list():
    report = []
    try:
        db = MySQLdb.connect(host="localhost", user="root", passwd="root", db="mydb")
        cursor = db.cursor()

        cursor.execute("select * from Report_Table")
        result = cursor.fetchall()


        for i in result:
            report.append([i[0], i[1], i[2], i[3], i[4], i[5], i[6], i[7]])
        '''
        print "------------------------Logs---------------------------"
        for i in report:
            print i
        '''
        db.close()
        return report

    except MySQLdb.Error as e:
        return "Error %d: %s" % (e.args[0], e.args[1])
