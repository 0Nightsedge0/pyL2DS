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
                   % (p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7])
            print sql
            cursor.execute(sql)
            db.commit()
            print 'HIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII'
        db.close()
    except MySQLdb.Error as e:
        print("Error %d: %s" % (e.args[0], e.args[1]))



def insert_Report():
    return 0


def insert_Gateway():
    return 0


def insert_Device():
    return 0


def get_Gateway():
    gateway = []
    try:
        db = MySQLdb.connect(host="localhost", user="root", passwd="root", db="mydb")
        cursor = db.cursor()

        cursor.execute("select * from Default_Gateway_Table")
        result = cursor.fetchall()

        for i in result:
            gateway.append([i[0], i[1], i[2]])

        db.close()
        return gateway

    except MySQLdb.Error as e:
        print("Error %d: %s" % (e.args[0], e.args[1]))


def get_Device_list():
    device = []
    try:
        db = MySQLdb.connect(host="localhost", user="root", passwd="root", db="mydb")
        cursor = db.cursor()

        cursor.execute("select * from Device_table")
        result = cursor.fetchall()

        for i in result:
            device.append([i[0], i[1], i[2]])

        db.close()
        return device

    except MySQLdb.Error as e:
        print("Error %d: %s" % (e.args[0], e.args[1]))


def get_Log_list():
    logs = []
    try:
        db = MySQLdb.connect(host="localhost", user="root", passwd="root", db="mydb")
        cursor = db.cursor()

        cursor.execute("select * from Logs_Table")
        result = cursor.fetchall()

        for i in result:
            logs.append([i[0], i[1], i[2], i[3], i[4], i[5], i[6], i[7]])

        print "------------------------Logs---------------------------"
        for i in logs:
            print i

        db.close()
        return logs

    except MySQLdb.Error as e:
        print("Error %d: %s" % (e.args[0], e.args[1]))


def get_Report_list():
    report = []
    try:
        db = MySQLdb.connect(host="localhost", user="root", passwd="root", db="mydb")
        cursor = db.cursor()

        cursor.execute("select * from Report_Table")
        result = cursor.fetchall()

        for i in result:
            report.append([i[0], i[1], i[2], i[3], i[4], i[5], i[6], i[7], i[8], i[9]])

        db.close()
        return report

    except MySQLdb.Error as e:
        print("Error %d: %s" % (e.args[0], e.args[1]))