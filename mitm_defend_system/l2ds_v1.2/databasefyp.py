__author__ = 'TKS'

import MySQLdb


def getgateway():
    gateway = []
    try:
        db = MySQLdb.connect(host="localhost", user="root", passwd="", db="mydb")
        cursor = db.cursor()

        cursor.execute("select * from default_gateway_table")
        result = cursor.fetchall()

        for i in result:
            gateway.append([i[0], i[1], i[2]])

        db.close()
        return gateway

    except MySQLdb.Error as e:
        print("Error %d: %s" % (e.args[0], e.args[1]))


def getDevice_list():
    return 0


def getlog_list():
    return 0


def getreport_list():
    return 0
