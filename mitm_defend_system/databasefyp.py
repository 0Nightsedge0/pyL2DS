import MySQLdb


def getgateway():
    global gateway

    try:
        db = MySQLdb.connect(host="localhost", user="root", passwd="", db="fyp")
        cursor = db.cursor()

        cursor.execute("select * from defaultgatewaytable")
        result = cursor.fetchall()

        for i in result:
            gateway.append([i[0], i[1]])

        db.close()
        return gateway

    except MySQLdb.Error as e:
        print("Error %d: %s" % (e.args[0], e.args[1]))