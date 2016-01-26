__author__ = 'TKS'
import MySQLdb
import os
import sys


def getgateway():
    gateway = []
    try:
        db = MySQLdb.connect(host="localhost", user="root", passwd="root", db="mydb")
        cursor = db.cursor()

        cursor.execute("select * from Default_Gateway_Table1")
        result = cursor.fetchall()

        for i in result:
            gateway.append([i[0], i[1], i[2]])

        db.close()
        return gateway

    except MySQLdb.Error as e:
        print("Error %d: %s" % (e.args[0], e.args[1]))


def getDevice_list():
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


def getlog_list():
    logs = []
    try:
        db = MySQLdb.connect(host="localhost", user="root", passwd="root", db="mydb")
        cursor = db.cursor()

        cursor.execute("select * from Logs_table")
        result = cursor.fetchall()

        for i in result:
            logs.append([i[0], i[1], i[2], i[3], i[4], i[5], i[6], i[7], i[8], i[9]])

        db.close()
        return logs

    except MySQLdb.Error as e:
        print("Error %d: %s" % (e.args[0], e.args[1]))


def getreport_list():
    report = []
    try:
        db = MySQLdb.connect(host="localhost", user="root", passwd="root", db="mydb")
        cursor = db.cursor()

        cursor.execute("select * from Report_table")
        result = cursor.fetchall()

        for i in result:
            report.append([i[0], i[1], i[2], i[3], i[4], i[5], i[6], i[7], i[8], i[9]])

        db.close()
        return report

    except MySQLdb.Error as e:
        print("Error %d: %s" % (e.args[0], e.args[1]))


def table_creating(tablename):
    createsql = {}

    createsql['User'] = {
        "CREATE TABLE IF NOT EXISTS `mydb`.`User` ("
        "  `UID` VARCHAR(10) NOT NULL,"
        "  `Username` VARCHAR(20) NOT NULL,"
        "  `Password` VARCHAR(30) NULL,"
        " PRIMARY KEY (`UID`, `Username`))"
        "ENGINE = InnoDB;"
    }
    createsql['Device_Table'] = {
        "CREATE TABLE IF NOT EXISTS `mydb`.`Device_Table` ("
        "  `Device_ID` VARCHAR(10) NOT NULL,"
        "  `Device_Type` VARCHAR(20) NULL,"
        "  `Device_Name` VARCHAR(60) NULL,"
        " PRIMARY KEY (`Device_ID`))"
        "ENGINE = InnoDB;"
    }
    createsql['Default_Gateway_Table'] = {
        "CREATE TABLE IF NOT EXISTS `mydb`.`Default_Gateway_Table` ("
        "  `Gateway_ID` VARCHAR(5) NOT NULL,"
        "  `Gateway_IP_Address` VARCHAR(16) NULL,"
        "  `Gateway_MAC_Address` VARCHAR(18) NULL,"
        "  `Device_ID` VARCHAR(10) NULL,"
        " PRIMARY KEY (`Gateway_ID`),"
        " CONSTRAINT `Device_ID_DGT_fk`"
        "FOREIGN KEY (`Device_ID`)"
        "REFERENCES `mydb`.`Device_Table` (`Device_ID`))"
        "ENGINE = InnoDB;"
    }
    createsql['IP_MAC_Table'] = {
        "CREATE TABLE IF NOT EXISTS `mydb`.`IP_MAC_Table` ("
        "  `IP_MAC_ID` VARCHAR(10) NOT NULL,"
        "  `IP_address` VARCHAR(16) NULL,"
        "  `MAC_address` VARCHAR(18) NULL,"
        "  `Device_ID` VARCHAR(10) NULL,"
        " PRIMARY KEY (`IP_MAC_ID`),"
        " CONSTRAINT `Device_ID_IP_MAC_TABLE_fk`"
        "FOREIGN KEY (`Device_ID`)"
        "REFERENCES `mydb`.`Device_Table` (`Device_ID`))"
        "ENGINE = InnoDB;"
    }
    createsql['Log2IP'] = {
        "CREATE TABLE IF NOT EXISTS `mydb`.`Log2IP` ("
        "  `IP_MAC_ID` VARCHAR(10) NOT NULL,"
        "  `IP_address` VARCHAR(16) NOT NULL,"
        " PRIMARY KEY (`IP_address`),"
        " CONSTRAINT `IP_MAC_ID_Log2IP_fk`"
        "FOREIGN KEY (`IP_MAC_ID`)"
        "REFERENCES `mydb`.`IP_MAC_Table` (`IP_MAC_ID`)"
        "ON DELETE NO ACTION"
        "ON UPDATE NO ACTION)"
        "ENGINE = InnoDB;"
    }
    createsql['Log2MAC'] = {
        "CREATE TABLE IF NOT EXISTS `mydb`.`Log2MAC` ("
        "  `IP_MAC_ID` VARCHAR(10) NOT NULL,"
        "  `MAC_address` VARCHAR(18) NOT NULL,"
        " PRIMARY KEY (`MAC_address`),"
        " CONSTRAINT `IP_MAC_ID_Log2MAC_fk`"
        "FOREIGN KEY (`IP_MAC_ID`)"
        "REFERENCES `mydb`.`IP_MAC_Table` (`IP_MAC_ID`)"
        "ON DELETE NO ACTION"
        "ON UPDATE NO ACTION)"
        "ENGINE = InnoDB;"
    }
    createsql['Logs_Table'] = {
        "CREATE TABLE IF NOT EXISTS `mydb`.`Logs_Table` ("
        "  `Logs_ID` VARCHAR(10) NOT NULL,"
        "  `DateTime` DATETIME NULL,"
        "  `Packet_Number` INT(100) NULL,"
        "  `Source_IP` VARCHAR(16) NULL,"
        "  `Destination_IP` VARCHAR(16) NULL,"
        "  `Source_MAC` VARCHAR(18) NULL,"
        "  `Destination_MAC` VARCHAR(18) NULL,"
        "  `Protocal` VARCHAR(15) NULL,"
        "  `Data` VARCHAR(500) NULL,"
        " PRIMARY KEY (`Logs_ID`),"
        " CONSTRAINT `IP_Source_Log_fk`"
        "FOREIGN KEY (`Source_IP`)"
        "REFERENCES `mydb`.`Log2IP` (`IP_address`),"
        " CONSTRAINT `IP_Dest_Log_fk`"
        "FOREIGN KEY (`Destination_IP`)"
        "REFERENCES `mydb`.`Log2IP` (`IP_address`)"
        "ON DELETE NO ACTION"
        "ON UPDATE NO ACTION,"
        " CONSTRAINT `MAC_Source_Log_fk`"
        "FOREIGN KEY (`Source_MAC`)"
        "REFERENCES `mydb`.`Log2MAC` (`MAC_address`)"
        "ON DELETE NO ACTION"
        "ON UPDATE NO ACTION,"
        " CONSTRAINT `MAC_Dest_Log_fk`"
        "FOREIGN KEY (`Destination_MAC`)"
        "REFERENCES `mydb`.`Log2MAC` (`MAC_address`)"
        "ON DELETE NO ACTION"
        "ON UPDATE NO ACTION)"
        "ENGINE = InnoDB;"
    }
    createsql['Report2MAC'] = {
        "CREATE TABLE IF NOT EXISTS `mydb`.`Report2MAC` ("
        "  `IP_MAC_ID` VARCHAR(10) NOT NULL,"
        "  `MAC_address` VARCHAR(18) NOT NULL,"
        " PRIMARY KEY (`MAC_address`),"
        " CONSTRAINT `IP_MAC_ID_Report2MAC_fk`"
        "FOREIGN KEY (`IP_MAC_ID`)"
        "REFERENCES `mydb`.`IP_MAC_Table` (`IP_MAC_ID`)"
        "ON DELETE NO ACTION"
        "ON UPDATE NO ACTION)"
        "ENGINE = InnoDB;"
    }
    createsql['Report2IP'] = {
        "CREATE TABLE IF NOT EXISTS `mydb`.`Report2IP` ("
        "  `IP_MAC_ID` VARCHAR(10) NOT NULL,"
        " `IP_address` VARCHAR(16) NOT NULL,"
        " PRIMARY KEY (`IP_address`),"
        " CONSTRAINT `IP_MAC_ID_Report2IP_fk`"
        "FOREIGN KEY (`IP_MAC_ID`)"
        "REFERENCES `mydb`.`IP_MAC_Table` (`IP_MAC_ID`)"
        "ON DELETE NO ACTION"
        "ON UPDATE NO ACTION)"
        "ENGINE = InnoDB;"
    }
    createsql['Report2IP'] = {
        "CREATE TABLE IF NOT EXISTS `mydb`.`Report_Table` ("
        "  `Report_ID` VARCHAR(10) NOT NULL,"
        "  `DateTime` DATETIME NULL,"
        "  `Packet_Number` INT(100) NULL,"
        "  `Source_IP` VARCHAR(16) NULL,"
        "  `Destination_IP` VARCHAR(16) NULL,"
        "  `Source_MAC` VARCHAR(18) NULL,"
        "  `Destination_MAC` VARCHAR(18) NULL,"
        "  `Protocal` VARCHAR(15) NULL,"
        "  `Data` VARCHAR(500) NULL,"
        " PRIMARY KEY (`Report_ID`),"
        "INDEX `MAC_Source_fk_idx` (`Source_MAC` ASC),"
        "INDEX `MAC_Dest_fk_idx` (`Destination_MAC` ASC),"
        "INDEX `IP_Source_fk_idx` (`Source_IP` ASC),"
        "INDEX `IP_Dest_fk_idx` (`Destination_IP` ASC),"
        " CONSTRAINT `MAC_Source_Report_fk`"
        "FOREIGN KEY (`Source_MAC`)"
        "REFERENCES `mydb`.`Report2MAC` (`MAC_address`)"
        "ON DELETE NO ACTION"
        "ON UPDATE NO ACTION,"
        " CONSTRAINT `MAC_Dest_Report_fk`"
        "FOREIGN KEY (`Destination_MAC`)"
        "REFERENCES `mydb`.`Report2MAC` (`MAC_address`)"
        "ON DELETE NO ACTION"
        "ON UPDATE NO ACTION,"
        " CONSTRAINT `IP_Source_Report_fk`"
        "FOREIGN KEY (`Source_IP`)"
        "REFERENCES `mydb`.`Report2IP` (`IP_address`)"
        "ON DELETE NO ACTION"
        "ON UPDATE NO ACTION,"
        " CONSTRAINT `IP_Dest_Report_fk`"
        "FOREIGN KEY (`Destination_IP`)"
        "REFERENCES `mydb`.`Report2IP` (`IP_address`)"
        "ON DELETE NO ACTION"
        "ON UPDATE NO ACTION)"
        "ENGINE = InnoDB;"
    }

    try:
        db = MySQLdb.connect(host="localhost", user="root", passwd="root", db="mydb")
        cursor = db.cursor()

        sqlcommend = createsql[tablename]
        sqlcommend = list(sqlcommend)
        sqlcommend = ' '.join(sqlcommend)

        print sqlcommend
        cursor.execute(sqlcommend)
        cursor.close()
        db.close()
    except MySQLdb.Error as e:
        print("Error %d: %s" % (e.args[0], e.args[1]))


def table_checking(table_name):
    try:
        db = MySQLdb.connect(host="localhost", user="root", passwd="root", db="mydb")
        cursor = db.cursor()

        sqlcommend = "select count(*) from information_schema.tables " \
                     "where table_name = '%s'" % (table_name)
        #print sqlcommend
        cursor.execute(sqlcommend)
        if cursor.fetchone()[0] == 1:
            cursor.close()
            db.close()
            return True
        else:
            cursor.close()
            db.close()
            return False

    except MySQLdb.Error as e:
        print("Error %d: %s" % (e.args[0], e.args[1]))


def table_list_checking():
    checkpointer = 1
    table_list = ['User', 'Device_Table', 'Default_Gateway_Table', 'IP_MAC_Table',
                  'Log2IP', 'Log2MAC', 'Logs_Table', 'Report2IP', 'Report2MAC', 'Report_Table']
    table_exist = [0]*len(table_list)
    for i in range(len(table_exist)):
        table_exist[i] = table_checking(table_list[i])
    print "-------Tables Checking-------"
    for j in range(len(table_exist)):
        #print "%-22s : %-5s" % (table_list[j], table_exist[j])
        if(table_exist[j] == False):
            checkpointer = 0
            print "%-22s [Not Exist]" % (table_list[j])
    if(checkpointer == 1):
        print "Database tables :         OK!"
    else:
        print "Database tables : Creating..."
        for k in range(len(table_exist)):
            if(table_exist[k] == False):
                table_creating(table_list[k])


def create_db(cursor):
    print "Database 'mydb' :   Creating..."
    cursor.execute("create database mydb")
    print "Database 'mydb' :   Existed!"

def check_db_exitst():
    try:
        db = MySQLdb.connect(host="localhost", user="root", passwd="root")
        cursor = db.cursor()
        cursor.execute("SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA WHERE SCHEMA_NAME = 'mydb'")
        results = cursor.fetchone()
        if results[0] > 1:
            print "Database 'mydb' :   Existed!"
            cursor.close()
            db.close()
        else:
            print "Database 'mydb' : not Existed!"
            create_db(cursor)
            cursor.close()
            db.close()
    except MySQLdb.Error, e:
        print "ERROR %d IN CONNECTION: %s" % (e.args[0], e.args[1])


def check_db_on():
    try:
        db = MySQLdb.connect(host="localhost", user="root", passwd="root", db="mydb")
        cursor = db.cursor()
        cursor.execute("SELECT VERSION()")
        results = cursor.fetchone()
        if results:
            cursor.close()
            db.close()
            return True
        else:
            cursor.close()
            db.close()
            return False
    except MySQLdb.Error, e:
        print "ERROR %d IN CONNECTION: %s" % (e.args[0], e.args[1])
    return False


def startmysql():
    choose = 0
    while(choose != 'y' or choose != 'q'):
        choose = raw_input("Please Enter y to start Mysql or Enter q to exit the program: ")
        choose = choose.lower()
        if(choose == 'y'):
            print "Starting Mysql service..."
            os.system("service mysql start")
            return 1
        elif(choose == 'q'):
            print "Exiting!"
            return 0


def dbconfig():
    print "--Configuration of Database--"
    if(check_db_on() == True):
        print "MySQL state     :   Online!"
        #check_db_exitst()
    else:
        sign = startmysql()
        if(check_db_on() == True):
            print "MySQL state     :   Online!"
            #check_db_exitst()
        elif(sign == 0):
            print "Bye Bye!"
            sys.exit()
    check_db_exitst()
    table_list_checking()

if ('__main__'== __name__):
    dbconfig()




