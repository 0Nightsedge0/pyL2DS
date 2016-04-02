import MySQLdb
import pandas
import matplotlib.pyplot as plt
from bs4 import BeautifulSoup
import webbrowser


def main():
    db_cn = MySQLdb.connect(host="localhost", user="root", passwd="root", db="mydb")

    traffic_all = pandas.read_sql('select DateTime,count(*) as Traffic from Logs_Table group by DateTime',
                                  con=db_cn, index_col='DateTime')

    traffic_this_month = pandas.read_sql('select DateTime,count(*) as Traffic from Logs_Table '
                                         'where MONTH(DateTime) = MONTH(CURDATE()) group by Datetime',
                                         con=db_cn, index_col='DateTime')

    traffic_today = pandas.read_sql('select DateTime,count(*) as Traffic from Logs_Table '
                                    'where DATE(DateTime) = CURDATE() group by Datetime',
                                    con=db_cn, index_col='DateTime')

    proto_all = pandas.read_sql('select DISTINCT Protocol, count(*)'
                                'from Logs_Table group by Protocol order by count(*) DESC LIMIT 5',
                                con=db_cn, index_col='Protocol')

    proto_this_monrh = pandas.read_sql('select DISTINCT Protocol, count(*) from Logs_Table '
                                       'where MONTH(DateTime) = MONTH(CURDATE()) group by Protocol order by count(*) DESC LIMIT 5',
                                       con=db_cn, index_col='Protocol')

    proto_today = pandas.read_sql('select DISTINCT Protocol, count(*) from Logs_Table '
                                  'where DATE(DateTime) = CURDATE() group by Protocol order by count(*) DESC LIMIT 5',
                                  con=db_cn, index_col='Protocol')

    #print traffic_all
    #print traffic_today
    #print traffic_this_month
    #print proto_all
    #print proto_this_month
    #print proto_today

    traffic_all.plot()
    plt.title('Traffic graph all')
    plt.savefig('assets/Traffic_log_all.png')

    traffic_this_month.plot()
    plt.title('Traffic graph this month')
    plt.savefig('assets/Traffic_log_this_month.png')

    traffic_today.plot()
    plt.title('Traffic graph today')
    plt.savefig('assets/Traffic_log_today.png')

    proto_all.plot(kind='pie', subplots=True, figsize=(8, 8))
    plt.title('Protocol all')
    plt.savefig('assets/Protocol_log_all.png')

    proto_this_monrh.plot(kind='pie', subplots=True, figsize=(8, 8))
    plt.title('Protocol this month')
    plt.savefig('assets/Protocol_log_this_month.png')

    proto_today.plot(kind='pie', subplots=True, figsize=(8, 8))
    plt.title('Protocol today')
    plt.savefig('assets/Protocol_log_today.png')

    plt.show()
    '''
    html_report = open("assets/test_Report.html", "r").read()
    soup = BeautifulSoup(html_report)
    #print soup.prettify()
    '''
    #webbrowser.open("assets/test_Report.html")

    db_cn.close()