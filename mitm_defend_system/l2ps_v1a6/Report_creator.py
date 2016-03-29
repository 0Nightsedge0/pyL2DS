import MySQLdb
#import pandas
import matplotlib.pyplot as plt
from bs4 import BeautifulSoup
import webbrowser


def main():
    db_cn = MySQLdb.connect(host="localhost", user="root", passwd="root", db="mydb")

    #traffic = pandas.read_sql('select DateTime,count(*) as Traffic from Logs_Table group by DateTime',
    #                          con=db_cn, index_col='DateTime')
    #proto = pandas.read_sql('select DISTINCT Protocol, count(*)'
    #                        'from Logs_Table group by Protocol',
    #                        con=db_cn, index_col='Protocol')

    #print traffic
    #print proto

    #traffic.plot()
    #plt.title('Traffic graph')
    #plt.savefig('assets/Traffic_log.png')

    #proto.plot(kind='pie', subplots=True, figsize=(8, 8))
    #plt.title('Protocol')
    #plt.savefig('assets/Protocol_log.png')

    #plt.show()
    '''
    html_report = open("assets/test_Report.html", "r").read()
    soup = BeautifulSoup(html_report)
    #print soup.prettify()
    '''
    #webbrowser.open("assets/test_Report.html")

    db_cn.close()