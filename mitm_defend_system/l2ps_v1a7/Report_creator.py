import MySQLdb
import pandas
import matplotlib.pyplot as plt
from bs4 import BeautifulSoup


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

    detect_attacks_all = pandas.read_sql('select DateTime,count(*) as Traffic from Report_Table group by DateTime',
                                         con=db_cn, index_col='DateTime')

    detect_attacks_this_month = pandas.read_sql('select DateTime,count(*) as Traffic from Report_Table '
                                                'where MONTH(DateTime) = MONTH(CURDATE()) group by Datetime',
                                                con=db_cn, index_col='DateTime')

    detect_attacks_today = pandas.read_sql('select DateTime,count(*) as Traffic from Report_Table '
                                           'where DATE(DateTime) = CURDATE() group by Datetime',
                                           con=db_cn, index_col='DateTime')

    cursor = db_cn.cursor()
    cursor.execute("select YEAR(DateTime),count(*) as Traffic from Report_Table")
    percentage_report_all = cursor.fetchall()
    cursor.execute("select YEAR(DateTime),count(*) as Traffic from Logs_Table")
    percentage_logs_all = cursor.fetchall()

    cursor.execute("select MONTH(DateTime),count(*) as Traffic from Report_Table "
                   "where MONTH(DateTime) = MONTH(CURDATE())")
    percentage_report_this_month = cursor.fetchall()
    cursor.execute("select MONTH(DateTime),count(*) as Traffic from Logs_Table "
                   "where MONTH(DateTime) = MONTH(CURDATE())")
    percentage_logs_this_month = cursor.fetchall()

    cursor.execute("select DateTime,count(*) as Traffic from Report_Table "
                   "where DATE(DateTime) = CURDATE()")
    percentage_report_today = cursor.fetchall()
    cursor.execute("select DateTime,count(*) as Traffic from Logs_Table "
                   "where DATE(DateTime) = CURDATE()")
    percentage_logs_today = cursor.fetchall()

    #print percentage_report_all[0][0], percentage_report_all[0][1]
    #print percentage_logs_all[0][0], percentage_logs_all[0][1]

    percentage_all = [(float(percentage_report_all[0][1])/float(percentage_logs_all[0][1]) * 100.0),
                      ((float(percentage_logs_all[0][1])-float(percentage_report_all[0][1]))/
                       float(percentage_logs_all[0][1]) * 100.0)]

    #print percentage_all

    #print percentage_report_this_month[0][0], percentage_report_this_month[0][1]
    #print percentage_logs_this_month[0][0], percentage_logs_this_month[0][1]

    percentage_this_month = [(float(percentage_report_this_month[0][1])/float(percentage_logs_this_month[0][1]) * 100.0),
                             ((float(percentage_logs_this_month[0][1])-float(percentage_report_this_month[0][1]))/
                              float(percentage_logs_this_month[0][1]) * 100.0)]
    #print percentage_this_month

    #print percentage_report_today[0][0], percentage_report_today[0][1]
    #print percentage_logs_today[0][0], percentage_logs_today[0][1]

    percentage_today = [(float(percentage_report_today[0][1])/float(percentage_logs_today[0][1]) * 100.0),
                        ((float(percentage_logs_today[0][1])-float(percentage_report_today[0][1]))/
                         float(percentage_logs_today[0][1]) * 100.0)]
    #print percentage_today

    percentage_label = ['Attacks', 'Safe Traffic']
    explode = (0.1, 0)

    #print traffic_all
    #print traffic_today
    #print traffic_this_month
    #print proto_all
    #print proto_this_month
    #print proto_today

    traffic_all.plot()
    #plt.title('Traffic graph all')
    plt.savefig('HTML/GraphPhoto/Traffic_log_all.png')

    traffic_this_month.plot()
    #plt.title('Traffic graph this month')
    plt.savefig('HTML/GraphPhoto/Traffic_log_this_month.png')

    traffic_today.plot()
    #plt.title('Traffic graph today')
    plt.savefig('HTML/GraphPhoto/Traffic_log_today.png')

    #plt.show()
    plt.clf()

    proto_all.plot(kind='pie', subplots=True, figsize=(8, 8))
    #plt.title('Protocol all')
    plt.savefig('HTML/GraphPhoto/Protocol_log_all.png')

    proto_this_monrh.plot(kind='pie', subplots=True, figsize=(8, 8))
    #plt.title('Protocol this month')
    plt.savefig('HTML/GraphPhoto/Protocol_log_this_month.png')

    proto_today.plot(kind='pie', subplots=True, figsize=(8, 8))
    #plt.title('Protocol today')
    plt.savefig('HTML/GraphPhoto/Protocol_log_today.png')

    #plt.show()
    plt.clf()

    detect_attacks_all.plot()
    #plt.title('Detect attacks all')
    plt.savefig('HTML/GraphPhoto/Detect_attacks_all.png')

    detect_attacks_this_month.plot()
    #plt.title('Detect attacks this month')
    plt.savefig('HTML/GraphPhoto/Detect_attacks_this_month.png')

    detect_attacks_today.plot()
    #plt.title('Detect attacks today')
    plt.savefig('HTML/GraphPhoto/Detect_attacks_today.png')

    #plt.show()
    plt.clf()

    plt.figure(figsize=(8, 8))
    plt.pie(percentage_all, explode=explode, labels=percentage_label, labeldistance=1.05, autopct='%2.2f%%',
            startangle=-45, pctdistance=0.6, shadow=False)
    #plt.title('Attacks / Traffic ALL', bbox={'facecolor':'0.6','pad':1})
    plt.tight_layout()
    plt.axis('equal')
    plt.tight_layout(pad=8)
    plt.legend(loc=9, bbox_to_anchor=(0.5, -0.1))
    plt.savefig('HTML/GraphPhoto/Attack_per_Traffic_all.png')

    plt.figure(figsize=(8, 8))
    plt.pie(percentage_this_month, explode=explode, labels=percentage_label, labeldistance=1.05, autopct='%2.2f%%',
            startangle=-45, pctdistance=0.6, shadow=False)
    #plt.title('Attacks / Traffic this month', bbox={'facecolor':'0.6','pad':1})
    plt.tight_layout()
    plt.axis('equal')
    plt.tight_layout(pad=8)
    plt.legend(loc=9, bbox_to_anchor=(0.5, -0.1))
    plt.savefig('HTML/GraphPhoto/Attack_per_Traffic_this_month.png')

    plt.figure(figsize=(8, 8))
    plt.pie(percentage_today, explode=explode, labels=percentage_label, labeldistance=1.05, autopct='%2.2f%%',
            startangle=-45, pctdistance=0.6, shadow=False)
    #plt.title('Attacks / Traffic', bbox={'facecolor':'0.6','pad':1})
    plt.tight_layout()
    plt.axis('equal')
    plt.tight_layout(pad=8)
    plt.legend(loc=9, bbox_to_anchor=(0.5, -0.1))
    plt.savefig('HTML/GraphPhoto/Attack_per_Traffic_today.png')

    #plt.show()

    #webbrowser.open("HTML/test_Report.html")

    db_cn.close()