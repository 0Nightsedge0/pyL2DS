import MySQLdb
import pandas
import matplotlib.pyplot as plt
from bs4 import BeautifulSoup


def main():
    try:
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

        proto_this_month = pandas.read_sql('select DISTINCT Protocol, count(*) from Logs_Table '
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
        print proto_all
        pl = proto_all.T.to_dict('records')
        list_pl = []
        #print pl[0]
        for key, value in pl[0].iteritems():
            #print key, value
            list_pl.append([key, value])
        print list_pl

        print proto_this_month
        print proto_today

        #print detect_attacks_all
        #print detect_attacks_this_month
        #print detect_attacks_today

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

        proto_this_month.plot(kind='pie', subplots=True, figsize=(8, 8))
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
        html = open('HTML/FYP Overview.html')
        soup = BeautifulSoup(html, "lxml")
        for row in soup.find('table').findAll('tr'):
            for col in row.findAll('td'):
                for ul in col.findAll('ul'):
                    for li in ul.findAll('li'):
                        #print li.renderContents()
                        #print li.string

                        if '1:' in li.string:
                            li.string = '1: %8s (%10d)' % (list_pl[0][0], list_pl[0][1])
                        elif '2:' in li.string:
                            li.string = '2: %8s (%10d)' % (list_pl[1][0], list_pl[2][1])
                        elif '3:' in li.string:
                            li.string = '3: %8s (%10d)' % (list_pl[2][0], list_pl[2][1])
                        elif '4:' in li.string:
                            li.string = '4: %8s (%10d)' % (list_pl[3][0], list_pl[3][1])
                        elif '5:' in li.string:
                            li.string = '5: %8s (%10d)' % (list_pl[4][0], list_pl[4][1])
                        elif 'Safe Traffic:' in li.string:
                            li.string = 'Safe Traffic: %d (%2.2f%%)' % (percentage_logs_all[0][1], ((float(percentage_logs_today[0][1])-float(percentage_report_today[0][1]))/float(percentage_logs_today[0][1]) * 100.0))
                        elif 'Attacks:' in li.string:
                            li.string = 'Attacks: %d (%2.2f%%)' % (percentage_report_all[0][1], (float(percentage_report_all[0][1])/float(percentage_logs_all[0][1]) * 100.0))
                        print li

        html = soup.prettify('utf-8')
        with open('HTML/FYP Overview.html', 'wb') as file:
            file.write(html)


        #webbrowser.open("HTML/test_Report.html")

        db_cn.close()
    except:
        print 'report error'

main()
