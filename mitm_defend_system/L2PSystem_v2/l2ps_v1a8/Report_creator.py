import Database_get2insert

import MySQLdb
import pandas
import matplotlib.pyplot as plt
from bs4 import BeautifulSoup


def sql2table(table):
    table_script = []
    table_script.append('<table border="1">\n')

    table_script.append('<tr>\n')

    if table == 'Device':
        result = Database_get2insert.get_Device2address_list()
        table_script.append('<td>IP MAC Table ID</td>\n')
        table_script.append('<td>Device Table ID</td>\n')
        table_script.append('<td>Device Name</td>\n')
        table_script.append('<td>Device Type</td>\n')
        table_script.append('<td>Device IP address</td>\n')
        table_script.append('<td>Device MAC address</td>\n')
    if table == 'Log':
        result = Database_get2insert.get_Log_list()
        table_script.append('<td>Log ID</td>\n')
        table_script.append('<td>DateTime</td>\n')
        table_script.append('<td>Source IP address</td>\n')
        table_script.append('<td>Destination IP address</td>\n')
        table_script.append('<td>Source MAC address</td>\n')
        table_script.append('<td>Destination MAC address</td>\n')
        table_script.append('<td>Protocol</td>\n')
    if table == 'Report':
        result = Database_get2insert.get_Report_list()
        table_script.append('<td>Report ID</td>\n')
        table_script.append('<td>DateTime</td>\n')
        table_script.append('<td>Source IP address</td>\n')
        table_script.append('<td>Destination IP address</td>\n')
        table_script.append('<td>Source MAC address</td>\n')
        table_script.append('<td>Destination MAC address</td>\n')
        table_script.append('<td>Protocol</td>\n')

    table_script.append('</tr>\n')

    if len(result) > 500:
        result = result[:500]

    for row in result:
        table_script.append('<tr>\n')
        for row_num in range(0, len(row)-1):
            temp = '<td> %s </td>\n' % row[row_num]
            table_script.append(temp)
        table_script.append('</tr>\n')

    table_script.append('</table>\n')
    #print table_script
    return table_script


def html_table(path):
    file = open(path)
    lines = file.read().split('\n')

    if 'Device' in path:
        table = 'Device'
    elif 'Log' in path:
        table = 'Log'
    elif 'Report' in path:
        table = 'Report'

    html_script = []
    html_script_footer = []
    for line_num in range(0, len(lines)-1):
        #print lines[line_num]
        html_script.append(lines[line_num]+'\n')
        if '<div class="table" style="padding: 10px 40px;">' in lines[line_num]:
            for n in range(line_num, len(lines)-1):
                if '</div>' in lines[n]:
                    for foot in range(n, len(lines)-1):
                        html_script_footer.append(lines[foot]+'\n')
                    break
            break
    table_script = sql2table(table)
    #print html_script
    #print html_script_footer

    html_script = html_script + table_script + html_script_footer

    #print html_script
    file.close()
    file = open(path, 'w')
    for html in html_script:
        file.write(html)
    file.close()


def html_generate(path, list, percentage_logs, percentage_report):
    html = open(path)
    soup = BeautifulSoup(html, "lxml")
    for row in soup.find('table').findAll('tr'):
        for col in row.findAll('td'):
            for ul in col.findAll('ul'):
                for li in ul.findAll('li'):
                    # print li.renderContents()
                    # print li.string
                    if '1:' in li.string:
                        li.string = '1: %8s (%10d)' % (list[0][0], list[0][1])
                    elif '2:' in li.string:
                        li.string = '2: %8s (%10d)' % (list[1][0], list[2][1])
                    elif '3:' in li.string:
                        li.string = '3: %8s (%10d)' % (list[2][0], list[2][1])
                    elif '4:' in li.string:
                        li.string = '4: %8s (%10d)' % (list[3][0], list[3][1])
                    elif '5:' in li.string:
                        try:
                            li.string = '5: %8s (%10d)' % (list[4][0], list[4][1])
                        except:
                            pass
                    elif 'Safe Traffic:' in li.string:
                        li.string = 'Safe Traffic: %d (%2.2f%%)' % (percentage_logs[0][1], (
                        (float(percentage_logs[0][1]) - float(percentage_report[0][1])) / float(
                            percentage_logs[0][1]) * 100.0))
                    elif 'Attacks:' in li.string:
                        li.string = 'Attacks: %d (%2.2f%%)' % (percentage_report[0][1], (
                        float(percentage_report[0][1]) / float(percentage_logs[0][1]) * 100.0))
                    #print li

    html = soup.prettify('utf-8')
    with open(path, 'wb') as file:
        file.write(html)
    file.close()


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

        #print proto_all
        pl = proto_all.T.to_dict('records')
        list_pl = []
        #print pl[0]
        for key, value in pl[0].iteritems():
            #print key, value
            list_pl.append([key, value])
        #print list_pl

        #print proto_this_month
        pl_month = proto_this_month.T.to_dict('records')
        list_pl_month = []
        for key, value in pl_month[0].iteritems():
            # print key, value
            list_pl_month.append([key, value])
        #print list_pl_month

        #print proto_today
        pl_today = proto_today.T.to_dict('records')
        list_pl_today = []
        for key, value in pl_today[0].iteritems():
            # print key, value
            list_pl_today.append([key, value])
        #print list_pl_today

        #print detect_attacks_all
        #print detect_attacks_this_month
        #print detect_attacks_today

        path = '/root/PycharmProjects/L2PSystem/L2PSystem_v2/'

        traffic_all.plot()
        #plt.title('Traffic graph all')
        plt.savefig(path+'HTML/GraphPhoto/Traffic_log_all.png')

        traffic_this_month.plot()
        #plt.title('Traffic graph this month')
        plt.savefig(path+'HTML/GraphPhoto/Traffic_log_this_month.png')

        traffic_today.plot()
        #plt.title('Traffic graph today')
        plt.savefig(path+'HTML/GraphPhoto/Traffic_log_today.png')

        #plt.show()
        plt.clf()

        proto_all.plot(kind='pie', subplots=True, figsize=(8, 8))
        #plt.title('Protocol all')
        plt.savefig(path+'HTML/GraphPhoto/Protocol_log_all.png')

        proto_this_month.plot(kind='pie', subplots=True, figsize=(8, 8))
        #plt.title('Protocol this month')
        plt.savefig(path+'HTML/GraphPhoto/Protocol_log_this_month.png')

        proto_today.plot(kind='pie', subplots=True, figsize=(8, 8))
        #plt.title('Protocol today')
        plt.savefig(path+'HTML/GraphPhoto/Protocol_log_today.png')

        #plt.show()
        plt.clf()

        detect_attacks_all.plot()
        #plt.title('Detect attacks all')
        plt.savefig(path+'HTML/GraphPhoto/Detect_attacks_all.png')

        detect_attacks_this_month.plot()
        #plt.title('Detect attacks this month')
        plt.savefig(path+'HTML/GraphPhoto/Detect_attacks_this_month.png')

        detect_attacks_today.plot()
        #plt.title('Detect attacks today')
        plt.savefig(path+'HTML/GraphPhoto/Detect_attacks_today.png')

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
        plt.savefig(path+'HTML/GraphPhoto/Attack_per_Traffic_all.png')

        plt.figure(figsize=(8, 8))
        plt.pie(percentage_this_month, explode=explode, labels=percentage_label, labeldistance=1.05, autopct='%2.2f%%',
                startangle=-45, pctdistance=0.6, shadow=False)
        #plt.title('Attacks / Traffic this month', bbox={'facecolor':'0.6','pad':1})
        plt.tight_layout()
        plt.axis('equal')
        plt.tight_layout(pad=8)
        plt.legend(loc=9, bbox_to_anchor=(0.5, -0.1))
        plt.savefig(path+'HTML/GraphPhoto/Attack_per_Traffic_this_month.png')

        plt.figure(figsize=(8, 8))
        plt.pie(percentage_today, explode=explode, labels=percentage_label, labeldistance=1.05, autopct='%2.2f%%',
                startangle=-45, pctdistance=0.6, shadow=False)
        #plt.title('Attacks / Traffic', bbox={'facecolor':'0.6','pad':1})
        plt.tight_layout()
        plt.axis('equal')
        plt.tight_layout(pad=8)
        plt.legend(loc=9, bbox_to_anchor=(0.5, -0.1))
        plt.savefig(path+'HTML/GraphPhoto/Attack_per_Traffic_today.png')

        #plt.show()

        html_generate(path+'HTML/FYP Overview.html', list_pl, percentage_logs_all, percentage_report_all)
        html_generate(path+'HTML/FYP Overview-ThisMouth.html', list_pl_month, percentage_logs_this_month, percentage_report_this_month)
        html_generate(path+'HTML/FYP Overview-Today.html', list_pl_today, percentage_logs_today, percentage_report_today)

        html_table(path+'HTML/FYP Devices.html')
        html_table(path+'HTML/FYP Logs.html')
        html_table(path+'HTML/FYP Reports.html')

        db_cn.close()
    except IOError as error:
        print error
