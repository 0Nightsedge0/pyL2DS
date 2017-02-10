import pylab, time
from pylab import *
from PyQt4.QtGui import *
from matplotlib.backends.backend_qt4agg import FigureCanvasQTAgg as FigureCanvas
from multiprocessing import Manager

manager3 = Manager()
manager = Manager()
manager2 = Manager()
q3 = manager3.Queue()
q = manager.Queue()
q2 = manager2.Queue()
l3 = manager3.Lock()
l = manager.Lock()
l2 = manager2.Lock()


class Graph(QWidget):
    def __init__(self):
        QWidget.__init__(self)

        self.task = [0,0,0,0,0,0,0,0,0,0,0,0]
        self.setWindowTitle("Windows")
        self.fig = pylab.figure(figsize=(12, 5), dpi=80)
        self.fig.patch.set_facecolor("#333333")

        xAchse = pylab.arange(0, 10, 1)
        yAchse = pylab.array([0]*10)

        self.ax1 = self.fig.add_subplot(1, 2, 1)
        self.ax1.grid(True, color='black', linewidth=0.5)
        self.ax1.set_title("Network Traffic", fontsize="18", color='cyan')
        self.ax1.set_xlabel("Time", color='beige')
        self.ax1.set_ylabel("Packets", color='beige')
        self.ax1.patch.set_facecolor("#E0E0D1")

        self.yticks = []
        for y in range(0, 1100, 100):
            self.yticks.append(y)

        self.ax1.set_yticks(self.yticks)
        self.ax1.tick_params(colors='honeydew')
        self.line1 = self.ax1.plot(xAchse, yAchse, '-')
        self.ax1.grid(True, color='blue', linewidth='0.5')

        global values
        values = []
        values = [0 for x in range(0, 10)]

        self.canvas = FigureCanvas(self.fig)
        self.canvas.setFixedSize(850,350)
        self.canvas.setParent(self)

        ########################### Graph 2

        ax2 = self.fig.add_subplot(1, 2, 2)
        ax2.grid(True, color='black', linewidth=0.5)
        ax2.set_title('Protocol Monitor', fontsize='18', color='cyan')
        ax2.set_xlabel("Count/s", color='beige')
        ax2.set_ylabel("Protocol Type", color='beige')
        ax2.set_xticklabels(['ARP', 'ICMP', 'DHCP', 'DNS'], fontsize='10')
        ind = np.arange(1, 5)
        self.pm, self.pc, self.pn, self.pt = plt.bar(ind, self.get_state())
        centers = ind + 0.5 * self.pm.get_width()
        self.pm.set_facecolor('y')
        self.pc.set_facecolor('g')
        self.pn.set_facecolor('b')
        self.pt.set_facecolor('c')
        ax2.set_xlim([0.5, 5])
        ax2.set_xticks(centers)
        ax2.set_yticks([0,10,20,30,40,50,60,70,80,90,100])
        ax2.tick_params(colors='honeydew')
        ax2.patch.set_facecolor("#E0E0D1")
        self.timer = self.canvas.new_timer(interval=1000)
        self.timer.add_callback(self.RealtimePloter)
        self.timer1 = self.canvas.new_timer(interval=1000)
        self.timer1.add_callback(self.SinwaveformGenerator)
        self.timer2 = self.canvas.new_timer(interval=1000)
        self.timer2.add_callback(self.RealtimeBarPloter)

    def start(self):
        time.sleep(1)
        self.timer.start()
        self.timer1.start()
        self.timer2.start()

    def stop(self):

        self.timer.stop()
        self.timer1.stop()
        self.timer2.stop()

    def RealtimeBarPloter(self):
        m, c, n, t = self.get_state()
        self.pm.set_height(m)
        self.pc.set_height(c)
        self.pn.set_height(n)
        self.pt.set_height(t)
        self.canvas.draw_idle()

    def SinwaveformGenerator(self):
        global values
        try:
            values.append(self.task[9])
        except:
            pass

    def RealtimePloter(self):
        global values
        CurrentXAxis = pylab.arange(len(values)-10, len(values), 1)
        self.line1[0].set_data(CurrentXAxis, pylab.array(values[-10:]))
        self.ax1.axis([CurrentXAxis.min(), CurrentXAxis.max(), 0, 1000])
        self.canvas.draw()

    def settask(self, t):
        for d in range(0, 11):
            self.task[d] = t[d]

    def get_arp(self):
        return self.task[0]

    def get_icmp(self):
        return self.task[2]

    def get_dhcp(self):
        return self.task[4]

    def get_dns(self):
        return self.task[6]

    def get_state(self):
        return self.get_arp(), self.get_icmp(), self.get_dhcp(), self.get_dns()


def main():
    app = QApplication(sys.argv)
    w = Graph()
    w.show()
    sys.exit(app.exec_())

#main()