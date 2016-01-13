import pylab
from pylab import *

xAchse = pylab.arange(0,100,1)
yAchse = pylab.array([0]*100)

fig = pylab.figure(1)
ax = fig.add_subplot(111)
ax.grid(True)
ax.set_title("Network")
ax.set_xlabel("Time")
ax.set_ylabel("Packets")
ax.axis([0,100,-1.5,1.5])
line1 = ax.plot(xAchse, yAchse, '-')

manager = pylab.get_current_fig_manager()

values = []
values = [0 for x in range(100)]

y = 0
x = 0


def gety():
    global y
    y = random()*10000
    return y


def SinwaveformGenerator(arg):
  global values
  Tnext = gety()
  values.append(Tnext)


def RealtimePloter(arg):
    global values
    CurrentXAxis = pylab.arange(len(values)-100, len(values), 1)
    line1[0].set_data(CurrentXAxis, pylab.array(values[-100:]))
    ax.axis([CurrentXAxis.min(), CurrentXAxis.max(), 0, 10000])
    manager.canvas.draw()
    #manager.show()

def showing():
    timer = fig.canvas.new_timer(interval=1000) # 1000 = 1second
    timer.add_callback(RealtimePloter, ())
    timer2 = fig.canvas.new_timer(interval=1000)
    timer2.add_callback(SinwaveformGenerator, ())
    timer.start()
    timer2.start()

    pylab.show()
