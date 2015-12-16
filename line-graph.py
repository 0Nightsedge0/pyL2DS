import pylab
from pylab import *
import numpy as np

xAchse = pylab.arange(0, 10, 1)
yAchse = pylab.array([0]*10)

fig = pylab.figure(1)
ax = fig.add_subplot(111)
ax.grid(True)
ax.set_title("Network Traffic")
ax.set_xlabel("Time")
ax.set_ylabel("Packets")

yticks = []
for y in range(0,10000,500):
    yticks.append(y)
ax.set_yticks(yticks)
line1 = ax.plot(xAchse, yAchse, '-')
ax.grid(True, color='black', linewidth='0.5')

manager = pylab.get_current_fig_manager()

values=[]
values = [0 for x in range(10)]


def SinwaveformGenerator(arg):
    global values
    Tnext= random()*10000
    values.append(Tnext)


def RealtimePloter(arg):
      global values
      CurrentXAxis=pylab.arange(len(values)-10,len(values),1)
      line1[0].set_data(CurrentXAxis,pylab.array(values[-10:]))
      ax.axis([CurrentXAxis.min(),CurrentXAxis.max(),0,10000])
      manager.canvas.draw()
      #manager.show()

timer = fig.canvas.new_timer(interval=1000)
timer.add_callback(RealtimePloter, ())
timer2 = fig.canvas.new_timer(interval=1000)
timer2.add_callback(SinwaveformGenerator, ())
timer.start()
timer2.start()

pylab.show()