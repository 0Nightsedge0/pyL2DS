# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'GUI.ui'
#
# Created by: PyQt4 UI code generator 4.11.4

import sys
import pl
import scannetwork
sys.path.append('./l2ps_v1a8')
import L2PS_v1a8
import Config, RS_connector,Report_creator
import twograph
import Database_get2insert
import time

import MySQLdb
from IPy import IP
from multiprocessing import Process, Manager
from PyQt4 import QtCore, QtGui, QtDesigner, QtWebKit
from PyQt4.QtCore import *
from PyQt4.QtGui import *

try:
    _fromUtf8 = QtCore.QString.fromUtf8
except AttributeError:
    def _fromUtf8(s):
        return s

try:
    _encoding = QtGui.QApplication.UnicodeUTF8
    def _translate(context, text, disambig):
        return QtGui.QApplication.translate(context, text, disambig, _encoding)
except AttributeError:
    def _translate(context, text, disambig):
        return QtGui.QApplication.trnslate(context, text, disambig)

class HoverButton(QToolButton):
    description = QtCore.pyqtSignal(int)
    def __init__(self,  num):
        QToolButton.__init__(self)
        self.setMouseTracking(True)
        self.num = num

    def mouseMoveEvent(self, QMouseEvent):
        self.setStyleSheet(self.styleSheet() + "background-color: rgb(72, 72, 108);")
        self.description.emit(self.num)
        self.setAutoRaise(True)
    def leaveEvent(self, QEvent):
        self.setStyleSheet("font: 14pt Adobe Devanagari;"
                               "border-style: solid;"
                               "border-color:rgb(61,61,93);"
                               "border-radius: 10px;"
                               "border-width: 1px;"
                    "background-color: rgb(43, 43, 65);"
                    "color: rgb(170, 255, 255);")
        self.description.emit(999)

class Ui_StackedWidget(QStackedWidget):
    def __init__(self):
        QtGui.QWidget.__init__(self)
        self.setupUi(self)
        self.setCurrentWidget(self.main)
        self.StartButton_2.clicked.connect(self.runthread)
        self.StopButton.clicked.connect(self.stop)
        self.th0 = syncThread()
        self.th0.datasignal.connect(self.chilWid.Consumer)
        self.ButtToTextSingal()

    def runthread(self):
        self.StartButton_2.setEnabled(False)
        self.th0.start()
        self.chilWid.graph.start()
        QtGui.qApp.processEvents()

    def stop(self):
        self.th0.stop()
        self.StartButton_2.setEnabled(True)
        self.chilWid.graph.stop()
        self.gra = twograph.Graph()
        self.gra.stop()
    def ButtToTextSingal(self):
        self.LogButton.description.connect(self.setScriLabel)
        self.StartButton.description.connect(self.setScriLabel)
        self.SetButton.description.connect(self.setScriLabel)
        self.NetStatus.description.connect(self.setScriLabel)
        self.NetCheck.description.connect(self.setScriLabel)
    @QtCore.pyqtSlot(int)
    def setScriLabel(self,flag):
        if flag == 0:
            self.label_text.setText("Start Monitoring your network here! ")
        elif flag == 1 :
            self.label_text.setText("show the history and analysis with network \n vulnerabilities in graph and table form")
        elif flag == 2 :
            self.label_text.setText("show all of database devices status")
        elif flag == 3 :
            self.label_text.setText("control your interface and maintain security setting")
        elif flag == 4 :
            self.label_text.setText("initialize your Host and Network Devices")
        elif flag == 999:
            self.label_text.setText("Welcome to Layer 2 Prevention System!!\n"
                                "This system help you detect abnormal traffic from LAN\n"
                                "and prevent any further attack\n"
                                "Start scanning NOW!")
    def setupUi(self, StackedWidget):
        self.chilWid = ChildWid()
        StackedWidget.setObjectName(_fromUtf8("StackedWidget"))
        StackedWidget.setMaximumSize(QtCore.QSize(1000, 650))
        StackedWidget.setMinimumSize(QtCore.QSize(1000, 650))

        def setcolor():
            palette = QtGui.QPalette()
            brush = QtGui.QBrush(QtGui.QColor(255, 255, 255))
            brush.setStyle(QtCore.Qt.SolidPattern)
            palette.setBrush(QtGui.QPalette.Active, QtGui.QPalette.WindowText, brush)
            brush = QtGui.QBrush(QtGui.QColor(43, 43, 65))
            brush.setStyle(QtCore.Qt.SolidPattern)
            palette.setBrush(QtGui.QPalette.Active, QtGui.QPalette.Button, brush)
            brush = QtGui.QBrush(QtGui.QColor(64, 64, 97))
            brush.setStyle(QtCore.Qt.SolidPattern)
            palette.setBrush(QtGui.QPalette.Active, QtGui.QPalette.Light, brush)
            brush = QtGui.QBrush(QtGui.QColor(53, 53, 81))
            brush.setStyle(QtCore.Qt.SolidPattern)
            palette.setBrush(QtGui.QPalette.Active, QtGui.QPalette.Midlight, brush)
            brush = QtGui.QBrush(QtGui.QColor(21, 21, 32))
            brush.setStyle(QtCore.Qt.SolidPattern)
            palette.setBrush(QtGui.QPalette.Active, QtGui.QPalette.Dark, brush)
            brush = QtGui.QBrush(QtGui.QColor(28, 28, 43))
            brush.setStyle(QtCore.Qt.SolidPattern)
            palette.setBrush(QtGui.QPalette.Active, QtGui.QPalette.Mid, brush)
            brush = QtGui.QBrush(QtGui.QColor(255, 255, 255))
            brush.setStyle(QtCore.Qt.SolidPattern)
            palette.setBrush(QtGui.QPalette.Active, QtGui.QPalette.Text, brush)
            brush = QtGui.QBrush(QtGui.QColor(255, 255, 255))
            brush.setStyle(QtCore.Qt.SolidPattern)
            palette.setBrush(QtGui.QPalette.Active, QtGui.QPalette.BrightText, brush)
            brush = QtGui.QBrush(QtGui.QColor(255, 255, 255))
            brush.setStyle(QtCore.Qt.SolidPattern)
            palette.setBrush(QtGui.QPalette.Active, QtGui.QPalette.ButtonText, brush)
            brush = QtGui.QBrush(QtGui.QColor(0, 0, 0))
            brush.setStyle(QtCore.Qt.SolidPattern)
            palette.setBrush(QtGui.QPalette.Active, QtGui.QPalette.Base, brush)
            brush = QtGui.QBrush(QtGui.QColor(43, 43, 65))
            brush.setStyle(QtCore.Qt.SolidPattern)
            palette.setBrush(QtGui.QPalette.Active, QtGui.QPalette.Window, brush)
            brush = QtGui.QBrush(QtGui.QColor(0, 0, 0))
            brush.setStyle(QtCore.Qt.SolidPattern)
            palette.setBrush(QtGui.QPalette.Active, QtGui.QPalette.Shadow, brush)
            brush = QtGui.QBrush(QtGui.QColor(21, 21, 32))
            brush.setStyle(QtCore.Qt.SolidPattern)
            palette.setBrush(QtGui.QPalette.Active, QtGui.QPalette.AlternateBase, brush)
            brush = QtGui.QBrush(QtGui.QColor(255, 255, 220))
            brush.setStyle(QtCore.Qt.SolidPattern)
            palette.setBrush(QtGui.QPalette.Active, QtGui.QPalette.ToolTipBase, brush)
            brush = QtGui.QBrush(QtGui.QColor(0, 0, 0))
            brush.setStyle(QtCore.Qt.SolidPattern)
            palette.setBrush(QtGui.QPalette.Active, QtGui.QPalette.ToolTipText, brush)
            brush = QtGui.QBrush(QtGui.QColor(255, 255, 255))
            brush.setStyle(QtCore.Qt.SolidPattern)
            palette.setBrush(QtGui.QPalette.Inactive, QtGui.QPalette.WindowText, brush)
            brush = QtGui.QBrush(QtGui.QColor(43, 43, 65))
            brush.setStyle(QtCore.Qt.SolidPattern)
            palette.setBrush(QtGui.QPalette.Inactive, QtGui.QPalette.Button, brush)
            brush = QtGui.QBrush(QtGui.QColor(64, 64, 97))
            brush.setStyle(QtCore.Qt.SolidPattern)
            palette.setBrush(QtGui.QPalette.Inactive, QtGui.QPalette.Light, brush)
            brush = QtGui.QBrush(QtGui.QColor(53, 53, 81))
            brush.setStyle(QtCore.Qt.SolidPattern)
            palette.setBrush(QtGui.QPalette.Inactive, QtGui.QPalette.Midlight, brush)
            brush = QtGui.QBrush(QtGui.QColor(21, 21, 32))
            brush.setStyle(QtCore.Qt.SolidPattern)
            palette.setBrush(QtGui.QPalette.Inactive, QtGui.QPalette.Dark, brush)
            brush = QtGui.QBrush(QtGui.QColor(28, 28, 43))
            brush.setStyle(QtCore.Qt.SolidPattern)
            palette.setBrush(QtGui.QPalette.Inactive, QtGui.QPalette.Mid, brush)
            brush = QtGui.QBrush(QtGui.QColor(255, 255, 255))
            brush.setStyle(QtCore.Qt.SolidPattern)
            palette.setBrush(QtGui.QPalette.Inactive, QtGui.QPalette.Text, brush)
            brush = QtGui.QBrush(QtGui.QColor(255, 255, 255))
            brush.setStyle(QtCore.Qt.SolidPattern)
            palette.setBrush(QtGui.QPalette.Inactive, QtGui.QPalette.BrightText, brush)
            brush = QtGui.QBrush(QtGui.QColor(255, 255, 255))
            brush.setStyle(QtCore.Qt.SolidPattern)
            palette.setBrush(QtGui.QPalette.Inactive, QtGui.QPalette.ButtonText, brush)
            brush = QtGui.QBrush(QtGui.QColor(0, 0, 0))
            brush.setStyle(QtCore.Qt.SolidPattern)
            palette.setBrush(QtGui.QPalette.Inactive, QtGui.QPalette.Base, brush)
            brush = QtGui.QBrush(QtGui.QColor(43, 43, 65))
            brush.setStyle(QtCore.Qt.SolidPattern)
            palette.setBrush(QtGui.QPalette.Inactive, QtGui.QPalette.Window, brush)
            brush = QtGui.QBrush(QtGui.QColor(0, 0, 0))
            brush.setStyle(QtCore.Qt.SolidPattern)
            palette.setBrush(QtGui.QPalette.Inactive, QtGui.QPalette.Shadow, brush)
            brush = QtGui.QBrush(QtGui.QColor(21, 21, 32))
            brush.setStyle(QtCore.Qt.SolidPattern)
            palette.setBrush(QtGui.QPalette.Inactive, QtGui.QPalette.AlternateBase, brush)
            brush = QtGui.QBrush(QtGui.QColor(255, 255, 220))
            brush.setStyle(QtCore.Qt.SolidPattern)
            palette.setBrush(QtGui.QPalette.Inactive, QtGui.QPalette.ToolTipBase, brush)
            brush = QtGui.QBrush(QtGui.QColor(0, 0, 0))
            brush.setStyle(QtCore.Qt.SolidPattern)
            palette.setBrush(QtGui.QPalette.Inactive, QtGui.QPalette.ToolTipText, brush)
            brush = QtGui.QBrush(QtGui.QColor(21, 21, 32))
            brush.setStyle(QtCore.Qt.SolidPattern)
            palette.setBrush(QtGui.QPalette.Disabled, QtGui.QPalette.WindowText, brush)
            brush = QtGui.QBrush(QtGui.QColor(43, 43, 65))
            brush.setStyle(QtCore.Qt.SolidPattern)
            palette.setBrush(QtGui.QPalette.Disabled, QtGui.QPalette.Button, brush)
            brush = QtGui.QBrush(QtGui.QColor(64, 64, 97))
            brush.setStyle(QtCore.Qt.SolidPattern)
            palette.setBrush(QtGui.QPalette.Disabled, QtGui.QPalette.Light, brush)
            brush = QtGui.QBrush(QtGui.QColor(53, 53, 81))
            brush.setStyle(QtCore.Qt.SolidPattern)
            palette.setBrush(QtGui.QPalette.Disabled, QtGui.QPalette.Midlight, brush)
            brush = QtGui.QBrush(QtGui.QColor(21, 21, 32))
            brush.setStyle(QtCore.Qt.SolidPattern)
            palette.setBrush(QtGui.QPalette.Disabled, QtGui.QPalette.Dark, brush)
            brush = QtGui.QBrush(QtGui.QColor(28, 28, 43))
            brush.setStyle(QtCore.Qt.SolidPattern)
            palette.setBrush(QtGui.QPalette.Disabled, QtGui.QPalette.Mid, brush)
            brush = QtGui.QBrush(QtGui.QColor(21, 21, 32))
            brush.setStyle(QtCore.Qt.SolidPattern)
            palette.setBrush(QtGui.QPalette.Disabled, QtGui.QPalette.Text, brush)
            brush = QtGui.QBrush(QtGui.QColor(255, 255, 255))
            brush.setStyle(QtCore.Qt.SolidPattern)
            palette.setBrush(QtGui.QPalette.Disabled, QtGui.QPalette.BrightText, brush)
            brush = QtGui.QBrush(QtGui.QColor(21, 21, 32))
            brush.setStyle(QtCore.Qt.SolidPattern)
            palette.setBrush(QtGui.QPalette.Disabled, QtGui.QPalette.ButtonText, brush)
            brush = QtGui.QBrush(QtGui.QColor(43, 43, 65))
            brush.setStyle(QtCore.Qt.SolidPattern)
            palette.setBrush(QtGui.QPalette.Disabled, QtGui.QPalette.Base, brush)
            brush = QtGui.QBrush(QtGui.QColor(43, 43, 65))
            brush.setStyle(QtCore.Qt.SolidPattern)
            palette.setBrush(QtGui.QPalette.Disabled, QtGui.QPalette.Window, brush)
            brush = QtGui.QBrush(QtGui.QColor(0, 0, 0))
            brush.setStyle(QtCore.Qt.SolidPattern)
            palette.setBrush(QtGui.QPalette.Disabled, QtGui.QPalette.Shadow, brush)
            brush = QtGui.QBrush(QtGui.QColor(43, 43, 65))
            brush.setStyle(QtCore.Qt.SolidPattern)
            palette.setBrush(QtGui.QPalette.Disabled, QtGui.QPalette.AlternateBase, brush)
            brush = QtGui.QBrush(QtGui.QColor(255, 255, 220))
            brush.setStyle(QtCore.Qt.SolidPattern)
            palette.setBrush(QtGui.QPalette.Disabled, QtGui.QPalette.ToolTipBase, brush)
            brush = QtGui.QBrush(QtGui.QColor(0, 0, 0))
            brush.setStyle(QtCore.Qt.SolidPattern)
            palette.setBrush(QtGui.QPalette.Disabled, QtGui.QPalette.ToolTipText, brush)
            return palette
        def ButtonStyle(Butt):
            Butt.setStyleSheet("font: 14pt Adobe Devanagari;"
                               "border-style: solid;"
                               "border-color:rgb(61,61,93);"
                               "border-radius: 10px;"
                               "border-width: 1px;"
                    "background-color: rgb(43, 43, 65);"
                    "color: rgb(170, 255, 255);")

        StackedWidget.setPalette(setcolor())

        self.main = QtGui.QWidget()
        self.main.setObjectName(_fromUtf8("main"))
        self.label = QLabel(self.main)
        self.label.setGeometry(QtCore.QRect(130, 40, 421, 81))
        self.label.setObjectName(_fromUtf8("label"))
        self.label_text = QLabel(self.main)
        self.label_text.setText("Welcome to Layer 2 Prevention System!!\n"
                                "This system help you detect abnormal traffic from LAN\n"
                                "and prevent any further attack\n"
                                "Start scanning NOW!")
        self.label_text.setAlignment(Qt.AlignCenter)

        self.label_text.setGeometry(QtCore.QRect(200, 120, 550, 110))
        self.label_text.setStyleSheet("color: rgb(173,101,95);"
                                      "font-size:18px;"
                                      "font: Adobe Devanagari;")
        self.label_icon = QLabel(self.main)
        k = QPixmap("/root/PycharmProjects/GUI/GUI_Image/sheild.png")
        self.label_icon.setGeometry(20,40,100,100)
        self.label_icon.setPixmap(k.scaled(100,100,Qt.IgnoreAspectRatio, Qt.SmoothTransformation))

        self.horizontalLayoutWidget = QWidget(self.main)
        self.horizontalLayoutWidget.setGeometry(QtCore.QRect(30, 240, 900, 171))
        self.horizontalLayoutWidget.setObjectName(_fromUtf8("horizontalLayoutWidget"))
        self.MainLayout = QHBoxLayout(self.horizontalLayoutWidget)
        self.MainLayout.setSpacing(45)
        self.MainLayout.setObjectName(_fromUtf8("MainLayout"))
        self.StartButton = HoverButton(0)
        self.StartButton.setMaximumSize(QtCore.QSize(150, 131))
        ButtonStyle(self.StartButton)

        icon = QtGui.QIcon()
        icon.addPixmap(QtGui.QPixmap(_fromUtf8("/root/PycharmProjects/GUI/GUI_Image/Computer.png")),
                                        QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.StartButton.setIcon(icon)
        self.StartButton.setIconSize(QtCore.QSize(80, 80))
        self.StartButton.setToolButtonStyle(QtCore.Qt.ToolButtonTextUnderIcon)
        self.StartButton.setObjectName(_fromUtf8("StartButton"))
        self.MainLayout.addWidget(self.StartButton)
        self.LogButton = HoverButton(1)
        self.MainLayout.addWidget(self.LogButton)
        self.LogButton.setMaximumSize(QtCore.QSize(150, 131))
        ButtonStyle(self.LogButton)
        icon1 = QtGui.QIcon()
        icon1.addPixmap(QtGui.QPixmap(_fromUtf8("/root/PycharmProjects/GUI/GUI_Image/Log.png")))
        self.LogButton.setIcon(icon1)
        self.LogButton.setIconSize(QtCore.QSize(80, 80))
        self.LogButton.setToolButtonStyle(QtCore.Qt.ToolButtonTextUnderIcon)
        self.LogButton.setObjectName(_fromUtf8("LogButton"))
        self.MainLayout.addWidget(self.LogButton)
        self.NetStatus = HoverButton(2)
        self.NetStatus.setMaximumSize(QtCore.QSize(150, 131))
        ButtonStyle(self.NetStatus)
        icon2 = QtGui.QIcon()
        icon2.addPixmap(QtGui.QPixmap(_fromUtf8("/root/PycharmProjects/GUI/GUI_Image/Chart.png")), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.NetStatus.setIcon(icon2)
        self.NetStatus.setIconSize(QtCore.QSize(80, 80))
        self.NetStatus.setToolButtonStyle(QtCore.Qt.ToolButtonTextUnderIcon)
        self.NetStatus.setObjectName(_fromUtf8("NetStatus"))
        self.MainLayout.addWidget(self.NetStatus)
        self.NetCheck = HoverButton(3)
        self.NetCheck.setMaximumSize(QtCore.QSize(150, 131))
        ButtonStyle(self.NetCheck)
        icon3 = QtGui.QIcon()
        icon3.addPixmap(QPixmap("/root/PycharmProjects/GUI/GUI_Image/check.png"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.NetCheck.setIcon(icon3)
        self.NetCheck.setIconSize(QtCore.QSize(80, 80))
        self.NetCheck.setToolButtonStyle(QtCore.Qt.ToolButtonTextUnderIcon)
        self.NetCheck.setObjectName(_fromUtf8("NetCheck"))
        self.MainLayout.addWidget(self.NetCheck)
        StackedWidget.addWidget(self.main)

        icon8 = QIcon()
        icon8.addPixmap(QPixmap("/root/PycharmProjects/GUI/GUI_Image/settings.png"), QtGui.QIcon.Normal)
        self.SetButton = HoverButton(4)
        self.SetButton.setIcon(icon8)
        self.SetButton.setIconSize(QSize(80,80))
        ButtonStyle(self.SetButton)

        self.RTLayoutWidget = QtGui.QWidget(self.main)
        self.RTLayoutWidget.setGeometry(QtCore.QRect(880, 50, 111, 91))
        self.verticalLayout_2 = QtGui.QVBoxLayout(self.RTLayoutWidget)
        self.verticalLayout_2.addWidget(self.SetButton)
        self.label_bottom = QLabel(self.main)
        pl_t = pl.col_info()
        self.label_bottom.setText(pl_t)
        self.label_bottom.setGeometry(QRect(40, 400, 960, 155))
        self.label_bottom.setStyleSheet("color: rgb(173,101,95);"
                                        "font-size:15px;"
                                        "font-weight: bold;"
                                        "font-family:DejaVu Sans Mono;")
    #### monitor page
        self.monitor = QtGui.QWidget()
        self.monitor.setObjectName(_fromUtf8("monitor"))

        self.verticalLayoutWidget = QtGui.QWidget(self.monitor)
        self.verticalLayoutWidget.setGeometry(QtCore.QRect(15, 90, 1000, 550))

        self.verticalLayoutWidget.setObjectName(_fromUtf8("verticalLayoutWidget"))
        self.horizontalLayout = QtGui.QHBoxLayout(self.verticalLayoutWidget)
        self.horizontalLayout.setObjectName(_fromUtf8("verticalLayout"))
        self.verticalLay = QVBoxLayout()
        self.verticalLay.setSpacing(20)
        self.horizontalLayout.addLayout(self.verticalLay)
        self.horizontalLayout.addWidget(self.chilWid)
        self.horizontalLayout.setSpacing(0)

        self.StartButton_2 = HoverButton(self.verticalLayoutWidget)
        self.StartButton_2.setMaximumSize(QtCore.QSize(150, 131))
        self.StartButton_2.setAutoFillBackground(False)
        self.StartButton_2.setStyleSheet(_fromUtf8("font: 75 28pt \"Adobe Devanagari\";\n"
                    "color: rgb(170, 255, 255);\n"
                    "background-color: rgb(43, 43, 65);\n"
                    "font: 75 14pt \"MV Boli\";\n"
                    ""))
        self.StartButton_2.setText(_fromUtf8("Start"))
        icon4 = QtGui.QIcon()
        icon4.addPixmap(QtGui.QPixmap(_fromUtf8("/root/PycharmProjects/GUI/GUI_Image/Play.png")), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.StartButton_2.setIcon(icon4)
        self.StartButton_2.setIconSize(QtCore.QSize(100, 100))
        self.StartButton_2.setPopupMode(QtGui.QToolButton.DelayedPopup)
        self.StartButton_2.setToolButtonStyle(QtCore.Qt.ToolButtonTextUnderIcon)
        self.StartButton_2.setAutoRaise(True)
        self.StartButton_2.setArrowType(QtCore.Qt.NoArrow)
        self.StartButton_2.setObjectName(_fromUtf8("StartButton_2"))
        ButtonStyle(self.StartButton_2)
        self.verticalLay.addWidget(self.StartButton_2)
        self.StopButton = HoverButton(self.verticalLayoutWidget)
        self.StopButton.setAutoFillBackground(False)
        ButtonStyle(self.StopButton)
        self.StopButton.setText(_fromUtf8("Stop"))
        icon5 = QtGui.QIcon()
        icon5.addPixmap(QtGui.QPixmap(_fromUtf8("/root/PycharmProjects/GUI/GUI_Image/Stop.png")), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.StopButton.setIcon(icon5)
        self.StopButton.setIconSize(QtCore.QSize(100, 100))
        self.StopButton.setToolButtonStyle(QtCore.Qt.ToolButtonTextUnderIcon)
        self.StopButton.setAutoRaise(True)
        self.StopButton.setArrowType(QtCore.Qt.NoArrow)
        self.StopButton.setObjectName(_fromUtf8("StopButton"))
        self.verticalLay.addWidget(self.StopButton)
        self.backButton = HoverButton(self.verticalLayoutWidget)
        self.verticalLay.addWidget(self.backButton)
        StackedWidget.addWidget(self.monitor)

        icon7 = QtGui.QIcon()
        icon7.addPixmap(QtGui.QPixmap(_fromUtf8("/root/PycharmProjects/GUI/GUI_Image/home.png")), QtGui.QIcon.Normal,QtGui.QIcon.Off)
        self.backButton.setIcon(icon7)
        self.backButton.setIconSize(QtCore.QSize(100, 100))
        self.backButton.setAutoFillBackground(False)
        ButtonStyle(self.backButton)

        k = QPixmap("/root/PycharmProjects/GUI/GUI_Image/Computer.png")
        self.Monitortitle = QLabel(self.monitor)
        self.Monitortitle.setText("Monitor")
        self.Monitortitle.setGeometry(77, 40, 150, 50)
        self.Monitortitle.setStyleSheet("font: 20pt Adobe Devanagari; color:#7FCCFF;")
        self.Monitortitle_2 = QLabel(self.monitor)
        self.Monitortitle_2.setGeometry(187,40,50,50)
        self.Monitortitle_2.setPixmap(k.scaled(30,30,Qt.IgnoreAspectRatio, Qt.SmoothTransformation))

    #### Log page
        self.Log = QtGui.QWidget()
        self.Log.setObjectName(_fromUtf8("Log"))
        self.Logback = HoverButton(9)
        self.Logback.setFixedSize(50,50)
        ButtonStyle(self.Logback)
        self.Logback.setIcon(icon7)
        self.Logback.setIconSize(QSize(50,50))

        self.LogMainLayout = QtGui.QWidget(self.Log)
        self.LogMainLayout.setGeometry(QRect(16,95,1000,600))
        self.WebBox = QtWebKit.QWebView(self.LogMainLayout)
        self.WebBox.load(QUrl("./HTML/FYP Home.html"))

        self.WebBox.setStyleSheet("border-style:inset;"
                                  "border-width:15px;")
        self.LogRTLayoutWid = QWidget(self.Log)
        self.LogRTLayoutWid.setGeometry(QRect(910,0,100,100))
        self.LogRTLayout = QHBoxLayout(self.LogRTLayoutWid)
        self.LogRTLayout.addWidget(self.Logback)

        self.WebBox.setFixedSize(980,550)
        self.WebBox.show()

        k = QPixmap("/root/PycharmProjects/GUI/GUI_Image/Log.png")
        self.Logtitle = QLabel(self.Log)
        self.Logtitle.setText("Log and Report")
        self.Logtitle.setGeometry(77, 40, 300, 50)
        self.Logtitle.setStyleSheet("font: 20pt Adobe Devanagari; color:#7FCCFF;")
        self.Logtitle_2 = QLabel(self.Log)
        self.Logtitle_2.setGeometry(290,40,50,50)
        self.Logtitle_2.setPixmap(k.scaled(30,30,Qt.IgnoreAspectRatio, Qt.SmoothTransformation))

        StackedWidget.addWidget(self.Log)

    #### Network Status page
        self.NetSta = QtGui.QWidget()
        self.NetSta.setObjectName(_fromUtf8("NetSta"))
        self.NetStaback = HoverButton(9)
        self.NetStaback.setIcon(icon7)
        self.NetStaback.setIconSize(QSize(50,50))
        ButtonStyle(self.NetStaback)
        self.NetStaRTLayoutWid = QWidget(self.NetSta)
        self.NetStaRTLayoutWid.setGeometry(900,30,70,70)
        self.NetStaRTLayout = QHBoxLayout(self.NetStaRTLayoutWid)
        self.NetStaRTLayout.addWidget(self.NetStaback)
        self.NetStacenWid = QWidget(self.NetSta)
        k = QPixmap("/root/PycharmProjects/GUI/GUI_Image/Chart.png")
        self.NetStatitle = QLabel(self.NetSta)
        self.NetStatitle.setText("Network Status")
        self.NetStatitle.setGeometry(77, 40, 300, 50)
        self.NetStatitle.setStyleSheet("font: 20pt Adobe Devanagari; color:#7FCCFF;")
        self.NetStatitle_2 = QLabel(self.NetSta)
        self.NetStatitle_2.setGeometry(290,40,50,50)
        self.NetStatitle_2.setPixmap(k.scaled(30,30,Qt.IgnoreAspectRatio, Qt.SmoothTransformation))
        self.NetStacenlayout = QGridLayout(self.NetStacenWid)
        self.databaseSta = QTreeWidget()
        self.databaseSta.setColumnCount(5)
        self.databaseSta.setHeaderLabels(["Device ID","Device name","Device type", "IP address",
                                          "MAC address","Gateway"])
        self.databaseSta.setFixedSize(650,450)
        self.databaseSta.setStyleSheet("color:black;")

        self.netStaScanbutt = HoverButton(9)
        ButtonStyle(self.netStaScanbutt)
        self.netStaScanbutt.setIconSize(QSize(50,50))
        self.netStaScanbutt.setToolButtonStyle(Qt.ToolButtonTextUnderIcon)
        self.netStaScanbutt.setText("Scan")
        self.netStaScanbutt.setFixedSize(80,80)
        icon_scan =QIcon()
        icon_scan.addPixmap(QPixmap("/root/PycharmProjects/GUI/GUI_Image/scan.png"))
        self.netStaScanbutt.setIcon(icon_scan)
        self.NetStaTable = QTableWidget()
        self.NetStaTable.setColumnCount(2)
        self.NetStaTable.setRowCount(1)
        self.NetStaTable.setEditTriggers(self.NetStaTable.NoEditTriggers)
        self.NetStaTable.setStyleSheet("color:black;")
        self.NetStaTable.setFixedSize(250,450)
        #self.NetStaTable.resizeRowsToContents()
        #self.NetStaTable.resizeColumnsToContents()
        self.NetStaTable.setHorizontalHeaderLabels(["Host","Status"])
        self.NetStacenWid.setGeometry(QRect(30, 100, 900, 500))
        self.NetStacenlayout.addWidget(self.NetStaTable,1,0)
        self.NetStacenlayout.addWidget(self.databaseSta,1,1)
        self.NetStacenlayout.addWidget(self.netStaScanbutt,0,0)


        StackedWidget.addWidget(self.NetSta)


    #### Network check page
        self.NetChec = QtGui.QWidget()
        self.NetChec.setObjectName(_fromUtf8("NetChec"))
        self.Netchback = HoverButton(9)
        self.Netchback.setIcon(icon7)
        self.Netchback.setIconSize(QSize(50,50))
        ButtonStyle(self.Netchback)
        self.NetchbackRTLayoutWid = QWidget(self.NetChec)
        self.NetchbackRTLayoutWid.setGeometry(900,30,70,70)
        self.NetchbackRTLayout = QHBoxLayout(self.NetchbackRTLayoutWid)
        self.NetchbackRTLayout.addWidget(self.Netchback)
        self.netcheccenwid = QTabWidget(self.NetChec)
        self.netcheccenwid.setGeometry(245,100,550,500)
        self.netcheccenwid.setStyleSheet("color:black;")
        self.StatusTree = QTreeWidget()
        self.StatusTree.setColumnCount(5)
        self.StatusTree.setHeaderLabels(["interface", "IP address", "Status", "Protocol","On/Off"])
        self.TreeWiditem = QTreeWidgetItem()
        self.netcheccenwid.addTab(self.StatusTree,"Interface status")

        k = QPixmap("/root/PycharmProjects/GUI/GUI_Image/check.png")
        self.NetChectitle = QLabel(self.NetChec)
        self.NetChectitle.setText("Network Check")
        self.NetChectitle.setGeometry(77, 40, 300, 50)
        self.NetChectitle.setStyleSheet("font: 20pt Adobe Devanagari; color:#7FCCFF;")
        self.NetChectitle_2 = QLabel(self.NetChec)
        self.NetChectitle_2.setGeometry(290,40,50,50)
        self.NetChectitle_2.setPixmap(k.scaled(30,30,Qt.IgnoreAspectRatio, Qt.SmoothTransformation))


        StackedWidget.addWidget(self.NetChec)

        self.retranslateUi(StackedWidget)
        StackedWidget.setCurrentIndex(1)
        QtCore.QMetaObject.connectSlotsByName(StackedWidget)
    #### Config page
        self.Popup = Ui_Dialog()
        self.Popup.setFixedSize(400,500)

        self.configPage = QWidget()
        self.ConfigLayWidget = QWidget(self.configPage)
        self.ConfigHorizon = QHBoxLayout(self.ConfigLayWidget)

        self.ConfigLayWidget.setGeometry(QRect(50, 90, 900, 550))
        self.scanButt = HoverButton(9)
        self.scanButt.setIconSize(QSize(50,50))
        self.scanButt.setToolButtonStyle(Qt.ToolButtonTextUnderIcon)
        self.scanButt.setText("Scan")
        self.scanButt.setFixedSize(80,80)
        icon_scan =QIcon()
        icon_scan.addPixmap(QPixmap("/root/PycharmProjects/GUI/GUI_Image/scan.png"))
        self.scanButt.setIcon(icon_scan)
        ButtonStyle(self.scanButt)
        self.ScanView = QTableWidget()
        self.ScanView.setEditTriggers(self.ScanView.NoEditTriggers)
        self.ScanView.setStyleSheet("color:black;")
        self.ScanView.setFixedSize(325,450)
        self.ScanView.resizeRowsToContents()
        self.ScanView.resizeColumnsToContents()
        self.ScanView.setRowCount(1)
        self.ScanView.setColumnCount(3)
        horHeaders = ["IP address","MAC address","OS"]
        self.ScanView.setHorizontalHeaderLabels(horHeaders)

        self.leftverlay = QVBoxLayout()

        self.leftverlay.addWidget(self.ScanView)
        self.leftverlay.addWidget(self.scanButt)
        self.leftverlay.setAlignment(self.scanButt,Qt.AlignRight)
        self.ConfigHorizon.addLayout(self.leftverlay)
        self.ConfigVertical = QVBoxLayout()
        self.ConfigHorizon.addLayout(self.ConfigVertical)
        self.addviewWidget = QTableWidget()
        header = ["Device name", "IP address", "MAC address", "Device type", "Gateway"]
        self.addviewWidget.setEditTriggers(self.ScanView.NoEditTriggers)
        self.addviewWidget.setStyleSheet("color:black;")
        self.addviewWidget.resizeRowsToContents()
        self.addviewWidget.resizeColumnsToContents()
        self.addviewWidget.setColumnCount(5)
        self.addviewWidget.setHorizontalHeaderLabels(header)
        #self.addviewWidget.setRowCount(1)
        self.addviewWidget.setFixedSize(550,200)
        self.FormFrame = QWidget()
        self.FormFrame.setAutoFillBackground(True)

        self.Popup.setGeometry(85,-10,500,700)
        self.FormFrame.setStyleSheet("background-color:rgb(50,50,75);")
        self.Popup.setParent(self.FormFrame)
        self.ConfigVertical.addWidget(self.FormFrame)
        self.ConfigVertical.addWidget(self.addviewWidget)

        self.ConfigRTLayoutWid = QWidget(self.configPage)
        self.ConfigRTLayoutWid.setGeometry(900,30,70,70)
        self.ConfigRTLayout = QHBoxLayout(self.ConfigRTLayoutWid)
        self.configback = HoverButton(9)
        self.configback.setIcon(icon7)
        self.configback.setIconSize(QSize(50,50))
        ButtonStyle(self.configback)
        self.ConfigRTLayout.addWidget(self.configback)
        k = QPixmap("/root/PycharmProjects/GUI/GUI_Image/settings.png")
        self.configtitle = QLabel(self.configPage)
        self.configtitle.setText("Configuration")
        self.configtitle.setGeometry(77, 40, 300, 50)
        self.configtitle.setStyleSheet("font: 20pt Adobe Devanagari; color:#7FCCFF;")
        self.configtitle_2 = QLabel(self.configPage)
        self.configtitle_2.setGeometry(270,40,50,50)
        self.configtitle_2.setPixmap(k.scaled(30,30,Qt.IgnoreAspectRatio, Qt.SmoothTransformation))


        StackedWidget.addWidget(self.configPage)

        def gethostalive():
            host = scannetwork.aliveHost()
            for i,record in enumerate(host):
                print record
                for k,item in enumerate(record):
                    print item
                    newitem = QTableWidgetItem(item)
                    self.NetStaTable.setItem(i,k,newitem)
                if i < len(host)-1:
                    self.NetStaTable.insertRow(self.NetStaTable.rowCount())

        def updateTree_database():
            record = Database_get2insert.get_Device2address_list()
            for r,item in enumerate(record):
                item.pop(0)
                for c,item2 in enumerate(item):
                    if c >= 1:
                        item_2 = QTreeWidgetItem(item)
                self.databaseSta.insertTopLevelItem(r,item_2)

        def switchToMonitor():
            self.configbox = QMessageBox()
            self.configbox.setText("Please configure database first!")
            self.configbox.setStandardButtons(QMessageBox.Ok | QMessageBox.No)
            ret = self.configbox.exec_()
            if (ret == QMessageBox.Ok):
                self.setCurrentWidget(self.configPage)
            else:
                self.setCurrentWidget(self.monitor)


        def switchToMain():
            self.setCurrentWidget(self.main)

        def switchToLog():
            try:
                Report_creator.main()
            except Exception, e:
                errormeg = QMessageBox()
                errormeg.setText("No Log and report in database")
                errormeg.exec_()
                return 0
            self.setCurrentWidget(self.Log)
        def switchToSta():
            self.setCurrentWidget(self.NetSta)

        def switchToCheck():
            self.setCurrentWidget(self.NetChec)
            self.updateTree_status()

        def switchToConfig():
            self.setCurrentWidget(self.configPage)
        def switchPage():
            self.NetStatus.clicked.connect(switchToSta)
            self.StartButton.clicked.connect(switchToMonitor)
            self.LogButton.clicked.connect(switchToLog)
            self.NetCheck.clicked.connect(switchToCheck)
            self.backButton.clicked.connect(switchToMain)
            self.Logback.clicked.connect(switchToMain)
            self.NetStaback.clicked.connect(switchToMain)
            self.Netchback.clicked.connect(switchToMain)
            self.SetButton.clicked.connect(switchToConfig)
            self.configback.clicked.connect(switchToMain)
            self.scanButt.clicked.connect(self.scanHost)
            self.netStaScanbutt.clicked.connect(gethostalive)
            self.netStaScanbutt.clicked.connect(updateTree_database)
        switchPage()
        self.Popup.record.connect(self.InputView)
    @pyqtSlot(str)
    def InputView(self,value):
        self.input = value
        row = self.addviewWidget.rowCount()
        self.addviewWidget.insertRow(self.addviewWidget.rowCount())
        for c,val in enumerate(self.input):
            newitem = QTableWidgetItem(val)
            self.addviewWidget.setItem(row,c,newitem)


    def updateTree_status(self):
        list = RS_connector.remote_shell(1,"","")
        l = []

        if self.StatusTree.topLevelItemCount() >= 26:
            self.StatusTree.clear()
        self.StatusTree.connect(self.StatusTree,SIGNAL("columnCountChanged()"),SLOT("clear()"))
        self.onbutt = []
        self.mapper = QSignalMapper(self)

        #list2 = [["fa0/0","test","test","test"],["fa0/1","test","test","test"],["fa0/2","test","test","test"]]
        for i,item in enumerate(list):
            item_2 = QTreeWidgetItem(item)
            l.append(item_2)
            self.StatusTree.setColumnWidth(0,155)
            self.StatusTree.setColumnWidth(2,80)
            self.StatusTree.setColumnWidth(3,80)
        self.StatusTree.addTopLevelItems(l)
        for i in range(0,len(l)):

            a = QPushButton("On/Off")
            self.onbutt.append(a)
            self.StatusTree.setItemWidget(l[i],4,self.onbutt[i])
            self.connect(self.onbutt[i], SIGNAL("clicked()"), self.mapper, SLOT("map()"))
            if list[i][2] == 'up':
                self.mapper.setMapping(self.onbutt[i],i+70)
            else:
                self.mapper.setMapping(self.onbutt[i],i)
        self.connect(self.mapper,SIGNAL("mapped(int)"),self.configSwitchslot)

    def configSwitchslot(self,num):
        print num
        if num >=70:
            RS_connector.remote_shell(7,"",num-69)
            self.updateTree_status()

        else:
            RS_connector.remote_shell(5,"",num+1)
            time.sleep(1)
            self.updateTree_status()

    def scanHost(self):
        '''message = QDialog()
        message.setParent(self.configPage,Qt.Popup)
        text = QLabel(message)
        text.setText("Scanning ...")
        message.setModal(True)
        message.show()'''

        self.scan = scannetwork.scanHost()
        for row,item in enumerate(self.scan):
            print item, row
            for col,c in enumerate(item):
                print row, c, col
                newitem = QTableWidgetItem(c)
                self.ScanView.setItem(row,col,newitem)
                self.ScanView.resizeColumnsToContents()
                self.ScanView.resizeRowsToContents()
            if row < len(self.scan)-1:
                self.ScanView.insertRow(self.ScanView.rowCount())

    def retranslateUi(self, StackedWidget):
        StackedWidget.setWindowTitle(_translate("Layer 2", "Layer 2 Prevention System", None))
        self.label.setText(_translate("StackedWidget", "<html><head/><body><p><span style=\" font-size:22pt; font-weight:600; font-style:italic; color:#7FCCFF;\">Layer 2 Prevention System</span></p></body></html>", None))
        self.StartButton.setText(_translate("StackedWidget", "Monitor", None))
        self.LogButton.setText(_translate("StackedWidget", "Log&&Report", None))
        self.NetStatus.setText(_translate("StackedWidget", "Network Status", None))
        self.NetCheck.setText(_translate("StackedWidget", "Network Check", None))


class Ui_Dialog(QDialog):
    record = QtCore.pyqtSignal(list)
    def __init__(self):
        QtGui.QWidget.__init__(self)
        self.setupUi(self)
        self.db = MySQLdb.connect(host="localhost", user="root", passwd="root", db="mydb")
        self.cursor = self.db.cursor()
        self.GWTable = "Default_Gateway_Table"
        self.IP_MAC_Table = "IP_MAC_Table"
        self.DevTable = "Device_Table"
        self.Add_NetDev.clicked.connect(self.commitNetDev)
        self.Add_GWRouter.clicked.connect(self.commitGWRouter)
        self.MegForSta = QMessageBox()
        self.MegForSta.setStandardButtons(QMessageBox.Ok)
        self.setModal(True)

    def setupUi(self, Dialog):
        self.formLayoutWidget = QtGui.QWidget(Dialog)
        self.formLayoutWidget.setGeometry(QtCore.QRect(10, 70, 331, 500))
        self.formLayout = QtGui.QFormLayout(self.formLayoutWidget)
        self.formLayout.setRowWrapPolicy(QtGui.QFormLayout.DontWrapRows)
        self.formLayout.setContentsMargins(0, -1, -1, -1)
        self.formLayout.setHorizontalSpacing(6)
        self.formLayout.setVerticalSpacing(10)
        self.GatewayIP = QtGui.QLabel(self.formLayoutWidget)
        self.setStyleSheet("color:rgb(250,250,250);")
        self.GatewayIP.setMinimumSize(QtCore.QSize(150, 25))
        self.GatewayIP.setMaximumSize(QtCore.QSize(150, 35))
        self.GatewayIP.setAlignment(QtCore.Qt.AlignRight|QtCore.Qt.AlignTrailing|QtCore.Qt.AlignVCenter)
        self.formLayout.setWidget(0, QtGui.QFormLayout.LabelRole, self.GatewayIP)
        self.GWIP_input = QtGui.QLineEdit(self.formLayoutWidget)
        self.formLayout.setWidget(0, QtGui.QFormLayout.FieldRole, self.GWIP_input)
        self.GatewayMac = QtGui.QLabel(self.formLayoutWidget)
        self.GatewayMac.setMinimumSize(QtCore.QSize(150, 25))
        self.GatewayMac.setMaximumSize(QtCore.QSize(150, 35))
        self.GatewayMac.setAlignment(QtCore.Qt.AlignRight|QtCore.Qt.AlignTrailing|QtCore.Qt.AlignVCenter)
        self.formLayout.setWidget(1, QtGui.QFormLayout.LabelRole, self.GatewayMac)
        self.GWMAC_input = QtGui.QLineEdit(self.formLayoutWidget)
        self.GWMAC_input.setDragEnabled(False)
        self.formLayout.setWidget(1, QtGui.QFormLayout.FieldRole, self.GWMAC_input)
        self.GWRouter = QtGui.QLabel(Dialog)
        self.GWRouter.setGeometry(QtCore.QRect(10, 40, 134, 25))
        self.GWRouter.setMinimumSize(QtCore.QSize(100, 25))
        self.GWRouter.setMaximumSize(QtCore.QSize(150, 40))
        self.GWRouter.setTextFormat(QtCore.Qt.AutoText)
        self.NetDev = QtGui.QLabel(Dialog)
        self.NetDev.setGeometry(QtCore.QRect(10, 160, 150, 25))
        self.NetDev.setMinimumSize(QtCore.QSize(100, 25))
        self.NetDev.setMaximumSize(QtCore.QSize(150, 40))
        self.NetDev.setTextFormat(QtCore.Qt.AutoText)
        self.Add_GWRouter = QtGui.QPushButton(Dialog)
        self.Add_GWRouter.setGeometry(QtCore.QRect(300, 40, 75, 23))
        self.Add_GWRouter.setText('Add')
        self.Add_GWRouter.setStyleSheet("background-color:#343536;"
                                        "font:bold;")

        self.Add_NetDev = QtGui.QPushButton(Dialog)
        self.Add_NetDev.setGeometry(QtCore.QRect(300, 160, 75, 23))
        self.Add_NetDev.setStyleSheet("background-color:#343536;"
                                      "font:bold;")
        self.Device = QtGui.QGroupBox(Dialog)
        self.Device.setGeometry(QtCore.QRect(30, 190, 350, 500))
        self.Device.setMaximumSize(QtCore.QSize(350, 85))
        self.input_name = QtGui.QLineEdit(self.Device)
        self.input_name.setGeometry(QtCore.QRect(60, 10, 91, 21))
        self.Label_Name = QtGui.QLabel(self.Device)
        self.Label_Name.setGeometry(QtCore.QRect(0, 10, 51, 21))
        self.input_ip = QtGui.QLineEdit(self.Device)
        self.input_ip.setGeometry(QtCore.QRect(210, 10, 91, 21))
        self.input_mac = QtGui.QLineEdit(self.Device)
        self.input_mac.setGeometry(QtCore.QRect(210, 50, 91, 21))
        self.Label_IP = QtGui.QLabel(self.Device)
        self.Label_IP.setGeometry(QtCore.QRect(170, 10, 31, 21))
        self.Label_Mac = QtGui.QLabel(self.Device)
        self.Label_Mac.setGeometry(QtCore.QRect(150, 50, 51, 21))
        self.Label_Type = QtGui.QLabel(self.Device)
        self.Label_Type.setGeometry(QtCore.QRect(0, 50, 51, 21))
        self.TypeBox = QtGui.QComboBox(self.Device)
        self.TypeBox.setGeometry(QtCore.QRect(60, 50, 80, 22))
        self.TypeBox.addItem("PC")
        self.TypeBox.addItem("Router")
        self.TypeBox.addItem("DNS")
        self.TypeBox.addItem("DHCP")
        self.TypeBox.addItem("Switch")
        self.TypeBox.setStyleSheet("background-color:rgb(5F,5F,5F);"
                                   "color:rgb(FA,FA,FA);")
        self.Title = QtGui.QLabel(Dialog)
        self.Title.setGeometry(QtCore.QRect(50, 0, 291, 41))

        self.Device_GWLabel = QLabel(Dialog)
        self.Device_GWLabel.setGeometry(QtCore.QRect(-3,278, 85, 25))
        self.Device_GWInput = QLineEdit(Dialog)
        self.Device_GWInput.setGeometry(QtCore.QRect(90,280, 91, 21))

        self.retranslateUi(Dialog)

        QtCore.QMetaObject.connectSlotsByName(Dialog)

    def commitGWRouter(self):
        ip = self.GWIP_input.text()
        mac = self.GWMAC_input.text()

        if ip == '' or mac == '':
            self.MegForSta.setText("please input IP and Mac")
            ret = self.MegForSta.exec_()
            '''elif self.cursor.execute("select field1,field2,field3, count(*) "
                                 "from table_name group by field1,field2,fied3 "
                                 "having count(*) > 1"):'''
        else:
            try:
                IP(str(ip))
            except Exception, e:
                self.MegForSta.setText(str(e))
                self.MegForSta.exec_()
            else:
                Database_get2insert.insert_Gateway(ip,mac)
                ipmac = ["Gateway",ip,mac,"Router","Null"]
                self.record.emit(ipmac)
                self.MegForSta.setText("Gateway Router entry Successful!")
                self.MegForSta.exec_()
            self.GWIP_input.clear()
            self.GWMAC_input.clear()


    def commitNetDev(self):
        ip = self.input_ip.text()
        mac = self.input_mac.text()
        name = self.input_name.text()
        type = self.TypeBox.currentText()
        deviceGW = self.Device_GWInput.text()
        k = self.cursor.execute("SELECT IP_MAC_ID FROM IP_MAC_Table order by IP_MAC_ID desc")
        j =self.cursor.execute("SELECT IP_MAC_ID FROM IP_MAC_Table order by IP_MAC_ID desc")
        j = str(j)
        lastipmacID = 0 if k == 0 else int(j[0])
        self.IPMACID = 1
        if lastipmacID < self.IPMACID:
            self.IPMACID = 1
        else:
            self.IPMACID += lastipmacID

        k = self.cursor.execute("SELECT Device_ID from Device_Table order by Device_ID desc")
        j = self.cursor.execute("SELECT Device_ID from Device_Table order by Device_ID desc")
        j = str(j)
        lastdevID = 0 if k == 0 else int(j[0])
        self.Device_ID = 1
        if lastdevID < self.Device_ID:
            self.Device_ID = 1
        else:
            self.Device_ID += lastdevID

        if Database_get2insert.get_Gateway() == None:
            self.MsgForSta.setText('please input Default Router first!')
        elif ip == '' or mac == '':
            self.MegForSta.setText("please input IP and Mac")
            ret = self.MegForSta.exec_()
        else:
            try:
                IP(str(ip))
                Database_get2insert.insert_Device(self.Device_ID, type, name,deviceGW)
                Database_get2insert.insert_IPMAC(self.IPMACID,ip,mac,self.Device_ID)
            except Exception, e:
                self.MegForSta.setText(str(e))
                self.MegForSta.exec_()

            data2 = [name,ip,mac,type,deviceGW]
            self.record.emit(data2)
            self.MegForSta.setText('Device entry Successful!')
            self.MegForSta.exec_()
            self.input_ip.clear()
            self.input_mac.clear()
            self.input_name.clear()


    def retranslateUi(self, Dialog):
        Dialog.setWindowTitle(_translate("Dialog", "Dialog", None))
        self.GatewayIP.setText(_translate("Dialog", "<html><head/><body><p><span style=\" font-size:12pt;\">Gateway IP:</span></p></body></html>", None))
        self.GatewayMac.setText(_translate("Dialog", "<html><head/><body><p><span style=\" font-size:12pt;\">Gateway MAC:</span></p></body></html>", None))
        self.GWRouter.setText(_translate("Dialog", "<html><head/><body><p><span style=\" font-size:14pt;\">Gateway Router</span></p></body></html>", None))
        self.NetDev.setText(_translate("Dialog", "<html><head/><body><p><span style=\" font-size:14pt;\">Network Devices</span></p></body></html>", None))
        self.Add_NetDev.setText(_translate("Dialog", "Add", None))
        self.Label_IP.setText(_translate("Dialog", "<html><head/><body><p align=\"right\"><span style=\" font-size:12pt;\">IP:</span></p></body></html>", None))
        self.Label_Mac.setText(_translate("Dialog", "<html><head/><body><p align=\"right\">Mac:</p></body></html>", None))
        self.Label_Name.setText(_translate("Dialog", "<html><head/><body><p align=\"right\"><span style=\" font-size:12pt;\">Name:</span></p></body></html>", None))
        self.Label_Type.setText(_translate("Dialog", "<html><head/><body><p align=\"right\"><span style=\" font-size:12pt;\">Type:</span></p></body></html>", None))
        self.Device_GWLabel.setText(_translate("Dialog", "<html><head/><body><p align=\"right\"><span style=\" font-size:12pt;\">Gateway:</span></p></body></html>", None))

manager3 = Manager()
manager = Manager()
manager2 = Manager()
q3 =manager3.Queue()
q = manager.Queue()
q2 =manager2.Queue()
l3 =manager3.Lock()
l = manager.Lock()
l2 =manager2.Lock()

class syncThread(QThread):
    datasignal = QtCore.pyqtSignal()
    def __init__(self):
        QThread.__init__(self)
        self.stopped = False

    def DataSignal(self):
        time.sleep(1)
        self.datasignal.emit()
    def run(self):
        self.ps0 = Process(target=L2PS_v1a8.main, args=(q, l, 'wlan0', q2, l2, q3))
        self.ps0.start()
        while (not self.stopped):
            self.DataSignal()

        self.ps0.join()
    def stop(self):
        l3.acquire()
        q3.put('s')
        l3.release()
        self.terminate()

class ChildWid(QWidget):
    def __init__(self):
        QWidget.__init__(self)
        self.text = QTextEdit()
        self.text.setFixedSize(850,150)
        self.text.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.graph = twograph.Graph()
        self.lay = QVBoxLayout(self)
        self.lay.addWidget(self.graph)
        self.lay.addWidget(self.text)
        self.text.setStyleSheet("background-color: rgb(40, 40, 40);\n"
                    "color: rgb(170, 255, 127);")
        self.text.setReadOnly(True)
        self.text.setFrameShape(QtGui.QFrame.Panel)
    def Consumer(self):
        global q, q2, q3,l,l2,l3

        try:
            '''if num == 9:
                self.graph.stop()'''
            self.task = q.get(block=False)
            self.graph.settask(self.task)
            #print self.task
            header = "-------------------Now data and time : %s --------------------\n" % self.task[11]
            header2 = "-------------------------Operation times : %s seconds---------------------------" % self.task[10]
            body = "\nNumber of      ARP packets per second: %6s |  Total      ARP packets: %6s \n" % (self.task[0], self.task[1])
            body += "Number of    ICMP packets per second: %6s |  Total    ICMP packets: %6s \n" % (self.task[2], self.task[3])
            body += "Number of   DHCP packets per second: %6s |  Total   DHCP packets: %6s \n" % (self.task[4], self.task[5])
            body += "Number of    DNS packets per second: %6s |  Total       DNS packets: %6s \n" % (self.task[6], self.task[7])
            footer = "Network Traffic: %6d" % (self.task[8])
            self.text.setText(header + header2 + body + footer)
        except:
            pass

        try:
            self.alert = q2.get(block=False)
            print self.alert
            alertMsg = QMessageBox()
            alertMsg.setIcon(QMessageBox.Warning)
            alertMsg.setWindowTitle("Warning: " + self.alert[4])
            alertMsg.setText("Source IP:" + self.alert[0] +
                             " \tType: " + self.alert[4] +
                             "\nSource Mac: " + self.alert[1])
            alertMsg.setInformativeText("Message: " + self.alert[5])
            alertMsg.exec_()
            #signal = q3.get(block=False)
        except:
            pass

def main():
    if __name__ == "__main__":
        app = QApplication(sys.argv)
        w = Ui_StackedWidget()
        w.show()
        v = Ui_Dialog()
        v.show
        sys.exit(app.exec_())

main()