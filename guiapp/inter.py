import sys
import random
from PySide2.QtWidgets import *
from PySide2.QtCore import Slot, Qt
import sys
import requests
import json
from jwt import decode, InvalidTokenError
from jwt import encode
import datetime
import ntpath

address = "http://192.168.99.100:5001"
user = "admin"
response = None
JWT_SECRET="haha"
JWT_SESSION_TIME=30
status=False

class myApplication(QMainWindow):

    def __init__(self, parent=None):
        super(myApplication, self).__init__(parent)

        self.setWindowTitle('setup')

        #---- create instance of each tool widget ----
        self.Setup = Setup()
        self.Main = Main()
        #---- layout for central widget ----

        self.centralWidget = QWidget()
        self.centralLayout = QGridLayout()
        self.centralLayout.addWidget(self.Setup, 0, 0)
        self.centralLayout.addWidget(self.Main, 1, 0)
        self.centralWidget.setLayout(self.centralLayout)

        self.setCentralWidget(self.centralWidget)  
        self.Main.hide()

        #---- set the menu bar ----

        self.contentMenu = self.menuBar().addMenu(("menu"))
        self.contentMenu.addAction('setup', self.show_Setup)
        self.contentMenu.addAction('main', self.show_Main)

    def show_Setup(self):
        self.Setup.show()
        self.Main.hide()
        self.setWindowTitle('setup')

    def show_Main(self):
        if status == False:
            self.error_dialog = QErrorMessage()
            self.error_dialog.showMessage('Wrong address!')
        else:
            self.Setup.hide()
            self.Main.refresh()
            self.Main.show()
            self.setWindowTitle('main')

class Setup(QWidget):
    def __init__(self, parent=None):
        super(Setup, self).__init__(parent)

        self.layout = QVBoxLayout()

        self.labeladdress = QLabel("address: ")
        self.layout.addWidget(self.labeladdress)

        self.editaddress = QLineEdit("http://192.168.99.100:5001")
        self.layout.addWidget(self.editaddress)

        self.labeluser = QLabel("user: ")
        self.layout.addWidget(self.labeluser)

        self.edituser = QLineEdit("admin")
        self.layout.addWidget(self.edituser)

        self.buttonapply = QPushButton("apply")
        self.layout.addWidget(self.buttonapply)
        self.buttonapply.clicked.connect(self.apply)

        self.setLayout(self.layout)

    @Slot()
    def apply(self):
        global address
        address = self.editaddress.text()
        global user
        user = self.edituser.text()
        s=requests.Session()
        resp = s.get(address+'/'+user)
        global status
        if resp.status_code == 200:
            status =True
        else:
            status = False


class Main(QWidget):

    reftodelete = None

    def __init__(self, parent=None):
        super(Main, self).__init__(parent)
        self.listWidget = QListWidget()
        self.listWidget.itemClicked.connect(self.listOnClick)
        self.layout = QGridLayout()

        self.layout.addWidget(self.listWidget,0,0)

        self.layoutdetails=QGridLayout()
        self.layout.addLayout(self.layoutdetails,0,1)

        self.labelauthor = QLabel("Author: ")
        self.layoutdetails.addWidget(self.labelauthor,0,0)

        self.labelid = QLabel()
        self.layoutdetails.addWidget(self.labelid,0,2)
        self.buttondeletepub = QPushButton("delete publication")
        self.buttondeletepub.clicked.connect(self.deletepub)
        self.layoutdetails.addWidget(self.buttondeletepub,1,2)

        self.labeltitle =QLabel("Title: ")
        self.layoutdetails.addWidget(self.labeltitle,1,0)

        self.labelyear = QLabel("Year: ")
        self.layoutdetails.addWidget(self.labelyear,2,0)

        self.labelfile = QLabel("File: ")
        self.layoutdetails.addWidget(self.labelfile,3,0)

        self.labelreferences = QLabel("References: ")
        self.layoutdetails.addWidget(self.labelreferences,4,0)

        self.labelauthor2 = QLabel()
        self.layoutdetails.addWidget(self.labelauthor2,0,1)

        self.labeltitle2 =QLabel()
        self.layoutdetails.addWidget(self.labeltitle2,1,1)

        self.labelyear2 = QLabel()
        self.layoutdetails.addWidget(self.labelyear2,2,1)

        self.labelfile2 = QLabel()
        self.labelfile2.setStyleSheet('color: blue')
        self.layoutdetails.addWidget(self.labelfile2,3,1)
        self.filedownload = QPushButton("download")
        self.layoutdetails.addWidget(self.filedownload,3,2)


        self.listreferences = QListWidget()
        self.listreferences.setStyleSheet('color: blue')
        self.listreferences.itemClicked.connect(self.chooseref)
        self.layoutdetails.addWidget(self.listreferences,4,1)
        self.layoutref = QVBoxLayout()
        self.layoutdetails.addLayout(self.layoutref,4,2)

        self.referencedownload = QPushButton("download")
        self.referencedownload.clicked.connect(self.downloadref)
        self.layoutref.addWidget(self.referencedownload)
        self.referenceadd = QPushButton("add")
        self.referenceadd.clicked.connect(self.addref)
        self.layoutref.addWidget(self.referenceadd)
        self.referencedelete = QPushButton("delete")
        self.referencedelete.clicked.connect(self.deleteref)
        self.layoutref.addWidget(self.referencedelete)


        self.labeladd = QLabel("Dodaj publikację: ")
        self.layout.addWidget(self.labeladd,1,0)
        self.layoutadd = QGridLayout()
        self.layout.addLayout(self.layoutadd,1,1)
        self.labeladdauthor = QLabel("Author: ")
        self.layoutadd.addWidget(self.labeladdauthor,0,0)
        self.editauthor = QLineEdit("author")
        self.layoutadd.addWidget(self.editauthor,0,1)
        self.labeladdtitle = QLabel("Title: ")
        self.layoutadd.addWidget(self.labeladdtitle,1,0)
        self.edittitle = QLineEdit("title")
        self.layoutadd.addWidget(self.edittitle,1,1)
        self.labeladdyear = QLabel("Year: ")
        self.layoutadd.addWidget(self.labeladdyear,2,0)
        self.edityear = QLineEdit("year")
        self.layoutadd.addWidget(self.edityear,2,1)
        self.labeladdfile = QLabel("File: ")
        self.layoutadd.addWidget(self.labeladdfile,3,0)
        self.layoutfile =QHBoxLayout()
        self.layoutadd.addLayout(self.layoutfile,3,1)
        self.editfile = QLineEdit()
        self.editfile.setReadOnly(True)
        self.layoutfile.addWidget(self.editfile)
        self.filechoser = QPushButton("choose file")
        self.filechoser.clicked.connect(self.choosefile)
        self.layoutfile.addWidget(self.filechoser)
        self.buttonadd = QPushButton("Add")
        self.buttonadd.clicked.connect(self.add)
        self.layoutadd.addWidget(self.buttonadd,4,1)


        self.layout.setColumnStretch(0, 1)
        self.layout.setColumnStretch(1, 2)
        self.setLayout(self.layout)

    def changedata(self,pub):
        self.reftodelete = None
        self.labelid.setText(str(pub['id']))
        self.labelauthor2.setText(pub['author'])
        self.labeltitle2.setText(pub['title'])
        self.labelyear2.setText(str(pub['year']))
        self.labelfile2.setText(pub['filename'])
        self.listreferences.clear()
        for ref in pub['references']:
            item = QListWidgetItem(ref['filename'])
            self.listreferences.addItem(item)

    def listOnClick(self,item):
        for pub in response['publications']:
            if pub['title'] == item.text():
                self.changedata(pub)
                break

    def deletepub(self):
        id = self.labelid.text()
        s = requests.Session()
        x=s.delete(address+'/'+user+'/'+id
        )
        self.refresh()

    def downloadref(self):
        f = self.reftodelete
        if f is None:
            return
        token = self.create_download_token()
        s = requests.Session()
        id = self.labelid.text()
        x=s.get(address+'/'+user+'/'+id+'/'+f,params={
        'token':token}
        )
        dir = QFileDialog.getSaveFileName(self, 'Save File')
        if dir[0]:
            open(dir[0],'wb').write(x.content)

    def choosefile(self):
        filename = QFileDialog.getOpenFileName(parent=self,caption="Open file",dir='.')
        if filename[0]:
            self.editfile.setText(filename[0])

    def add(self):
        author = self.editauthor.text()
        title = self.edittitle.text()
        year = self.edityear.text()
        token = self.create_upload_token()
        s = requests.Session()
        f = open(self.editfile.text(),"r")
        x=s.post(address+'/'+'upload',files={'file':(ntpath.basename(self.editfile.text()),f)},params={
        'user':user,
        'token':token,
        'author' : author,
        'title' : title,
        'year' : year
        })
        self.refresh()

    def addref(self):
        filename = QFileDialog.getOpenFileName(parent=self,caption="Open file",dir='.')
        if filename[0]:
            f = open(filename[0],"r")
        else:
            return
        id = self.labelid.text()
        s = requests.Session()
        x=s.post(address+'/'+user+'/'+id,files={'file':(ntpath.basename(filename[0]),f)}
        )
        self.refresh()
        for pub in response['publications']:
            if pub['id'] == id:
                self.changedata(pub)
                break

    def chooseref(self,item):
        self.reftodelete = item.text()

    def deleteref(self):
        id = self.labelid.text()
        s = requests.Session()
        x=s.delete(address+'/'+user+'/'+id+'/'+self.reftodelete
        )      
        item = self.listreferences.findItems(self.reftodelete,Qt.MatchWildcard)
        self.listreferences.takeItem(self.listreferences.row(item[0]))
        reftodelete = None


    def create_download_token(self):
        exp = datetime.datetime.utcnow() + datetime.timedelta(seconds=JWT_SESSION_TIME)
        return encode({
            "iss":"web",
            "user":user,
            "exp":exp},
            JWT_SECRET, "HS256")

    def create_upload_token(self):
        exp = datetime.datetime.utcnow() + datetime.timedelta(seconds=JWT_SESSION_TIME)
        return encode({
            "iss":"web",
            "exp":exp},
            JWT_SECRET, "HS256")

    def refresh(self):
        global response
        reftodelete = None
        s=requests.Session()
        resp = s.get(address+'/'+user)
        response = json.loads(resp.text)
        publications = response['publications']
        if publications:
            pub = publications[0]
            self.changedata(pub)
        else:
            self.changedata({
                'id':'',
                "author": '', 
                "title": '', 
                "year": '', 
                "publication": '', 
                "filename": '', 
                "references":[]
            })
        self.listWidget.clear()
        for pub in publications:
            item = QListWidgetItem(pub['title'])
            self.listWidget.addItem(item)





if __name__ == '__main__':

    app = QApplication(sys.argv)
    instance = myApplication()  
    instance.show()    
    sys.exit(app.exec_())

