import sys
from PyQt5.QtWidgets import QApplication, QWidget, QMessageBox


class KR(QWidget):

    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        QMessageBox.information(self, ' Connect Alert ', ' \n \n [ Republic of KOREA ] \n \n  You ara in KOREA OFFICIAL PAGE \n')
        sys.exit()
        
class PHISHING(QWidget):

    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        QMessageBox.information(self, ' Connect Alert ', ' \n \n [ Warning : Phising ] \n \n  You ara maybe in Phishingsite \n')
        sys.exit()
        
if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = PHISHING()
    sys.exit(app.exec_())
