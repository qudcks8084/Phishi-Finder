# 피싱 사이트 접속 알림

import sys
from PyQt5.QtWidgets import QApplication, QWidget, QMessageBox


class KR(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        # 경고 메시지 박스 표시, 정확한 정부 페이지에 접속했음을 알림
        QMessageBox.information(
            self, 'Connect Alert', ' \n \n [Republic of KOREA] \n \n You are in KOREA OFFICIAL PAGE \n'
        )
        sys.exit()


class PHISHING(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        # 경고 메시지 박스 표시, 피싱 의심 페이지에 접속했음을 알림
        QMessageBox.information(
            self, 'Connect Alert', ' \n \n [Warning: Phishing] \n \n You are maybe in Phishing site \n'
        )
        sys.exit()


if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = PHISHING()
    sys.exit(app.exec_())
