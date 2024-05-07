from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QPushButton, QLabel, QLineEdit, QVBoxLayout, QMessageBox, QDialog, QFormLayout, QFileDialog, QTextEdit)
import sys
import sqlite3

def create_database():
    connection = sqlite3.connect('user.db')
    cursor = connection.cursor()
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL
    );
    ''')
    connection.commit()
    connection.close()
class AlgorithmSelectionDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent
        self.setWindowTitle('Algoritma Seçimi')
        self.setGeometry(600, 300, 300, 100)
        layout = QVBoxLayout(self)

        btn_algorithm_x = QPushButton('Metni Fuko Algoritması ile Karşılaştır', self)
        btn_algorithm_y = QPushButton('Metni Jaccard Algoritması ile Karşılaştır', self)
        
        btn_algorithm_x.clicked.connect(lambda: self.open_compare_dialog('Algoritma X'))
        btn_algorithm_y.clicked.connect(lambda: self.open_compare_dialog('Algoritma Y'))

        layout.addWidget(btn_algorithm_x)
        layout.addWidget(btn_algorithm_y)

    def open_compare_dialog(self, algorithm):
        self.hide()  
        compare_dialog = CompareDialog(algorithm, self.parent)
        compare_dialog.show()

class PasswordChangeDialog(QDialog):
    def __init__(self, username, parent=None):
        super().__init__(parent)
        self.username = username
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle('Şifre Değiştir')
        self.setGeometry(600, 300, 300, 120)

        layout = QVBoxLayout()
        self.new_password = QLineEdit(self)
        self.new_password.setPlaceholderText('Yeni Şifre')
        self.new_password.setEchoMode(QLineEdit.Password)
        layout.addWidget(self.new_password)

        change_button = QPushButton('Şifreyi Değiştir', self)
        change_button.clicked.connect(self.change_password)
        layout.addWidget(change_button)

        self.setLayout(layout)

    def change_password(self):
        new_password = self.new_password.text()
        if not new_password:
            QMessageBox.warning(self, 'Hata', 'Şifre boş bırakılamaz!')
            return
        
        connection = sqlite3.connect('user.db')
        cursor = connection.cursor()
        cursor.execute('UPDATE users SET password=? WHERE username=?', (new_password, self.username))
        connection.commit()
        connection.close()
        QMessageBox.information(self, 'Başarılı', 'Şifreniz başarıyla güncellendi!')
        self.accept()
class OperationsMenu(QDialog):
    def __init__(self, username, parent=None):
        super().__init__(parent)
        self.username = username
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle('İşlemler Menüsü')
        self.setGeometry(600, 300, 300, 100)

        layout = QVBoxLayout()
        password_change_button = QPushButton('Şifre Değiştir', self)
        password_change_button.clicked.connect(self.open_password_change_dialog)
        layout.addWidget(password_change_button)

        self.setLayout(layout)

    def open_password_change_dialog(self):
        self.password_dialog = PasswordChangeDialog(self.username, self)
        self.password_dialog.show()

class CompareDialog(QDialog):
    def __init__(self, algorithm, parent=None):
        super().__init__(parent)
        self.algorithm = algorithm
        self.parent = parent  
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle('Metin Karşılaştırma - ' + self.algorithm)
        self.setGeometry(600, 300, 500, 400)

        layout = QVBoxLayout()

        
        self.textarea1 = QTextEdit(self)
        self.textarea1.setPlaceholderText("Metin girin veya dosya seçin")
        self.textarea2 = QTextEdit(self)
        self.textarea2.setPlaceholderText("Metin girin veya dosya seçin")
        self.browse_button1 = QPushButton('Dosya Seç', self)
        self.browse_button2 = QPushButton('Dosya Seç', self)

        
        self.browse_button1.clicked.connect(lambda: self.open_file_dialog(self.textarea1))
        self.browse_button2.clicked.connect(lambda: self.open_file_dialog(self.textarea2))

        
        layout.addWidget(self.textarea1)
        layout.addWidget(self.browse_button1)
        layout.addWidget(self.textarea2)
        layout.addWidget(self.browse_button2)

        
        compare_button = QPushButton('Karşılaştır', self)
        compare_button.clicked.connect(self.compare_texts)
        layout.addWidget(compare_button)

        self.result_text = QTextEdit(self)
        self.result_text.setReadOnly(True)
        layout.addWidget(self.result_text)

        self.setLayout(layout)

    def open_file_dialog(self, textarea):
        filename, _ = QFileDialog.getOpenFileName(self, "Dosya Seç", "", "Text Files (*.txt)")
        if filename:
            try:
                with open(filename, 'r', encoding='utf-8') as file:
                    text = file.read()
                    textarea.setText(text)
            except Exception as e:
                QMessageBox.warning(self, 'Hata', 'Dosya okunurken bir hata oluştu: ' + str(e))

    def compare_texts(self):
        text1 = self.textarea1.toPlainText()
        text2 = self.textarea2.toPlainText()

        if self.algorithm == "Algoritma X":
            result = self.compare_using_algorithm_x(text1, text2)
        elif self.algorithm == "Algoritma Y":
            result = self.compare_using_algorithm_y(text1, text2)
        else:
            result = "Bilinmeyen algoritma."

        self.result_text.setText(result)
    def compare_using_algorithm_x(self, text1, text2):
        words1 = text1.split()
        words2=text2.split()
        similarCount=0
        totalCount= len(words1) + len(words2)    
        for i in range(len(words1)):
            for j in range(len(words2)):
                if words1[i]==words2[j]: 
                 similarCount +=1
                 totalCount-=1
        score =similarCount / totalCount
        return "Kendi algoritmam ile karşılaştırma sonucu:{:.2f}".format(score)

    def compare_using_algorithm_y(self, text1, text2):
        words1 = set(text1.split())  
        words2 = set(text2.split())  
        intersection = words1 & words2  
        union = words1 | words2         
        if len(union) == 0:
            return 0  
        jaccard_similarity = len(intersection) / len(union)  
        return "Jaccard algoritması ile karşılaştırma sonucu: {:.2f}".format(jaccard_similarity)
    def closeEvent(self, event): 
        self.parent.show()  
        event.accept()  

class MainMenu(QMainWindow):
    def __init__(self, username, parent=None):
        super().__init__(parent)
        self.username = username
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle('Ana Menü')
        self.setGeometry(500, 200, 320, 250)

        layout = QVBoxLayout()

        compare_button = QPushButton('Karşılaştır', self)
        compare_button.clicked.connect(self.open_compare)
        layout.addWidget(compare_button)

        operations_button = QPushButton('İşlemler', self)
        operations_button.clicked.connect(self.open_operations)
        layout.addWidget(operations_button)

        exit_button = QPushButton('Çıkış', self)
        exit_button.clicked.connect(self.close)
        layout.addWidget(exit_button)

        central_widget = QWidget()
        central_widget.setLayout(layout)
        self.setCentralWidget(central_widget)

    def open_compare(self):
        self.hide()  
        self.selection_dialog = AlgorithmSelectionDialog(self)
        self.selection_dialog.show()


    def open_operations(self):
        self.operations_dialog = OperationsMenu(self.username, self)
        self.operations_dialog.show()


class LoginWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle('Giriş Yap')
        self.setGeometry(500, 200, 320, 250)

        layout = QVBoxLayout()
        self.username = QLineEdit(self)
        self.username.setPlaceholderText('Kullanıcı Adı')
        layout.addWidget(self.username)

        self.password = QLineEdit(self)
        self.password.setEchoMode(QLineEdit.Password)
        self.password.setPlaceholderText('Şifre')
        layout.addWidget(self.password)

        login_button = QPushButton('Giriş Yap', self)
        login_button.clicked.connect(self.check_login)
        layout.addWidget(login_button)

        register_button = QPushButton('Kayıt Ol', self)
        register_button.clicked.connect(self.register)
        layout.addWidget(register_button)

        central_widget = QWidget()
        central_widget.setLayout(layout)
        self.setCentralWidget(central_widget)

    def check_login(self):
        username = self.username.text()
        password = self.password.text()
        connection = sqlite3.connect('user.db')
        cursor = connection.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ? AND password = ?', (username, password))
        if cursor.fetchone():
            QMessageBox.information(self, 'Başarılı', 'Giriş başarılı!')
            self.main_menu = MainMenu(username, self)
            self.main_menu.show()
            self.hide()
        else:
            QMessageBox.warning(self, 'Hata', 'Kullanıcı adı veya şifre hatalı!')
        connection.close()

    def register(self):
        username = self.username.text()
        password = self.password.text()
        connection = sqlite3.connect('user.db')
        cursor = connection.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        if cursor.fetchone():
            QMessageBox.warning(self, 'Hata', 'Kullanıcı adı zaten mevcut!')
        else:
            cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, password))
            connection.commit()
            QMessageBox.information(self, 'Başarılı', 'Kayıt başarılı!')
        connection.close()

if __name__ == '__main__':
    create_database()
    app = QApplication(sys.argv)
    ex = LoginWindow()
    ex.show()
    sys.exit(app.exec_())
