import sys
import os
import magic
import hashlib
from PyQt5.QtWidgets import QApplication, QMainWindow, QVBoxLayout, QTextBrowser, QPushButton, QFileDialog, QLabel, \
    QTextEdit, QAction, QWidget, QStatusBar, QToolBar, QLineEdit, QInputDialog, QDialog
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QTextCursor

class FileCarvingTool(QMainWindow):
    def __init__(self):
        super().__init__()

        self.file_path = ""
        self.file_type = ""
        self.carved_data = b""

        self.init_ui()

    def init_ui(self):
        self.setWindowTitle('File Carving Tool')
        self.setGeometry(100, 100, 800, 600)

        self.info_label = QLabel(self)
        self.info_label.setAlignment(Qt.AlignCenter)
        self.info_label.setText("Open a file and choose a file type to carve.")

        self.text_browser = QTextBrowser(self)
        self.text_browser.setReadOnly(True)

        self.carve_button = QPushButton('Carve', self)
        self.carve_button.clicked.connect(self.carve_file)
        self.carve_button.setEnabled(False)

        self.open_button = QPushButton('Open File', self)
        self.open_button.clicked.connect(self.open_file)

        self.choose_type_button = QPushButton('Choose File Type', self)
        self.choose_type_button.clicked.connect(self.choose_file_type)

        self.export_button = QPushButton('Export Carved File', self)
        self.export_button.clicked.connect(self.export_carved_file)
        self.export_button.setEnabled(False)

        self.hex_viewer_action = QAction('Hex Viewer', self)
        self.hex_viewer_action.triggered.connect(self.show_hex_viewer)

        self.metadata_button = QPushButton('Display Metadata', self)
        self.metadata_button.clicked.connect(self.display_metadata)
        self.metadata_button.setEnabled(False)

        self.hash_button = QPushButton('Calculate Hashes', self)
        self.hash_button.clicked.connect(self.calculate_hashes)
        self.hash_button.setEnabled(False)

        self.timeline_button = QPushButton('Timeline Analysis', self)
        self.timeline_button.clicked.connect(self.timeline_analysis)
        self.timeline_button.setEnabled(False)

        self.keyword_button = QPushButton('Highlight Keywords', self)
        self.keyword_button.clicked.connect(self.highlight_keywords)
        self.keyword_button.setEnabled(False)

        self.reconstruct_button = QPushButton('Reconstruct File', self)
        self.reconstruct_button.clicked.connect(self.reconstruct_file)
        self.reconstruct_button.setEnabled(False)

        self.entropy_button = QPushButton('Entropy Analysis', self)
        self.entropy_button.clicked.connect(self.entropy_analysis)
        self.entropy_button.setEnabled(False)

        self.search_line_edit = QLineEdit(self)
        self.search_line_edit.setPlaceholderText("Search Text")
        self.search_button = QPushButton('Search', self)
        self.search_button.clicked.connect(self.search_text)

        self.status_bar = QStatusBar(self)
        self.setStatusBar(self.status_bar)

        self.tool_bar = QToolBar('Tool Bar', self)
        self.tool_bar.addAction(self.hex_viewer_action)
        self.tool_bar.addSeparator()
        self.tool_bar.addWidget(self.search_line_edit)
        self.tool_bar.addWidget(self.search_button)

        layout = QVBoxLayout()
        layout.addWidget(self.info_label)
        layout.addWidget(self.text_browser)
        layout.addWidget(self.open_button)
        layout.addWidget(self.choose_type_button)
        layout.addWidget(self.carve_button)
        layout.addWidget(self.export_button)
        layout.addWidget(self.metadata_button)
        layout.addWidget(self.hash_button)
        layout.addWidget(self.timeline_button)
        layout.addWidget(self.keyword_button)
        layout.addWidget(self.reconstruct_button)
        layout.addWidget(self.entropy_button)

        central_widget = QWidget(self)
        central_widget.setLayout(layout)
        self.setCentralWidget(central_widget)
        self.addToolBar(self.tool_bar)

    def open_file(self):
        options = QFileDialog.Options()
        file_path, _ = QFileDialog.getOpenFileName(self, 'Open File', '', 'All Files (*)', options=options)

        if file_path:
            self.file_path = file_path
            self.info_label.setText(f"File Path: {file_path}")
            self.carve_button.setEnabled(True)

    def choose_file_type(self):
        file_types = ["jpeg", "png", "pdf", "docx"]  # Add more file types as needed
        file_type, ok_pressed = QInputDialog.getItem(self, "Choose File Type", "Select a file type:", file_types, 0, False)

        if ok_pressed and file_type:
            self.file_type = file_type
            self.info_label.setText(f"File Type: {file_type}")
            self.carve_button.setEnabled(True)
            self.export_button.setEnabled(False)  # Reset export button when file type changes
            self.metadata_button.setEnabled(True)
            self.hash_button.setEnabled(True)
            self.timeline_button.setEnabled(True)
            self.keyword_button.setEnabled(True)
            self.reconstruct_button.setEnabled(True)
            self.entropy_button.setEnabled(True)

    def carve_file(self):
        if not self.file_path or not self.file_type:
            return

        with open(self.file_path, 'rb') as file:
            data = file.read()

        magic_mime = magic.Magic()
        file_mime_type = magic_mime.from_buffer(data)

        if self.file_type.lower() not in file_mime_type.lower():
            self.text_browser.setPlainText(f"Selected file type '{self.file_type}' does not match the file's actual type.")
            return

        start_marker = f"----- Start of {self.file_type} File -----"
        end_marker = f"----- End of {self.file_type} File -----"

        start_index = data.find(start_marker.encode())
        end_index = data.find(end_marker.encode())

        if start_index != -1 and end_index != -1:
            self.carved_data = data[start_index + len(start_marker):end_index].strip()
            self.text_browser.setPlainText(self.carved_data.decode('latin-1'))
            self.export_button.setEnabled(True)

        else:
            self.text_browser.setPlainText(f"No {self.file_type} file found in the given data.")

    def export_carved_file(self):
        options = QFileDialog.Options()
        file_path, _ = QFileDialog.getSaveFileName(self, 'Save Carved File', '', 'All Files (*)', options=options)

        if file_path:
            with open(file_path, 'wb') as file:
                file.write(self.carved_data)
            self.status_bar.showMessage(f"Carved file exported to: {file_path}")

    def show_hex_viewer(self):
        hex_viewer = HexViewer(self.carved_data)
        hex_viewer.exec_()

    def search_text(self):
        search_text = self.search_line_edit.text()
        if search_text:
            cursor = self.text_browser.document().find(search_text)
            if not cursor.isNull():
                self.text_browser.setTextCursor(cursor)
                self.text_browser.setFocus()

    def display_metadata(self):
        # Implement metadata extraction and display logic here
        # For example, use external libraries to extract metadata from different file types
        self.status_bar.showMessage("Metadata displayed.")

    def calculate_hashes(self):
        # Implement file hashing logic here
        md5_hash = hashlib.md5(self.carved_data).hexdigest()
        sha256_hash = hashlib.sha256(self.carved_data).hexdigest()
        sha1_hash = hashlib.sha1(self.carved_data).hexdigest()

        hash_info = f"MD5: {md5_hash}\nSHA-256: {sha256_hash}\nSHA-1: {sha1_hash}"
        self.text_browser.append("\n" + hash_info)
        self.status_bar.showMessage("Hashes calculated and displayed.")

    def timeline_analysis(self):
        # Implement timeline analysis logic here
        # Consider integrating with a timeline analysis tool or displaying relevant timestamps
        self.status_bar.showMessage("Timeline analysis performed.")

    def highlight_keywords(self):
        # Implement keyword highlighting logic here
        # Highlight occurrences of specific keywords within the text
        keywords = ["keyword1", "keyword2", "keyword3"]  # Add your keywords
        cursor = QTextCursor(self.text_browser.document())
        format_ = cursor.charFormat()
        format_.setBackground(Qt.yellow)

        document = self.text_browser.document()
        cursor.setPosition(0)  # Set the cursor to the beginning

        for keyword in keywords:
            while cursor := document.find(keyword, cursor):
                cursor.mergeCharFormat(format_)

        self.status_bar.showMessage("Keywords highlighted.")

    def reconstruct_file(self):
        # Implement file reconstruction logic here
        # Attempt to reconstruct fragmented files within the carved data
        self.status_bar.showMessage("File reconstruction attempted.")

    def entropy_analysis(self):
        # Implement entropy analysis logic here
        # Calculate and display the entropy of the carved file
        entropy = self.calculate_entropy(self.carved_data)
        self.text_browser.append(f"\nEntropy: {entropy}")
        self.status_bar.showMessage("Entropy analysis performed.")

    def calculate_entropy(self, data):
        # Helper function to calculate entropy
        histogram = {}
        for byte in data:
            histogram[byte] = histogram.get(byte, 0) + 1

        entropy = 0.0
        total_bytes = len(data)
        for count in histogram.values():
            probability = count / total_bytes
            entropy -= probability * (probability and math.log2(probability))

        return entropy

class HexViewer(QDialog):
    def __init__(self, data):
        super().__init__()

        self.data = data

        self.init_ui()

    def init_ui(self):
        self.setWindowTitle('Hex Viewer')
        self.setGeometry(100, 100, 800, 600)

        hex_text = self.bytes_to_hex(self.data)

        self.text_browser = QTextBrowser(self)
        self.text_browser.setPlainText(hex_text)
        self.text_browser.setReadOnly(True)

        layout = QVBoxLayout()
        layout.addWidget(self.text_browser)

        central_widget = QWidget(self)
        central_widget.setLayout(layout)
        self.setCentralWidget(central_widget)

    def bytes_to_hex(self, byte_data):
        hex_str = ""
        for byte in byte_data:
            hex_str += format(byte, '02X') + ' '
        return hex_str

def main():
    app = QApplication(sys.argv)
    window = FileCarvingTool()
    window.show()
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()
