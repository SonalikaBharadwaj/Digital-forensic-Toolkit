import sys
import os
import hashlib
import difflib
from PyQt5.QtWidgets import QApplication, QMainWindow, QTextEdit, QVBoxLayout, QFileDialog, \
                            QAction, QWidget, QLabel, QSplitter, QTextBrowser, QLineEdit, QPushButton, QInputDialog, \
                            QStatusBar
from PyQt5.QtGui import QTextCursor, QTextDocument, QTextCharFormat, QColor
from PyQt5.QtCore import Qt


class HexViewer(QMainWindow):
    def __init__(self):
        super().__init__()

        self.file_path = ""
        self.hex_edit_mode = False
        self.edited_data = bytearray()

        self.init_ui()

    def init_ui(self):
        self.setWindowTitle('Hex Viewer')
        self.setGeometry(100, 100, 1000, 600)

        self.text_edit = QTextEdit(self)
        self.text_edit.setReadOnly(True)
        self.text_edit.cursorPositionChanged.connect(self.update_status_bar)

        self.info_label = QLabel(self)
        self.info_label.setText("File Information")

        self.text_browser = QTextBrowser(self)
        self.text_browser.setReadOnly(True)

        self.splitter = QSplitter(self)
        self.splitter.addWidget(self.text_edit)
        self.splitter.addWidget(self.text_browser)
        self.splitter.setSizes([500, 500])

        self.init_menu()
        self.init_toolbar()

        self.status_bar = QStatusBar(self)
        self.setStatusBar(self.status_bar)

        central_widget = QWidget(self)
        layout = QVBoxLayout(central_widget)
        layout.addWidget(self.splitter)

        self.setCentralWidget(central_widget)

    def init_menu(self):
        menubar = self.menuBar()
        file_menu = menubar.addMenu('File')

        open_action = QAction('Open', self)
        open_action.triggered.connect(self.open_file)
        file_menu.addAction(open_action)

        search_action = QAction('Search', self)
        search_action.triggered.connect(self.search_text)
        file_menu.addAction(search_action)

        bookmarks_action = QAction('Add Bookmark', self)
        bookmarks_action.triggered.connect(self.add_bookmark)
        file_menu.addAction(bookmarks_action)

        checksum_action = QAction('Checksum (SHA-256)', self)
        checksum_action.triggered.connect(self.calculate_checksum)
        file_menu.addAction(checksum_action)

        frequency_action = QAction('Byte Frequency Analysis', self)
        frequency_action.triggered.connect(self.byte_frequency_analysis)
        file_menu.addAction(frequency_action)

        file_menu.addSeparator()

        hex_edit_action = QAction('Hex Edit', self)
        hex_edit_action.setCheckable(True)
        hex_edit_action.toggled.connect(self.toggle_hex_edit_mode)
        file_menu.addAction(hex_edit_action)

        file_menu.addSeparator()

        structure_viewer_action = QAction('Structure Viewer', self)
        structure_viewer_action.triggered.connect(self.structure_viewer)
        file_menu.addAction(structure_viewer_action)

        metadata_action = QAction('Metadata Extraction', self)
        metadata_action.triggered.connect(self.extract_metadata)
        file_menu.addAction(metadata_action)

        file_comparison_action = QAction('File Comparison', self)
        file_comparison_action.triggered.connect(self.file_comparison)
        file_menu.addAction(file_comparison_action)

        file_menu.addSeparator()

        save_changes_action = QAction('Save Changes', self)
        save_changes_action.triggered.connect(self.save_changes)
        file_menu.addAction(save_changes_action)

    def init_toolbar(self):
        toolbar = self.addToolBar('Toolbar')

        back_button = QPushButton('Back', self)
        back_button.clicked.connect(self.text_edit.undo)
        toolbar.addWidget(back_button)

    def open_file(self):
        options = QFileDialog.Options()
        file_path, _ = QFileDialog.getOpenFileName(self, 'Open File', '', 'All Files (*)', options=options)

        if file_path:
            with open(file_path, 'rb') as file:
                data = file.read()

            self.edited_data = bytearray(data)
            hex_data = self.hex_format(data)
            self.text_edit.setPlainText(hex_data)

            file_info = f"File Path: {file_path}\nFile Size: {len(data)} bytes"
            self.info_label.setText(file_info)

            self.file_path = file_path
            self.hex_edit_mode = False  # Reset hex edit mode
            self.update_hex_edit_mode()

    def hex_format(self, data, chunk_size=16):
        lines = []
        for i in range(0, len(data), chunk_size):
            chunk = data[i:i + chunk_size]
            hex_line = ' '.join(f'{byte:02X}' for byte in chunk)
            ascii_line = ''.join(chr(byte) if 32 <= byte < 127 else '.' for byte in chunk)
            lines.append(f'{hex_line.ljust(3 * chunk_size)} | {ascii_line}')
        return '\n'.join(lines)

    def search_text(self):
        text, ok_pressed = QInputDialog.getText(self, "Search", "Enter text:")
        if ok_pressed and text:
            cursor = self.text_edit.document().find(text)
            if not cursor.isNull():
                self.text_edit.setTextCursor(cursor)
                self.text_edit.setFocus()
            else:
                print("Text not found.")

    def add_bookmark(self):
        cursor = self.text_edit.textCursor()
        offset = cursor.position()
        comment, ok_pressed = QInputDialog.getText(self, "Add Bookmark", "Enter comment:")
        if ok_pressed and comment:
            bookmark_text = f"Bookmark: {comment} at offset {offset}\n"
            self.text_browser.moveCursor(QTextCursor.End)
            self.text_browser.insertPlainText(bookmark_text)

    def calculate_checksum(self):
        if self.file_path:
            sha256 = hashlib.sha256()
            with open(self.file_path, 'rb') as file:
                while (chunk := file.read(8192)):
                    sha256.update(chunk)
            checksum = sha256.hexdigest()
            self.info_label.setText(f"File Checksum (SHA-256): {checksum}")

    def byte_frequency_analysis(self):
        if self.file_path:
            with open(self.file_path, 'rb') as file:
                data = file.read()

            byte_counts = [0] * 256
            for byte in data:
                byte_counts[byte] += 1

            byte_freq_text = "\n".join([f"Byte {i:02X}: {count}" for i, count in enumerate(byte_counts) if count > 0])
            self.text_browser.setPlainText(byte_freq_text)

    def toggle_hex_edit_mode(self, checked):
        self.hex_edit_mode = checked
        self.update_hex_edit_mode()

    def update_hex_edit_mode(self):
        if self.hex_edit_mode:
            cursor = self.text_edit.textCursor()
            cursor.clearSelection()
            self.text_edit.setTextCursor(cursor)
            self.text_edit.setReadOnly(False)
            self.status_bar.showMessage("Hex Edit Mode: Enabled")
        else:
            self.text_edit.setReadOnly(True)
            self.status_bar.clearMessage()

    def update_status_bar(self):
        if not self.hex_edit_mode:
            cursor = self.text_edit.textCursor()
            position = cursor.position()
            self.status_bar.showMessage(f"Offset: {position}")

    def structure_viewer(self):
        if self.file_path:
            with open(self.file_path, 'rb') as file:
                data = file.read()

            # Display the first 32 bytes as an example
            structure_text = self.hex_format(data[:32])
            self.text_browser.setPlainText(structure_text)

    def extract_metadata(self):
        if self.file_path and self.file_path.lower().endswith(('.png', '.jpg', '.jpeg')):
            from PIL import Image

            try:
                image = Image.open(self.file_path)
                metadata = {
                    "Format": image.format,
                    "Size": image.size,
                    "Mode": image.mode,
                    # Add more metadata fields as needed
                }
                metadata_text = "\n".join([f"{key}: {value}" for key, value in metadata.items()])
                self.text_browser.setPlainText(metadata_text)
            except Exception as e:
                self.text_browser.setPlainText(f"Error extracting metadata: {str(e)}")

    def file_comparison(self):
        options = QFileDialog.Options()
        file_path2, _ = QFileDialog.getOpenFileName(self, 'Compare File', '', 'All Files (*)', options=options)

        if file_path2:
            with open(self.file_path, 'rb') as file1, open(file_path2, 'rb') as file2:
                data1 = file1.read()
                data2 = file2.read()

            differ = difflib.Differ()
            diff = list(differ.compare(data1.decode('latin-1'), data2.decode('latin-1')))

            diff_text = '\n'.join(diff)
            self.text_browser.setPlainText(diff_text)

    def save_changes(self):
        if self.file_path and self.hex_edit_mode:
            try:
                with open(self.file_path, 'wb') as file:
                    file.write(self.edited_data)
                self.status_bar.showMessage("Changes saved successfully.")
            except Exception as e:
                self.status_bar.showMessage(f"Error saving changes: {str(e)}")


def main():
    app = QApplication(sys.argv)
    window = HexViewer()
    window.show()
    sys.exit(app.exec_())


if __name__ == '__main__':
    main()
