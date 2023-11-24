# File Explorer

import json
import sys
import os
import hashlib
import magic
import exifread
import pytsk3
import PyPDF2
from PyQt5.QtWidgets import (
    QApplication,
    QMainWindow,
    QTreeView,
    QFileSystemModel,
    QVBoxLayout,
    QWidget,
    QLabel,
    QLineEdit,
    QPushButton,
    QTextBrowser,
    QAction,
    QToolBar
)
from PyQt5.QtCore import Qt, QModelIndex, QItemSelectionModel


class ForensicFileSystemExplorer(QMainWindow):
    def __init__(self):
        super(ForensicFileSystemExplorer, self).__init__()

        self.setWindowTitle("Digital Forensic File Explorer")
        self.setGeometry(100, 100, 800, 600)

        # Create a file system model
        self.file_system_model = QFileSystemModel()
        self.file_system_model.setRootPath('')  # Set root path as an empty string for the entire file system

        # Create a tree view and set the model
        self.tree_view = QTreeView()
        self.tree_view.setModel(self.file_system_model)
        self.tree_view.setRootIndex(self.file_system_model.index(''))  # Set the root index

        # Additional forensic features
        self.selected_file_label = QLabel("Selected File:")
        self.selected_file_info_label = QLabel()

        self.search_label = QLabel("Search for files:")
        self.search_input = QLineEdit()
        self.search_button = QPushButton("Search")
        self.search_button.clicked.connect(self.search_files)

        self.file_hash_label = QLabel("File Hash:")
        self.file_hash_value = QLabel()

        self.file_type_label = QLabel("File Type:")
        self.file_type_value = QLabel()

        self.metadata_label = QLabel("Metadata:")
        self.metadata_viewer = QTextBrowser()

        # Back button
        back_action = QAction("Back", self)
        back_action.triggered.connect(self.go_back)

        # Create toolbar
        toolbar = QToolBar(self)
        toolbar.addAction(back_action)

        # Set up the layout
        central_widget = QWidget(self)
        layout = QVBoxLayout(central_widget)
        layout.addWidget(toolbar)  # Add the toolbar
        layout.addWidget(self.tree_view)
        layout.addWidget(self.selected_file_label)
        layout.addWidget(self.selected_file_info_label)
        layout.addWidget(self.file_hash_label)
        layout.addWidget(self.file_hash_value)
        layout.addWidget(self.file_type_label)
        layout.addWidget(self.file_type_value)
        layout.addWidget(self.metadata_label)
        layout.addWidget(self.metadata_viewer)
        layout.addWidget(self.search_label)
        layout.addWidget(self.search_input)
        layout.addWidget(self.search_button)
        self.setCentralWidget(central_widget)

        # Connect the item selection signal to the custom slot
        self.tree_view.selectionModel().selectionChanged.connect(self.display_file_info)

    def go_back(self):
        # Handle back button functionality here
        pass

    def display_file_info(self):
        selected_indexes = self.tree_view.selectionModel().selectedIndexes()
        if selected_indexes:
            selected_file_path = self.file_system_model.filePath(selected_indexes[0])
            self.selected_file_info_label.setText(f"Path: {selected_file_path}")

            # Display file hash
            file_hash = self.calculate_file_hash(selected_file_path)
            self.file_hash_value.setText(json.dumps(file_hash, indent=2))  # Convert dict to string

            # Display file type
            file_type = self.detect_file_type(selected_file_path)
            self.file_type_value.setText(file_type)

            # Display metadata
            metadata = self.extract_metadata(selected_file_path)
            self.metadata_viewer.setPlainText(metadata)

    def calculate_file_hash(self, file_path):
        hash_algorithms = ["md5", "sha1", "sha256"]
        hash_values = {}

        if os.path.isdir(file_path):
            for root, dirs, files in os.walk(file_path):
                for file_name in files:
                    file_path = os.path.join(root, file_name)
                    hash_values[file_name] = self.calculate_single_file_hash(file_path, hash_algorithms)
        else:
            hash_values[os.path.basename(file_path)] = self.calculate_single_file_hash(file_path, hash_algorithms)

        return hash_values

    def calculate_single_file_hash(self, file_path, hash_algorithms):
        file_hashes = {}
        for algorithm in hash_algorithms:
            hash_object = hashlib.new(algorithm)
            with open(file_path, "rb") as f:
                while chunk := f.read(8192):
                    hash_object.update(chunk)
            file_hashes[algorithm] = hash_object.hexdigest()
        return file_hashes

    def detect_file_type(self, file_path):
        mime = magic.Magic()
        return mime.from_file(file_path)

    def extract_metadata(self, file_path):
        if file_path.lower().endswith(('.jpg', '.jpeg', '.png', '.gif')):
            return self.extract_image_metadata(file_path)
        elif file_path.lower().endswith('.pdf'):
            return self.extract_pdf_metadata(file_path)
        elif file_path.lower().endswith('.dd'):
            return self.extract_disk_image_metadata(file_path)
        else:
            return "Metadata extraction not supported for this file type."

    def extract_image_metadata(self, file_path):
        metadata_str = ""
        with open(file_path, 'rb') as file:
            tags = exifread.process_file(file)
            for tag, value in tags.items():
                metadata_str += f"{tag}: {value}\n"
        return metadata_str

    def extract_pdf_metadata(self, file_path):
        metadata_str = ""
        with open(file_path, 'rb') as file:
            pdf_reader = PyPDF2.PdfFileReader(file)
            metadata = pdf_reader.getDocumentInfo()
            for key, value in metadata.items():
                metadata_str += f"{key}: {value}\n"
        return metadata_str

    def extract_disk_image_metadata(self, file_path):
        metadata_str = ""
        try:
            img_info = pytsk3.Img_Info(file_path)
            fs_info = pytsk3.FS_Info(img_info)

            for directory_entry in fs_info.open_dir(path="/"):
                metadata_str += f"Name: {directory_entry.info.name.name.decode()}\n"
                metadata_str += f"Size: {directory_entry.info.meta.size}\n"
                metadata_str += f"Inode: {directory_entry.info.meta.addr}\n"
                metadata_str += "\n"

        except Exception as e:
            metadata_str = f"Error extracting metadata: {str(e)}"

        return metadata_str

    def search_files(self):
        search_text = self.search_input.text()
        if search_text:
            root_index = self.file_system_model.index('')
            self.highlight_matching_items(root_index, search_text)

    def highlight_matching_items(self, parent_index, search_text):
        selection_model = self.tree_view.selectionModel()

        selected_indexes = []
        for row in range(self.file_system_model.rowCount(parent_index)):
            index = self.file_system_model.index(row, 0, parent_index)
            file_name = self.file_system_model.fileName(index).lower()

            if search_text.lower() in file_name:
                selected_indexes.append(index)

        if selected_indexes:
            first_index = selected_indexes[0]
            last_index = selected_indexes[-1]

            selection = QItemSelection(first_index, last_index)
            selection_model.select(
                selection, QItemSelectionModel.Select | QItemSelectionModel.Rows
            )
        else:
            selection_model.clearSelection()

        for index in selected_indexes:
            self.highlight_matching_items(index, search_text)




def main():
    app = QApplication(sys.argv)
    window = ForensicFileSystemExplorer()
    window.show()
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()
