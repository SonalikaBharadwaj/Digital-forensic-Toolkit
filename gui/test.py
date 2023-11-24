import sys
import os
import pytest
from PyQt5.QtWidgets import QApplication, QLineEdit, QPushButton, QTreeView
from PyQt5.QtTest import QTest
from PyQt5.QtCore import Qt
from main import ForensicFileSystemExplorer


@pytest.fixture
def qtbot(qtbot):
    return qtbot

@pytest.fixture
def app(qtbot):
    application = QApplication(sys.argv)
    window = ForensicFileSystemExplorer()
    qtbot.addWidget(window)
    window.show()
    return application, window

def test_search_files(qtbot, app):
    application, window = app

    # Print out the names of widgets to help diagnose the issue
    print("Available widgets:", [child.objectName() for child in window.children()])

    # Simulate a user entering text in the search input
    search_input = window.findChild(QLineEdit, "search_input")
    if search_input is None:
        pytest.fail("Search input not found")

    search_input.setText("example.txt")

    # Simulate a user clicking the search button
    search_button = window.findChild(QPushButton, "search_button")
    if search_button is None:
        pytest.fail("Search button not found")

    qtbot.mouseClick(search_button, Qt.LeftButton)

    # Ensure that the search has been performed and the matching item is selected
    tree_view = window.findChild(QTreeView, "tree_view")
    if tree_view is None:
        pytest.fail("Tree view not found")

    selected_indexes = tree_view.selectionModel().selectedIndexes()
    assert len(selected_indexes) == 1
    assert os.path.basename(window.file_system_model.filePath(selected_indexes[0])) == "example.txt"

if __name__ == '__main__':
    pytest.main(['-v', '--tb=no', 'test.py'])
