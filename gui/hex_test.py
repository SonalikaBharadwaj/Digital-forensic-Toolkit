import sys
import os
import hashlib
from PyQt5.QtWidgets import QApplication
from PyQt5.QtTest import QTest
from PyQt5.QtCore import Qt
import pytest
from your_hex_viewer_module import HexViewer  # Replace with your actual module name

@pytest.fixture
def app(qtbot):
    application = QApplication(sys.argv)
    widget = HexViewer()
    qtbot.addWidget(widget)
    return application, widget

def test_open_file_dialog(app, qtbot, tmp_path):
    application, widget = app
    file_path = str(tmp_path / "test_file.txt")
    file_content = b"Test content for file."

    # Mock the file dialog response
    with open(file_path, 'wb') as file:
        file.write(file_content)

    qtbot.mouseClick(widget.toolBar.widgetForAction(widget.toolBar.actions()[1]), Qt.LeftButton)
    qtbot.wait(500)  # Wait for the dialog to open
    qtbot.keyClicks(widget, file_path)
    qtbot.keyClick(widget, Qt.Key_Enter)

    # Check if the file information label is updated
    assert widget.info_label.text() == f"File Path: {file_path}\nFile Size: {len(file_content)} bytes"

def test_hex_edit_mode_toggle(app, qtbot):
    application, widget = app

    # Click on the Hex Edit button
    hex_edit_button = widget.toolBar.widgetForAction(widget.toolBar.actions()[3])
    qtbot.mouseClick(hex_edit_button, Qt.LeftButton)

    # Check if hex edit mode is enabled
    assert widget.hex_edit_mode is True

    # Click on the Hex Edit button again
    qtbot.mouseClick(hex_edit_button, Qt.LeftButton)

    # Check if hex edit mode is disabled
    assert widget.hex_edit_mode is False

def test_search_text(app, qtbot):
    application, widget = app

    # Enter some text in the search dialog
    search_text = "Test"
    qtbot.keyClicks(widget, search_text)

    # Click on the Search button
    search_button = widget.toolBar.widgetForAction(widget.toolBar.actions()[2])
    qtbot.mouseClick(search_button, Qt.LeftButton)

    # Check if the text is found and cursor is updated
    assert widget.text_edit.textCursor().selectedText() == search_text

def test_add_bookmark(app, qtbot):
    application, widget = app

    # Click on the Add Bookmark button
    bookmark_button = widget.toolBar.widgetForAction(widget.toolBar.actions()[4])
    qtbot.mouseClick(bookmark_button, Qt.LeftButton)

    # Enter a comment in the bookmark dialog
    comment = "Test Bookmark"
    qtbot.keyClicks(widget, comment)

    # Press Enter to add the bookmark
    qtbot.keyClick(widget, Qt.Key_Enter)

    # Check if the bookmark is added to the text browser
    assert f"Bookmark: {comment}" in widget.text_browser.toPlainText()

def test_calculate_checksum(app, qtbot, tmp_path):
    application, widget = app
    file_path = str(tmp_path / "test_file.txt")
    file_content = b"Test content for file."

    with open(file_path, 'wb') as file:
        file.write(file_content)

    # Open the test file
    widget.file_path = file_path
    widget.calculate_checksum()

    # Check if the checksum is displayed in the info label
    sha256 = hashlib.sha256(file_content).hexdigest()
    assert widget.info_label.text() == f"File Checksum (SHA-256): {sha256}"

def test_byte_frequency_analysis(app, qtbot, tmp_path):
    application, widget = app
    file_path = str(tmp_path / "test_file.txt")
    file_content = b"Test content for file."

    with open(file_path, 'wb') as file:
        file.write(file_content)

    # Open the test file
    widget.file_path = file_path
    widget.byte_frequency_analysis()

    # Check if byte frequency analysis is displayed in the text browser
    byte_freq_text = widget.text_browser.toPlainText()
    for byte in range(256):
        byte_str = f"Byte {byte:02X}"
        if byte in file_content:
            assert byte_str in byte_freq_text
        else:
            assert byte_str not in byte_freq_text

def test_save_changes(app, qtbot, tmp_path):
    application, widget = app
    file_path = str(tmp_path / "test_file.txt")
    original_content = b"Original content for file."
    edited_content = b"Edited content for file."

    with open(file_path, 'wb') as file:
        file.write(original_content)

    # Open the test file
    widget.file_path = file_path
    widget.edited_data = bytearray(original_content)

    # Enable hex edit mode
    widget.hex_edit_mode = True
    widget.update_hex_edit_mode()

    # Simulate editing content
    qtbot.keyClicks(widget.text_edit, edited_content.decode('latin-1'))

    # Click on the Save Changes button
    save_changes_button = widget.toolBar.widgetForAction(widget.toolBar.actions()[9])
    qtbot.mouseClick(save_changes_button, Qt.LeftButton)

    # Read the file after saving changes
    with open(file_path, 'rb') as file:
        saved_content = file.read()

    # Check if the content is successfully edited and saved
    assert saved_content == edited_content

if __name__ == '__main__':
    pytest.main()
