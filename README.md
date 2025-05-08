# ChronoBrowser

ChronoBrowser is a Python script designed to parse browser history artifacts from Chromium-based browsers (e.g., Chrome, Edge) and Firefox. It extracts detailed browsing history, downloads, search keywords, and preferences, presenting the data in a user-friendly GUI built with PyQt5. The script also supports exporting parsed data to CSV files for further analysis.

## Features

- **Browser Support**: Parses history from Chromium-based browsers (Chrome, Edge) and Firefox.
- **Data Extraction**:
  - Browsing history with timestamps, URLs, titles, and redirection chains.
  - Downloads with file hashes and metadata.
  - Search keywords extracted from URLs.
  - Browser preferences, including sync status and account details.
- **GUI Interface**: Built with PyQt5, offering tabs for history, downloads, preferences, and search keywords.
- **Search and Filter**: Query parsed data by keywords, dates, or file types (e.g., `.pdf`).
- **Export to CSV**: Save parsed data to CSV files for external analysis.
- **Logging**: Detailed logging for debugging and tracking parsing activities.

## Installation

### Prerequisites
- **Python**: Version 3.6 or higher.
- **PyQt5**: For the GUI interface.
- **Operating System**: Tested on Windows; may work on macOS/Linux with adjustments.

### Steps
1. **Clone the Repository**:
   ```bash
   git clone https://github.com/your-username/ChronoBrowse.git
   cd ChronoBrowse
   ```

2. **Install Dependencies**:
   Install the required Python packages using pip:
   ```bash
   pip install PyQt5
   ```
   No additional dependencies are required, as the script uses standard Python libraries (`sqlite3`, `os`, `csv`, etc.).

3. **Ensure Icon File**:
   The script uses `chrono.ico` for the GUI icon. Ensure this file is in the same directory as `chronobrowse.py`. If you need a replacement icon, you can download one or modify the script to remove the icon dependency:
   ```python
   # Comment out or remove this line in chronobrowse.py if chrono.ico is unavailable
   app.setWindowIcon(QIcon('chrono.ico'))
   ```

## Usage

1. **Prepare Browser History Artifacts**:
   - Locate the browser history files:
     - **Chromium-based (Chrome/Edge)**: Typically `History` file in `C:\Users\<YourUser>\AppData\Local\Google\Chrome\User Data\Default` (or similar for Edge).
     - **Firefox**: `places.sqlite` in `C:\Users\<YourUser>\AppData\Roaming\Mozilla\Firefox\Profiles\<ProfileName>`.
   - Copy these files to a folder (e.g., `artifacts/`) for parsing. **Note**: Ensure the browser is closed to avoid database lock issues.

2. **Run the Script**:
   ```bash
   python chronobrowse.py
   ```

3. **Interact with the GUI**:
   - **Select Artifact Folder**: Choose the folder containing the browser history files (e.g., `artifacts/`).
   - **Select Output Directory**: Choose where to save the exported CSV files.
   - **Browser Selection**: Choose the browser type (`Auto`, `Chromium`, or `Firefox`). `Auto` attempts to detect the browser automatically.
   - **Parse Artifacts**: Click "Parse Artifacts" to process the files.
   - **View Results**: Data appears in tabs (History, Downloads, Preferences, Keyword Searched).
   - **Search and Filter**: Enter a query (e.g., a keyword, date like `2025-05-06`, or file type like `.pdf`) to filter results.
   - **Export Results**: Export filtered or full data to CSV files.

4. **Log Output**:
   - The script generates a log file (`parse_browser_history.log`) in the project directory for debugging. Check this file for errors or parsing details.

## Screenshots

`![Chronobrowser GUI(https://raw.githubusercontent.com/sazznyx/ChronoBrowser/main/screenshots/ss1.jpg))`.)*

## Project Structure

- `chronobrowse.py`: The main script containing all parsing logic and GUI code.
- `chrono.ico`: Icon file for the GUI window.
- `build.bat`: Batch script for building the project into an executable (optional).
- `.gitignore`: Ignores temporary files, build artifacts, and sensitive data.

## Limitations

- **Browser Support**: Currently supports Chromium-based browsers and Firefox. Other browsers (e.g., Safari) are not supported.
- **File Access**: The script requires read access to browser history files, which may be locked if the browser is running.
- **Platform**: Primarily tested on Windows. macOS/Linux users may need to adjust file paths and ensure PyQt5 compatibility.

## Contributing

Contributions are welcome! To contribute:
1. Fork the repository.
2. Create a new branch (`git checkout -b feature/your-feature`).
3. Make your changes and commit (`git commit -m "Add your feature"`).
4. Push to your fork (`git push origin feature/your-feature`).
5. Open a pull request on GitHub.

Please ensure your code follows the existing style and includes appropriate comments. If adding new features, update this README accordingly.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

*(Note: You’ll need to create a `LICENSE` file in your repository. GitHub provides templates for common licenses like MIT, Apache, or GPL when you add a new file named `LICENSE`.)*

## Acknowledgments

- Built with [PyQt5](https://www.riverbankcomputing.com/software/pyqt/) for the GUI.
- Inspired by the need for easy browser history analysis in digital forensics.

## Contact

For questions or issues, please open an issue on GitHub or contact [your-email@example.com](mailto:your-email@example.com).

---
