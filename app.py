import os
import subprocess
import zipfile
import plistlib
import re
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QVBoxLayout, QLabel, QPushButton, QFileDialog,
    QTextEdit, QWidget, QHBoxLayout, QMessageBox, QSpacerItem, QSizePolicy
)
from PyQt6.QtCore import QThread, pyqtSignal

class JadxWorker(QThread):
    finished = pyqtSignal(str, str)  # emits (output_path, error_message)

    def __init__(self, jadx_path, apk_path, output_dir):
        super().__init__()
        self.jadx_path = jadx_path
        self.apk_path = apk_path
        self.output_dir = output_dir

    def run(self):
        try:
            result = subprocess.run(
                [self.jadx_path, "-d", self.output_dir, self.apk_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            error = result.stderr.decode() if result.returncode != 0 else ""
            self.finished.emit(self.output_dir, error)
        except Exception as e:
            self.finished.emit(self.output_dir, str(e))

class CryptoAnalyzer(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Cryptographic Vulnerability Analyzer")
        self.setGeometry(100, 100, 1024, 768)

        # UI Components
        self.file_label = QLabel("No file selected")
        self.file_btn = QPushButton("Upload APK/XAPK/APKM/IPA")
        self.result_display = QTextEdit()
        self.progress_label = QLabel("Idle")
        self.reset_btn = QPushButton("Reset")

        # Layouts
        header_layout = QHBoxLayout()
        header_layout.addWidget(self.file_label)

        button_layout = QHBoxLayout()
        button_layout.addWidget(self.file_btn)
        button_layout.addWidget(self.reset_btn)

        spacer = QSpacerItem(40, 20, QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum)
        button_layout.addItem(spacer)

        layout = QVBoxLayout()
        layout.addLayout(header_layout)
        layout.addLayout(button_layout)
        layout.addWidget(self.progress_label)
        layout.addWidget(self.result_display)

        # Connections
        self.file_btn.clicked.connect(self.analyze_file)
        self.reset_btn.clicked.connect(self.reset_app)

        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)

    def log_message(self, message):
        self.result_display.append(message)
        QApplication.processEvents()

    def analyze_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select Mobile App", "", "Mobile Apps (*.apk *.xapk *.apkm *.ipa)")
        if file_path:
            self.file_label.setText(f"File: {os.path.basename(file_path)}")
            self.result_display.clear()
            self.log_message("\U0001F4CC Starting analysis...\n")
            self.progress_label.setText("Analyzing...")

            if file_path.endswith(".apk"):
                self.analyze_apk(file_path)
            elif file_path.endswith(".xapk") or file_path.endswith(".apkm"):
                self.extract_and_analyze_xapk(file_path)
            elif file_path.endswith(".ipa"):
                self.analyze_ipa(file_path)
            else:
                self.log_message("\u274C Unsupported file format.")
                self.progress_label.setText("Analysis failed: Unsupported file format")

    def analyze_apk(self, apk_path):
        decompile_dir = os.path.join(os.getcwd(), "decompiled_apk")
        os.makedirs(decompile_dir, exist_ok=True)

        self.log_message(f"\U0001F50D Decompiling APK: {os.path.basename(apk_path)}")

        jadx_path = "C:/Users/nikku/OneDrive/Desktop/CryptographicAnalyzer/jadx-1.5.1/bin/jadx.bat"

        self.jadx_thread = JadxWorker(jadx_path, apk_path, decompile_dir)
        self.jadx_thread.finished.connect(self.on_decompilation_done)
        self.jadx_thread.start()

    def on_decompilation_done(self, output_dir, error):
        if error:
            self.log_message(f"\u274C jadx decompilation failed:\n{error}")
            self.progress_label.setText("Decompilation failed")
        else:
            self.log_message("\u2705 Decompilation Complete. Analyzing Code...")
            self.analyze_decompiled_code(output_dir)

    def extract_and_analyze_xapk(self, xapk_path):
        extract_dir = os.path.join(os.getcwd(), "extracted_xapk")
        self.log_message(f"\U0001F4E6 Extracting XAPK/APKM: {os.path.basename(xapk_path)}")
        try:
            with zipfile.ZipFile(xapk_path, 'r') as zip_ref:
                zip_ref.extractall(extract_dir)

            for root, _, files in os.walk(extract_dir):
                for file in files:
                    if file.endswith(".apk"):
                        apk_path = os.path.join(root, file)
                        self.log_message(f"\U0001F4C2 Found APK: {file}")
                        self.analyze_apk(apk_path)
                        return

            self.log_message("\u274C No APK found in extracted XAPK.")
            self.progress_label.setText("No APK found in archive.")
        except Exception as e:
            self.log_message(f"\u26A0\uFE0F Error Extracting XAPK: {str(e)}")
            self.progress_label.setText("Extraction error")

    def analyze_ipa(self, ipa_path):
        try:
            findings = []
            with zipfile.ZipFile(ipa_path) as z:
                for name in z.namelist():
                    if "Info.plist" in name:
                        plist_data = z.read(name)
                        plist = plistlib.loads(plist_data)
                        if plist.get("NSAppTransportSecurity", {}).get("NSAllowsArbitraryLoads", False):
                            findings.append("\u26A0\uFE0F Insecure transport security (HTTP allowed)")
                            self.log_message("\u26A0\uFE0F Found insecure transport settings in Info.plist")

                    if name.endswith(".app/"):
                        binary_data = z.read(name)
                        if b"CommonCrypto" not in binary_data:
                            findings.append("\u26A0\uFE0F Missing Apple's CommonCrypto framework")
                            self.log_message("\u26A0\uFE0F Missing Apple's CommonCrypto framework in binary")

            self.log_message("\u2705 iOS Analysis Complete.")
            self.display_results(self._generate_report(findings))
            self.progress_label.setText("Analysis Complete")
        except Exception as e:
            self.log_message(f"\u26A0\uFE0F iOS Analysis Error: {str(e)}")
            self.progress_label.setText("iOS analysis failed")

    def analyze_decompiled_code(self, decompiled_dir):
        findings = []
        crypto_patterns = {
            "ECB Mode": r"AES/ECB",
            "Weak RSA": r"RSA\\s*\\(\\s*2048\\s*\\)",
            "Insecure PRNG": r"SecureRandom.getInstance\\(\\\"SHA1PRNG\\\"\\)"
        }

        self.log_message("\U0001F4D1 Scanning for cryptographic vulnerabilities...")

        for pattern_name, pattern in crypto_patterns.items():
            for root, _, files in os.walk(decompiled_dir):
                for file in files:
                    if not file.endswith(".java") and not file.endswith(".smali"):
                        continue
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                            content = f.read()
                            if re.search(pattern, content):
                                findings.append(f"\u26A0\uFE0F {pattern_name} detected in {file}")
                                self.log_message(f"\u26A0\uFE0F Found {pattern_name} in {file}")
                    except:
                        continue

        self.log_message("\u2705 Analysis complete.")
        self.display_results(self._generate_report(findings))
        self.progress_label.setText("Analysis Complete")

    def _generate_report(self, findings):
        if not findings or not isinstance(findings, list):
            return "\u2705 No cryptographic vulnerabilities detected"

        report = "<b>Cryptographic Analysis Results</b><hr/>"
        report += f"Total Issues Found: {len(findings)}<br/><ul>"
        for finding in findings:
            report += f"<li>{finding}</li>"
        report += "</ul><br/><b>Recommended Fixes:</b><ul>"
        report += "<li>Use AES-GCM instead of ECB</li>"
        report += "<li>Upgrade to RSA-4096 or ECC</li>"
        report += "<li>Use HKDF for key derivation</li>"
        report += "<li>Enable Certificate Pinning</li>"
        report += "</ul>"
        return report

    def display_results(self, text):
        self.result_display.setHtml(text)
        self.result_display.ensureCursorVisible()

    def reset_app(self):
        self.file_label.setText("No file selected")
        self.result_display.clear()
        self.progress_label.setText("Idle")

if __name__ == "__main__":
    app = QApplication([])
    window = CryptoAnalyzer()
    window.show()
    app.exec()