"""
Sandboxing GUI - Orquestador de análisis de muestras en VMs QEMU
------------------------------------------------------------------
Interfaz para configurar y lanzar una VM QEMU (snapshot descartable)
en la que se ejecuta una muestra a analizar.

Requisitos:
    pip install PySide6
"""

import sys
import os
import subprocess
import threading
# pyrefly: ignore [missing-import]
import cpp
from datetime import datetime
from analyzer import MalwareAnalyzer


# pyrefly: ignore [missing-import]
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QGridLayout, QLabel, QLineEdit, QPushButton, QFileDialog,
    QGroupBox, QPlainTextEdit, QProgressBar, QStatusBar, QFrame,
    QSizePolicy, QSpacerItem, QSpinBox
)
from PySide6.QtCore import Qt, QObject, Signal
from PySide6.QtGui import QFont, QPalette, QColor


# ---------------------------------------------------------------------------
# Modelo de datos: rutas necesarias para armar la sandbox
# ---------------------------------------------------------------------------
class Paths:
    """Guarda las rutas configuradas por el usuario."""

    def __init__(self):
        self.qemu_path = ""
        self.vm_path = ""        # disco base .qcow2 (imagen limpia)
        self.malware_path = ""   # muestra a analizar
        self.sandbox_path = ""   # disco overlay descartable (.qcow2)

    def get_paths(self):
        return self.qemu_path, self.vm_path, self.malware_path, self.sandbox_path

    def is_complete(self):
        return all(self.get_paths())


# ---------------------------------------------------------------------------
# Lógica de "negocio": creación / lanzamiento de la sandbox
# Comunica progreso a la UI mediante señales (thread-safe en Qt)
# ---------------------------------------------------------------------------
class SandboxWorker(QObject):
    log = Signal(str)
    finished = Signal(bool)  # True = éxito, False = error
    progress = Signal(int)

    def __init__(self, paths: Paths, timeout_seconds: int = 120):
        super().__init__()
        self.paths = paths
        self.timeout_seconds = timeout_seconds

    def run(self):
        qemu_path, vm_path, malware_path, sandbox_path = self.paths.get_paths()
        try:
            self.log.emit(f"[{self._ts()}] Verificando rutas...")
            for p, name in [
                (qemu_path, "QEMU"), (vm_path, "Imagen base VM"),
                (malware_path, "Muestra"),
            ]:
                if not os.path.exists(p):
                    raise FileNotFoundError(f"No existe: {name} -> {p}")
            self.progress.emit(10)

            # ── Análisis estático de la muestra ──
            self.log.emit(f"[{self._ts()}] Iniciando análisis estático de la muestra...")
            analyzer = MalwareAnalyzer(malware_path, emit=self.log.emit)
            analyzer.analyze()
            self.progress.emit(40)

            # Directorio del sandbox
            sandbox_dir = os.path.dirname(sandbox_path)
            activity_log = os.path.join(sandbox_dir, "activity.log")
            monitor_log = os.path.join(sandbox_dir, "monitor.log")

            # 1) Crear disco overlay descartable a partir de la imagen base usando C++
            self.log.emit(f"[{self._ts()}] Creando snapshot descartable (overlay) vía C++...")
            qemu_img = self._sibling_tool(qemu_path, "qemu-img")

            success = cpp.create_overlay_disk(qemu_img, vm_path, sandbox_path, activity_log)
            if not success:
                raise RuntimeError("Falló la creación del overlay en el módulo C++.")
            self.progress.emit(60)

            # 2) Lanzar la VM aislada de red usando C++
            self.log.emit(f"[{self._ts()}] Lanzando VM aislada vía C++...")

            handle = cpp.launch_isolated_vm(qemu_path, sandbox_path, malware_path, monitor_log, activity_log)
            if handle == 0:
                raise RuntimeError("No se pudo lanzar la VM QEMU desde el módulo C++.")

            self.progress.emit(80)
            self.log.emit(f"[{self._ts()}] VM lanzada (Handle: {handle}). Esperando que finalice la VM...")

            # Esperamos a que la VM termine en segundo plano
            exit_code = cpp.wait_for_process(handle, self.timeout_seconds)
            cpp.close_handle(handle)

            self.progress.emit(100)
            if exit_code == 999:
                self.log.emit(f"[{self._ts()}] ⚠️ ADVERTENCIA: La VM superó el tiempo límite de {self.timeout_seconds} segundos y fue finalizada forzosamente.")
            else:
                self.log.emit(f"[{self._ts()}] VM finalizada (exit code: {exit_code}).")
            self.finished.emit(True)

        except Exception as e:
            self.log.emit(f"[{self._ts()}] ERROR: {e}")
            self.finished.emit(False)

    @staticmethod
    def _ts():
        return datetime.now().strftime("%H:%M:%S")

    @staticmethod
    def _sibling_tool(qemu_path, tool_name):
        """Busca qemu-img.exe / qemu-img junto al binario de qemu elegido."""
        directory = os.path.dirname(qemu_path)
        exe = tool_name + (".exe" if qemu_path.lower().endswith(".exe") else "")
        candidate = os.path.join(directory, exe)
        return candidate if os.path.exists(candidate) else tool_name


# ---------------------------------------------------------------------------
# Widget reutilizable: fila "Label + LineEdit + Botón Browse"
# ---------------------------------------------------------------------------
class PathRow(QWidget):
    def __init__(self, label_text, filter_str, on_change, parent=None):
        super().__init__(parent)
        self.on_change = on_change

        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        label = QLabel(label_text)
        label.setFixedWidth(150)
        label.setStyleSheet("color: #cdd6f4; font-weight: 500;")

        self.line_edit = QLineEdit()
        self.line_edit.setReadOnly(True)
        self.line_edit.setPlaceholderText("Sin seleccionar...")
        self.line_edit.setStyleSheet("""
            QLineEdit {
                background-color: #1e1e2e;
                border: 1px solid #313244;
                border-radius: 6px;
                padding: 6px 10px;
                color: #e0e0e0;
            }
        """)

        browse_btn = QPushButton("Buscar")
        browse_btn.setCursor(Qt.PointingHandCursor)
        browse_btn.setFixedWidth(90)
        browse_btn.clicked.connect(lambda: self._browse(filter_str))
        browse_btn.setStyleSheet("""
            QPushButton {
                background-color: #313244;
                color: #cdd6f4;
                border-radius: 6px;
                padding: 6px 10px;
            }
            QPushButton:hover { background-color: #45475a; }
        """)

        layout.addWidget(label)
        layout.addWidget(self.line_edit)
        layout.addWidget(browse_btn)

    def _browse(self, filter_str):
        path, _ = QFileDialog.getOpenFileName(self, "Seleccionar archivo", "", filter_str)
        if path:
            self.line_edit.setText(path)
            self.on_change(path)

    def text(self):
        return self.line_edit.text()


# ---------------------------------------------------------------------------
# Ventana principal
# ---------------------------------------------------------------------------
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.paths = Paths()
        self.worker = None

        self.setWindowTitle("🛡️  Sandbox de Análisis de Muestras — QEMU")
        self.setMinimumSize(720, 600)
        self._build_ui()
        self._apply_theme()

    # ------------------------------------------------------------------ UI
    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(24, 24, 24, 24)
        root.setSpacing(18)

        # --- Encabezado ---
        title = QLabel("Sandbox de análisis")
        title.setStyleSheet("font-size: 22px; font-weight: 700; color: #f5f5f5;")
        subtitle = QLabel("Ejecuta muestras sospechosas en una VM aislada y descartable")
        subtitle.setStyleSheet("font-size: 13px; color: #9399b2;")
        root.addWidget(title)
        root.addWidget(subtitle)

        # --- Grupo: configuración de rutas ---
        paths_group = QGroupBox("Configuración")
        paths_layout = QVBoxLayout()
        paths_layout.setSpacing(12)

        self.row_qemu = PathRow("Ejecutable QEMU", "QEMU (*.exe);;Todos (*)",
                                 lambda p: setattr(self.paths, "qemu_path", p))
        self.row_vm = PathRow("Imagen base (VM)", "Disco QEMU (*.qcow2)",
                               lambda p: setattr(self.paths, "vm_path", p))
        self.row_malware = PathRow("Muestra a analizar", "Ejecutables (*.exe);;Todos (*)",
                                    lambda p: setattr(self.paths, "malware_path", p))
        self.row_sandbox = PathRow("Snapshot destino", "Disco QEMU (*.qcow2)",
                                    lambda p: setattr(self.paths, "sandbox_path", p))

        for row in (self.row_qemu, self.row_vm, self.row_malware, self.row_sandbox):
            paths_layout.addWidget(row)

        # --- Fila de Timeout ---
        timeout_row = QHBoxLayout()
        timeout_row.setContentsMargins(0, 0, 0, 0)
        
        timeout_label = QLabel("Tiempo límite:")
        timeout_label.setFixedWidth(150)
        timeout_label.setStyleSheet("color: #cdd6f4; font-weight: 500;")
        
        self.timeout_spin = QSpinBox()
        self.timeout_spin.setRange(10, 3600)
        self.timeout_spin.setValue(120)
        self.timeout_spin.setSuffix(" segundos")
        self.timeout_spin.setFixedWidth(120)
        self.timeout_spin.setStyleSheet("""
            QSpinBox {
                background-color: #1e1e2e;
                border: 1px solid #313244;
                border-radius: 6px;
                padding: 6px 10px;
                color: #e0e0e0;
            }
        """)
        
        timeout_desc = QLabel("(La VM se cerrará automáticamente si supera este tiempo)")
        timeout_desc.setStyleSheet("color: #6c7086; font-size: 11px;")
        
        timeout_row.addWidget(timeout_label)
        timeout_row.addWidget(self.timeout_spin)
        timeout_row.addWidget(timeout_desc)
        timeout_row.addStretch()

        paths_layout.addLayout(timeout_row)

        paths_group.setLayout(paths_layout)
        root.addWidget(paths_group)

        # --- Botón principal + barra de progreso ---
        action_row = QHBoxLayout()
        self.run_btn = QPushButton("▶  Crear y ejecutar sandbox")
        self.run_btn.setCursor(Qt.PointingHandCursor)
        self.run_btn.setMinimumHeight(42)
        self.run_btn.clicked.connect(self.on_run_clicked)
        action_row.addWidget(self.run_btn)
        root.addLayout(action_row)

        self.progress = QProgressBar()
        self.progress.setValue(0)
        self.progress.setTextVisible(False)
        self.progress.setFixedHeight(8)
        root.addWidget(self.progress)

        # --- Log ---
        log_label = QLabel("Registro de actividad")
        log_label.setStyleSheet("font-size: 13px; color: #9399b2; margin-top: 6px;")
        root.addWidget(log_label)

        self.log_box = QPlainTextEdit()
        self.log_box.setReadOnly(True)
        self.log_box.setStyleSheet("""
            QPlainTextEdit {
                background-color: #11111b;
                color: #a6e3a1;
                border: 1px solid #313244;
                border-radius: 8px;
                font-family: Consolas, monospace;
                font-size: 12px;
                padding: 8px;
            }
        """)
        root.addWidget(self.log_box, stretch=1)

        # --- Status bar ---
        self.status = QStatusBar()
        self.setStatusBar(self.status)
        self.status.showMessage("Listo.")

    def _apply_theme(self):
        self.setStyleSheet("""
            QMainWindow { background-color: #181825; }
            QGroupBox {
                color: #cdd6f4;
                font-weight: 600;
                border: 1px solid #313244;
                border-radius: 10px;
                margin-top: 10px;
                padding: 16px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 6px;
            }
            QPushButton#run {
                background-color: #89b4fa;
                color: #11111b;
                font-weight: 700;
                border-radius: 8px;
            }
            QStatusBar { color: #6c7086; }
        """)
        self.run_btn.setObjectName("run")
        self.run_btn.setStyleSheet("""
            QPushButton {
                background-color: #89b4fa;
                color: #11111b;
                font-weight: 700;
                border-radius: 8px;
                font-size: 14px;
            }
            QPushButton:hover { background-color: #74a8f9; }
            QPushButton:disabled { background-color: #45475a; color: #9399b2; }
        """)
        self.progress.setStyleSheet("""
            QProgressBar { background-color: #1e1e2e; border-radius: 4px; }
            QProgressBar::chunk { background-color: #a6e3a1; border-radius: 4px; }
        """)

    # ----------------------------------------------------------- Acciones
    def on_run_clicked(self):
        if not self.paths.is_complete():
            self._log("⚠ Completá todas las rutas antes de continuar.")
            self.status.showMessage("Faltan rutas por seleccionar.", 4000)
            return

        self.run_btn.setEnabled(False)
        self.run_btn.setText("Ejecutando...")
        self.progress.setValue(0)
        self.status.showMessage("Creando sandbox...")

        timeout_val = self.timeout_spin.value()
        self.worker = SandboxWorker(self.paths, timeout_val)
        self.worker.log.connect(self._log)
        self.worker.progress.connect(self.progress.setValue)
        self.worker.finished.connect(self.on_finished)

        # Se corre en un hilo separado para no congelar la UI
        threading.Thread(target=self.worker.run, daemon=True).start()

    def on_finished(self, success: bool):
        self.run_btn.setEnabled(True)
        self.run_btn.setText("▶  Crear y ejecutar sandbox")
        if success:
            self.status.showMessage("✅ Sandbox en ejecución.", 5000)
        else:
            self.status.showMessage("❌ Falló la creación de la sandbox.", 5000)

    def _log(self, message: str):
        self.log_box.appendPlainText(message)


# ---------------------------------------------------------------------------
if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setFont(QFont("Segoe UI", 10))
    window = MainWindow()
    window.show()
    sys.exit(app.exec())