# --- MP4Saver A4 ---
# Parent/child split (A3) + improvements from "MP4_screensaver_A4 modification.docx"
# - Stable: VLC only in child. Parent controls via QProcess and exit codes.
# - Optional features: multi-monitor, transition overlay, remote control (Flask), advanced scheduling placeholder.
# - Optional teardown (explicit cleanup) mode in child (default off; default is os._exit on unlock/close).
# ------------------------------------------------------------

import sys
import os
import json
import base64
import ctypes
import ctypes.wintypes as wintypes
import hashlib
import datetime
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import List, Optional, Tuple

import faulthandler

APP_NAME = "MP4Saver"
IS_WINDOWS = sys.platform.startswith("win")
CONFIG_DIR = Path(os.environ.get("APPDATA", str(Path.home()))) / APP_NAME
CONFIG_PATH = CONFIG_DIR / "config.json"
LOG_DIR = CONFIG_DIR / "logs"
APP_LOG_PATH = LOG_DIR / "app.log"
CRASH_LOG_PATH = LOG_DIR / "crash.log"
VLC_LOG_PATH = LOG_DIR / "vlc.log"

LOG_DIR.mkdir(parents=True, exist_ok=True)
try:
    _crash_file = open(CRASH_LOG_PATH, "a", buffering=1, encoding="utf-8")
    faulthandler.enable(file=_crash_file)
except Exception:
    pass

CHILD_MODE = ("--child" in sys.argv)
DEBUG_MODE = ("--debug" in sys.argv)

def setup_logging(debug: bool) -> logging.Logger:
    logger = logging.getLogger(APP_NAME)
    logger.handlers.clear()
    logger.setLevel(logging.DEBUG if debug else logging.INFO)
    fh = RotatingFileHandler(APP_LOG_PATH, maxBytes=5 * 1024 * 1024, backupCount=5, encoding="utf-8")
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    fh.setFormatter(fmt)
    fh.setLevel(logging.DEBUG if debug else logging.INFO)
    logger.addHandler(fh)
    ch = logging.StreamHandler()
    ch.setFormatter(fmt)
    ch.setLevel(logging.DEBUG if debug else logging.INFO)
    logger.addHandler(ch)
    import platform
    logger.info("==== %s starting ====", APP_NAME + (" (child)" if CHILD_MODE else ""))
    logger.info("Python: %s (%s)", sys.version.split()[0], platform.architecture()[0])
    logger.info("Platform: %s %s", platform.system(), platform.release())
    logger.info("Executable: %s", sys.executable)
    logger.info("AppData dir: %s", CONFIG_DIR)
    return logger

logger = setup_logging(DEBUG_MODE)

# ---------------- Power (Windows) ----------------
ES_AWAYMODE_REQUIRED = 0x00000040
ES_CONTINUOUS = 0x80000000
ES_DISPLAY_REQUIRED = 0x00000002
ES_SYSTEM_REQUIRED = 0x00000001

def set_thread_execution_state(prevent_sleep: bool):
    if not IS_WINDOWS:
        return
    try:
        kernel32 = ctypes.windll.kernel32
        if prevent_sleep:
            kernel32.SetThreadExecutionState(
                ES_CONTINUOUS | ES_DISPLAY_REQUIRED | ES_SYSTEM_REQUIRED | ES_AWAYMODE_REQUIRED
            )
        else:
            kernel32.SetThreadExecutionState(ES_CONTINUOUS)
    except Exception as e:
        logger.warning("SetThreadExecutionState failed: %s", e)

# ---------------- Auth helpers -------------------
def get_current_username_and_domain():
    username = os.environ.get("USERNAME", "")
    domain = os.environ.get("USERDOMAIN", os.environ.get("COMPUTERNAME", "."))
    if not username:
        try:
            username = os.getlogin()
        except Exception:
            username = ""
    return username, domain or "."

def verify_windows_password(password: str) -> bool:
    if not IS_WINDOWS:
        return False
    username, domain = get_current_username_and_domain()
    LOGON32_LOGON_INTERACTIVE = 2
    LOGON32_PROVIDER_DEFAULT = 0
    try:
        advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
        token = wintypes.HANDLE()
        success = advapi32.LogonUserW(
            ctypes.c_wchar_p(username),
            ctypes.c_wchar_p(domain),
            ctypes.c_wchar_p(password),
            ctypes.c_uint(LOGON32_LOGON_INTERACTIVE),
            ctypes.c_uint(LOGON32_PROVIDER_DEFAULT),
            ctypes.byref(token),
        )
        if success:
            ctypes.windll.kernel32.CloseHandle(token)
            return True
    except Exception as e:
        logger.warning("Windows password verification failed: %s", e)
    return False

def pbkdf2_hash_password(password: str, salt: Optional[bytes] = None, rounds: int = 200_000):
    if salt is None:
        salt = os.urandom(16)
    import hashlib as _hash
    dk = _hash.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, rounds)
    import base64 as _b64
    return _b64.b64encode(salt).decode("ascii"), _b64.b64encode(dk).decode("ascii"), rounds

def pbkdf2_verify_password(password: str, salt_b64: str, hash_b64: str, rounds: int) -> bool:
    try:
        import base64 as _b64, hashlib as _hash
        salt = _b64.b64decode(salt_b64.encode("ascii"))
        expected = _b64.b64decode(hash_b64.encode("ascii"))
        dk = _hash.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, rounds)
        return _hash.compare_digest(dk, expected)
    except Exception:
        return False

# ---------------- Config -------------------------
class ConfigManager:
    def __init__(self, path: Path):
        self.path = path
        self.data = {
            "playlist": [],
            "shuffle": False,
            "loop": True,
            "volume": 100,
            "schedule_enabled": False,
            "schedule_time": "20:00",
            "schedule_duration_min": 60,
            "power_prevent_sleep": True,
            "unlock_mode": "windows",  # "no_password" | "windows" | "custom"
            "custom_pw_salt": "",
            "custom_pw_hash": "",
            "custom_pw_rounds": 200000,
            "vlc_force_d3d11": True,
            "enable_vlc_file_log": DEBUG_MODE,
            "waiting_enabled": False,
            "waiting_minutes": 5,
            "armed": False,
            # A4 additions:
            "multi_monitor_enable": False,
            "transition_enable": False,
            "transition_duration_ms": 600,
            "remote_control_enable": False,
            "remote_control_port": 8080,
            "advanced_schedule_enable": False,
            "advanced_schedule_rule": "",  # e.g., "*/15 9-17 * * MON-FRI"
            "explicit_cleanup_on_exit": False,  # A4: child explicit cleanup mode (default False)
        }
        self.load()

    def load(self):
        try:
            if self.path.exists():
                with open(self.path, "r", encoding="utf-8") as f:
                    obj = json.load(f)
                    self.data.update(obj)
        except Exception as e:
            logger.warning("Failed to load config: %s", e)

    def save(self):
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.path, "w", encoding="utf-8") as f:
                json.dump(self.data, f, indent=2)
        except Exception as e:
            logger.warning("Failed to save config: %s", e)

# ============================================================
# Parent Process (Controller) - does NOT load VLC
# ============================================================
if not CHILD_MODE:
    from PyQt6 import QtCore, QtGui, QtWidgets

    def get_system_idle_seconds() -> int:
        if not IS_WINDOWS:
            return 0
        class LASTINPUTINFO(ctypes.Structure):
            _fields_ = [("cbSize", ctypes.c_uint), ("dwTime", ctypes.c_uint)]
        lii = LASTINPUTINFO()
        lii.cbSize = ctypes.sizeof(LASTINPUTINFO)
        if ctypes.windll.user32.GetLastInputInfo(ctypes.byref(lii)) == 0:
            return 0
        tick_count = ctypes.windll.kernel32.GetTickCount()
        idle_ms = tick_count - lii.dwTime
        return max(0, idle_ms // 1000)

    class ScheduleWidget(QtWidgets.QGroupBox):
        settingsChanged = QtCore.pyqtSignal()
        runConfirmed = QtCore.pyqtSignal()
        stopRequested = QtCore.pyqtSignal()
        def __init__(self, config: ConfigManager, parent=None):
            super().__init__("Schedule and Waiting", parent)
            self.config = config
            grid = QtWidgets.QGridLayout(self)
            self.enable_schedule_checkbox = QtWidgets.QCheckBox("Enable schedule")
            grid.addWidget(self.enable_schedule_checkbox, 0, 0, 1, 2)
            grid.addWidget(QtWidgets.QLabel("Start time (24h):"), 1, 0)
            self.time_edit = QtWidgets.QTimeEdit()
            self.time_edit.setDisplayFormat("HH:mm")
            grid.addWidget(self.time_edit, 1, 1)
            grid.addWidget(QtWidgets.QLabel("Duration (minutes):"), 2, 0)
            self.duration_spin = QtWidgets.QSpinBox()
            self.duration_spin.setRange(1, 24 * 60)
            grid.addWidget(self.duration_spin, 2, 1)

            self.enable_waiting_checkbox = QtWidgets.QCheckBox("Enable waiting (idle timeout)")
            grid.addWidget(self.enable_waiting_checkbox, 3, 0, 1, 2)
            grid.addWidget(QtWidgets.QLabel("Idle minutes:"), 4, 0)
            self.wait_minutes_spin = QtWidgets.QSpinBox()
            self.wait_minutes_spin.setRange(1, 240)
            self.wait_minutes_spin.setSuffix(" min")
            grid.addWidget(self.wait_minutes_spin, 4, 1)

            # A4: Advanced scheduler
            self.adv_enable = QtWidgets.QCheckBox("Enable advanced schedule (cron-like)")
            grid.addWidget(self.adv_enable, 5, 0, 1, 2)
            self.adv_rule_edit = QtWidgets.QLineEdit()
            self.adv_rule_edit.setPlaceholderText('e.g. "*/15 9-17 * * MON-FRI"')
            grid.addWidget(self.adv_rule_edit, 6, 0, 1, 2)

            self.run_btn = QtWidgets.QPushButton("Run")
            self.stop_btn = QtWidgets.QPushButton("Stop")
            self.armed_label = QtWidgets.QLabel("")
            grid.addWidget(self.run_btn, 7, 0)
            grid.addWidget(self.stop_btn, 7, 1)
            grid.addWidget(self.armed_label, 8, 0, 1, 2)
            self.load_from_config()
            self._wire()
        def _wire(self):
            self.enable_schedule_checkbox.toggled.connect(lambda _: self._save(disarm=True))
            self.time_edit.timeChanged.connect(lambda _: self._save(disarm=True))
            self.duration_spin.valueChanged.connect(lambda _: self._save(disarm=True))
            self.enable_waiting_checkbox.toggled.connect(lambda _: self._save(disarm=True))
            self.wait_minutes_spin.valueChanged.connect(lambda _: self._save(disarm=True))
            self.adv_enable.toggled.connect(lambda _: self._save(disarm=True))
            self.adv_rule_edit.textChanged.connect(lambda _: self._save(disarm=True))
            self.run_btn.clicked.connect(self._confirm)
            self.stop_btn.clicked.connect(self._stop)
        def _confirm(self):
            self.config.data["armed"] = True
            self.config.save()
            self._update_armed_label()
            self.runConfirmed.emit()
        def _stop(self):
            self.config.data["armed"] = False
            self.config.save()
            self._update_armed_label()
            self.stopRequested.emit()
        def _update_armed_label(self):
            self.armed_label.setText("Armed" if self.config.data.get("armed", False) else "Not confirmed")
        def load_from_config(self):
            self.enable_schedule_checkbox.setChecked(bool(self.config.data.get("schedule_enabled", False)))
            try:
                s = self.config.data.get("schedule_time", "20:00")
                hh, mm = [int(x) for x in s.split(":")]
            except Exception:
                hh, mm = 20, 0
            self.time_edit.setTime(QtCore.QTime(hh, mm))
            self.duration_spin.setValue(int(self.config.data.get("schedule_duration_min", 60)))
            self.enable_waiting_checkbox.setChecked(bool(self.config.data.get("waiting_enabled", False)))
            self.wait_minutes_spin.setValue(int(self.config.data.get("waiting_minutes", 5)))
            self.adv_enable.setChecked(bool(self.config.data.get("advanced_schedule_enable", False)))
            self.adv_rule_edit.setText(self.config.data.get("advanced_schedule_rule", ""))
            self._update_armed_label()
        def _save(self, disarm=False):
            t = self.time_edit.time()
            self.config.data["schedule_enabled"] = self.enable_schedule_checkbox.isChecked()
            self.config.data["schedule_time"] = f"{t.hour():02d}:{t.minute():02d}"
            self.config.data["schedule_duration_min"] = int(self.duration_spin.value())
            self.config.data["waiting_enabled"] = self.enable_waiting_checkbox.isChecked()
            self.config.data["waiting_minutes"] = int(self.wait_minutes_spin.value())
            self.config.data["advanced_schedule_enable"] = self.adv_enable.isChecked()
            self.config.data["advanced_schedule_rule"] = self.adv_rule_edit.text().strip()
            if disarm:
                self.config.data["armed"] = False
            self.config.save()
            self._update_armed_label()
            self.settingsChanged.emit()

    class SettingsWidget(QtWidgets.QGroupBox):
        def __init__(self, config: ConfigManager, parent=None):
            super().__init__("Settings", parent)
            self.config = config
            layout = QtWidgets.QFormLayout(self)
            self.volume_slider = QtWidgets.QSlider(QtCore.Qt.Orientation.Horizontal)
            self.volume_slider.setRange(0, 100)
            self.volume_slider.setValue(int(self.config.data.get("volume", 100)))
            layout.addRow("Volume:", self.volume_slider)
            self.loop_checkbox = QtWidgets.QCheckBox("Loop playlist")
            self.loop_checkbox.setChecked(bool(self.config.data.get("loop", True)))
            layout.addRow("", self.loop_checkbox)
            self.shuffle_checkbox = QtWidgets.QCheckBox("Shuffle playlist")
            self.shuffle_checkbox.setChecked(bool(self.config.data.get("shuffle", False)))
            layout.addRow("", self.shuffle_checkbox)
            self.power_checkbox = QtWidgets.QCheckBox("Prevent sleep/display off while playing")
            self.power_checkbox.setChecked(bool(self.config.data.get("power_prevent_sleep", True)))
            layout.addRow("", self.power_checkbox)

            # A4: multi-monitor, transition, remote control, explicit cleanup
            self.mm_checkbox = QtWidgets.QCheckBox("Enable multi-monitor (extend full screen)")
            self.mm_checkbox.setChecked(bool(self.config.data.get("multi_monitor_enable", False)))
            layout.addRow("", self.mm_checkbox)
            self.tr_checkbox = QtWidgets.QCheckBox("Enable transition fade between videos")
            self.tr_checkbox.setChecked(bool(self.config.data.get("transition_enable", False)))
            layout.addRow("", self.tr_checkbox)
            self.tr_duration = QtWidgets.QSpinBox()
            self.tr_duration.setRange(100, 5000)
            self.tr_duration.setValue(int(self.config.data.get("transition_duration_ms", 600)))
            self.tr_duration.setSuffix(" ms")
            layout.addRow("Transition duration:", self.tr_duration)
            self.rc_checkbox = QtWidgets.QCheckBox("Enable web remote control (Flask)")
            self.rc_checkbox.setChecked(bool(self.config.data.get("remote_control_enable", False)))
            layout.addRow("", self.rc_checkbox)
            self.rc_port = QtWidgets.QSpinBox()
            self.rc_port.setRange(1024, 65535)
            self.rc_port.setValue(int(self.config.data.get("remote_control_port", 8080)))
            layout.addRow("Remote port:", self.rc_port)

            self.explicit_cleanup = QtWidgets.QCheckBox("Child: explicit cleanup on exit (advanced)")
            self.explicit_cleanup.setChecked(bool(self.config.data.get("explicit_cleanup_on_exit", False)))
            layout.addRow("", self.explicit_cleanup)

            self.unlock_mode_combo = QtWidgets.QComboBox()
            self.unlock_mode_combo.addItems(["no_password", "windows", "custom"])
            self.unlock_mode_combo.setCurrentText(self.config.data.get("unlock_mode", "windows"))
            layout.addRow("Unlock mode:", self.unlock_mode_combo)
            self.custom_pw_btn = QtWidgets.QPushButton("Set custom password...")
            layout.addRow("", self.custom_pw_btn)

            self.vlc_d3d11_checkbox = QtWidgets.QCheckBox("Use Direct3D11 output (recommended)")
            self.vlc_d3d11_checkbox.setChecked(bool(self.config.data.get("vlc_force_d3d11", True)))
            layout.addRow("", self.vlc_d3d11_checkbox)
            self.vlc_filelog_checkbox = QtWidgets.QCheckBox("Enable VLC engine log to file (vlc.log)")
            self.vlc_filelog_checkbox.setChecked(bool(self.config.data.get("enable_vlc_file_log", False)))
            layout.addRow("", self.vlc_filelog_checkbox)

            self.volume_slider.valueChanged.connect(self._save)
            self.loop_checkbox.toggled.connect(self._save)
            self.shuffle_checkbox.toggled.connect(self._save)
            self.power_checkbox.toggled.connect(self._save)
            self.mm_checkbox.toggled.connect(self._save)
            self.tr_checkbox.toggled.connect(self._save)
            self.tr_duration.valueChanged.connect(self._save)
            self.rc_checkbox.toggled.connect(self._save)
            self.rc_port.valueChanged.connect(self._save)
            self.explicit_cleanup.toggled.connect(self._save)
            self.unlock_mode_combo.currentTextChanged.connect(self._save)
            self.vlc_d3d11_checkbox.toggled.connect(self._save)
            self.vlc_filelog_checkbox.toggled.connect(self._save)
            self.custom_pw_btn.clicked.connect(self._set_custom_password)

        def _set_custom_password(self):
            pw1, ok1 = QtWidgets.QInputDialog.getText(
                self, "Custom Password", "Enter new password:", QtWidgets.QLineEdit.EchoMode.Password
            )
            if not ok1:
                return
            pw2, ok2 = QtWidgets.QInputDialog.getText(
                self, "Custom Password", "Confirm new password:", QtWidgets.QLineEdit.EchoMode.Password
            )
            if not ok2:
                return
            if pw1 != pw2:
                QtWidgets.QMessageBox.warning(self, "Mismatch", "Passwords do not match.")
                return
            salt_b64, hash_b64, rounds = pbkdf2_hash_password(pw1)
            self.config.data["custom_pw_salt"] = salt_b64
            self.config.data["custom_pw_hash"] = hash_b64
            self.config.data["custom_pw_rounds"] = rounds
            self.config.save()
            QtWidgets.QMessageBox.information(self, "Saved", "Custom password updated.")

        def _save(self, *_):
            self.config.data["volume"] = int(self.volume_slider.value())
            self.config.data["loop"] = bool(self.loop_checkbox.isChecked())
            self.config.data["shuffle"] = bool(self.shuffle_checkbox.isChecked())
            self.config.data["power_prevent_sleep"] = bool(self.power_checkbox.isChecked())
            self.config.data["multi_monitor_enable"] = bool(self.mm_checkbox.isChecked())
            self.config.data["transition_enable"] = bool(self.tr_checkbox.isChecked())
            self.config.data["transition_duration_ms"] = int(self.tr_duration.value())
            self.config.data["remote_control_enable"] = bool(self.rc_checkbox.isChecked())
            self.config.data["remote_control_port"] = int(self.rc_port.value())
            self.config.data["explicit_cleanup_on_exit"] = bool(self.explicit_cleanup.isChecked())
            self.config.data["unlock_mode"] = self.unlock_mode_combo.currentText()
            self.config.data["vlc_force_d3d11"] = bool(self.vlc_d3d11_checkbox.isChecked())
            self.config.data["enable_vlc_file_log"] = bool(self.vlc_filelog_checkbox.isChecked())
            self.config.save()

    class PlaylistWidget(QtWidgets.QGroupBox):
        runRequested = QtCore.pyqtSignal(str)  # "test" or "normal"
        def __init__(self, config: ConfigManager, parent=None):
            super().__init__("Playlist", parent)
            self.config = config
            layout = QtWidgets.QVBoxLayout(self)
            self.list_widget = QtWidgets.QListWidget()
            self.list_widget.setSelectionMode(QtWidgets.QAbstractItemView.SelectionMode.ExtendedSelection)
            layout.addWidget(self.list_widget)
            btns = QtWidgets.QHBoxLayout()
            self.add_btn = QtWidgets.QPushButton("Add MP4(s)")
            self.remove_btn = QtWidgets.QPushButton("Remove")
            self.clear_btn = QtWidgets.QPushButton("Clear")
            self.up_btn = QtWidgets.QPushButton("Up")
            self.down_btn = QtWidgets.QPushButton("Down")
            btns.addWidget(self.add_btn)
            btns.addWidget(self.remove_btn)
            btns.addWidget(self.clear_btn)
            btns.addStretch(1)
            btns.addWidget(self.up_btn)
            btns.addWidget(self.down_btn)
            layout.addLayout(btns)
            self.run_btn = QtWidgets.QPushButton("Test Video")
            layout.addWidget(self.run_btn)
            self.add_btn.clicked.connect(self.add_files)
            self.remove_btn.clicked.connect(self.remove_selected)
            self.clear_btn.clicked.connect(self.clear_all)
            self.up_btn.clicked.connect(self.move_up)
            self.down_btn.clicked.connect(self.move_down)
            self.run_btn.clicked.connect(lambda: self._request_run("test"))
            self.load_from_config()
        def load_from_config(self):
            self.list_widget.clear()
            for p in self.config.data.get("playlist", []):
                self.list_widget.addItem(p)
        def save_to_config(self):
            paths = [self.list_widget.item(i).text() for i in range(self.list_widget.count())]
            self.config.data["playlist"] = paths
            self.config.save()
        def add_files(self):
            dlg = QtWidgets.QFileDialog(self)
            dlg.setFileMode(QtWidgets.QFileDialog.FileMode.ExistingFiles)
            dlg.setNameFilter("MP4 files (*.mp4);;All files (*.*)")
            if dlg.exec():
                files = dlg.selectedFiles()
                for f in files:
                    self.list_widget.addItem(f)
                self.save_to_config()
        def remove_selected(self):
            for item in sorted(self.list_widget.selectedItems(), key=lambda i: self.list_widget.row(i), reverse=True):
                row = self.list_widget.row(item)
                self.list_widget.takeItem(row)
            self.save_to_config()
        def clear_all(self):
            self.list_widget.clear()
            self.save_to_config()
        def move_up(self):
            rows = sorted([self.list_widget.row(i) for i in self.list_widget.selectedItems()])
            for r in rows:
                if r > 0:
                    item = self.list_widget.takeItem(r)
                    self.list_widget.insertItem(r - 1, item)
                    item.setSelected(True)
            self.save_to_config()
        def move_down(self):
            rows = sorted([self.list_widget.row(i) for i in self.list_widget.selectedItems()], reverse=True)
            for r in rows:
                if r < self.list_widget.count() - 1:
                    item = self.list_widget.takeItem(r)
                    self.list_widget.insertItem(r + 1, item)
                    item.setSelected(True)
            self.save_to_config()
        def _request_run(self, mode: str):
            paths = [self.list_widget.item(i).text() for i in range(self.list_widget.count())]
            if not paths:
                QtWidgets.QMessageBox.warning(self, "Playlist empty", "Add MP4 files to the playlist first.")
                return
            logger.info("Test Video requested with %d file(s)", len(paths))
            self.runRequested.emit(mode)

    class MainWindow(QtWidgets.QMainWindow):
        def __init__(self):
            super().__init__()
            self.setWindowTitle(f"{APP_NAME} A4")
            self.resize(980, 760)
            self.config = ConfigManager(CONFIG_PATH)
            central = QtWidgets.QWidget()
            self.setCentralWidget(central)
            layout = QtWidgets.QVBoxLayout(central)
            tabs = QtWidgets.QTabWidget()
            layout.addWidget(tabs)
            self.playlist_widget = PlaylistWidget(self.config)
            self.schedule_widget = ScheduleWidget(self.config)
            self.settings_widget = SettingsWidget(self.config)
            self.playlist_widget.runRequested.connect(self._on_test_video)
            self.schedule_widget.settingsChanged.connect(self._on_schedule_changed)
            self.schedule_widget.runConfirmed.connect(self._on_schedule_confirmed)
            self.schedule_widget.stopRequested.connect(self._on_schedule_stopped)
            ptab = QtWidgets.QWidget(); ptab_layout = QtWidgets.QVBoxLayout(ptab); ptab_layout.addWidget(self.playlist_widget)
            stab = QtWidgets.QWidget(); stab_layout = QtWidgets.QVBoxLayout(stab); stab_layout.addWidget(self.schedule_widget)
            setab = QtWidgets.QWidget(); setab_layout = QtWidgets.QVBoxLayout(setab); setab_layout.addWidget(self.settings_widget)
            tabs.addTab(ptab, "Playlist")
            tabs.addTab(stab, "Schedule")
            tabs.addTab(setab, "Settings")
            self.status_label = QtWidgets.QLabel("Ready")
            layout.addWidget(self.status_label)

            menubar = self.menuBar()
            diag = menubar.addMenu("Diagnostics")
            act_env = diag.addAction("Show VLC Env")
            act_env.triggered.connect(self._show_vlc_env)
            helpm = menubar.addMenu("Help")
            act_logs = helpm.addAction("Open Logs Folder")
            act_logs.triggered.connect(self.open_logs_folder)

            self.screensaver_active = False
            self.child: Optional[QtCore.QProcess] = None

            self.scheduler_timer = QtCore.QTimer(self)
            self.scheduler_timer.setInterval(1000)
            self.scheduler_timer.timeout.connect(self.tick_scheduler)
            self.scheduler_timer.start()

            if QtWidgets.QSystemTrayIcon.isSystemTrayAvailable():
                self.tray = QtWidgets.QSystemTrayIcon(self)
                self.tray.setIcon(self.style().standardIcon(QtWidgets.QStyle.StandardPixmap.SP_MediaPlay))
                menu = QtWidgets.QMenu()
                action_run = menu.addAction("Test Video")
                action_stop = menu.addAction("Stop")
                action_quit = menu.addAction("Quit")
                action_run.triggered.connect(self._on_test_video)
                action_stop.triggered.connect(self._on_schedule_stopped)
                action_quit.triggered.connect(self.close)
                self.tray.setContextMenu(menu)
                self.tray.show()

        def _show_vlc_env(self):
            msg = f"VLC_PLUGIN_PATH: {os.environ.get('VLC_PLUGIN_PATH','')}\nPYTHON_VLC_LIB_PATH: {os.environ.get('PYTHON_VLC_LIB_PATH','')}"
            QtWidgets.QMessageBox.information(self, "VLC Environment", msg)

        def open_logs_folder(self):
            folder = str(LOG_DIR)
            logger.info("Opening logs folder: %s", folder)
            if IS_WINDOWS:
                os.startfile(folder)
            else:
                QtGui.QDesktopServices.openUrl(QtCore.QUrl.fromLocalFile(folder))

        # schedule logic
        def _on_schedule_changed(self):
            self.status_label.setText("Schedule/Waiting changed. Not confirmed.")
            logger.info("Schedule/Waiting settings changed; disarmed.")

        def _on_schedule_confirmed(self):
            self.status_label.setText("Armed: schedule/waiting ready.")
            logger.info("Schedule/Waiting confirmed and armed.")

        def _on_schedule_stopped(self):
            logger.info("Stop requested: disarming and stopping if running.")
            self.config.data["armed"] = False
            self.config.save()
            self.status_label.setText("Not confirmed")
            if self.screensaver_active:
                self.stop_screensaver()

        def _on_test_video(self):
            self.start_screensaver(mode="test")

        # simple cron-like check placeholder
        def _advanced_rule_match_now(self, rule: str, now: datetime.datetime) -> bool:
            # Minimal parser: supports "*/N HH-HH * * MON-FRI" like patterns (placeholder)
            # For now, return False if empty; True never auto-match unless exact minute mod matches (*/N).
            if not rule:
                return False
            try:
                parts = rule.split()
                if len(parts) != 5:
                    return False
                minute, hour, dom, month, dow = parts
                ok_min = True
                if minute.startswith("*/"):
                    step = int(minute[2:])
                    ok_min = (now.minute % step) == 0
                ok_hour = True
                if "-" in hour:
                    a, b = hour.split("-")
                    ok_hour = (now.hour >= int(a) and now.hour <= int(b))
                return ok_min and ok_hour
            except Exception:
                return False

        def tick_scheduler(self):
            if self.screensaver_active:
                return
            data = self.config.data
            if not data.get("armed", False):
                return
            paths = data.get("playlist", [])
            if not paths:
                return

            now = datetime.datetime.now()
            # idle waiting
            if data.get("waiting_enabled", False):
                idle_secs = get_system_idle_seconds()
                need_secs = max(1, int(data.get("waiting_minutes", 5))) * 60
                if idle_secs >= need_secs:
                    logger.info("Idle timeout reached (%ss). Starting screensaver.", idle_secs)
                    self.start_screensaver(mode="normal")
                    return
            # simple schedule exact match
            if data.get("schedule_enabled", False):
                try:
                    hh, mm = [int(x) for x in data.get("schedule_time", "20:00").split(":")]
                except Exception:
                    hh, mm = 20, 0
                if now.hour == hh and now.minute == mm and now.second == 0:
                    logger.info("Schedule time matched %02d:%02d. Starting screensaver.", hh, mm)
                    self.start_screensaver(mode="normal")
                    return
            # advanced schedule (placeholder)
            if data.get("advanced_schedule_enable", False):
                rule = data.get("advanced_schedule_rule", "").strip()
                if self._advanced_rule_match_now(rule, now):
                    logger.info("Advanced schedule rule matched. Starting screensaver.")
                    self.start_screensaver(mode="normal")
                    return

        def start_screensaver(self, mode: str):
            if self.screensaver_active:
                return
            if not self.config.data.get("playlist", []):
                self.status_label.setText("No playlist configured.")
                return
            self.child = QtCore.QProcess(self)
            program = sys.executable
            script = str(Path(sys.argv[0]).resolve())
            args = [script, "--child", f"--mode={mode}"]
            if DEBUG_MODE:
                args.append("--debug")
            self.child.setProgram(program)
            self.child.setArguments(args)
            self.child.setProcessChannelMode(QtCore.QProcess.ProcessChannelMode.MergedChannels)
            self.child.finished.connect(self._on_child_finished)
            self.child.start()
            if not self.child.waitForStarted(5000):
                QtWidgets.QMessageBox.critical(self, "Error", "Failed to start screensaver child process.")
                self.child = None
                return
            self.screensaver_active = True
            self.status_label.setText("Screensaver running (child).")

        def _on_child_finished(self, exitCode: int, exitStatus: QtCore.QProcess.ExitStatus):
            logger.info("Screensaver child finished. exitCode=%s exitStatus=%s", exitCode, exitStatus.name)
            self.screensaver_active = False
            self.child = None
            if exitCode == 200:  # unlocked
                self.showMinimized()
                self.status_label.setText("Unlocked. Main minimized.")
            elif exitCode == 102:  # test_return
                self.showNormal(); self.activateWindow(); self.raise_()
                self.status_label.setText("Returned from Test Video.")
            elif exitCode == 101:  # user/no_password close
                self.showNormal()
                self.status_label.setText("Screensaver closed.")
            else:
                self.showNormal()
                self.status_label.setText(f"Screensaver ended (code {exitCode}). See logs.")

        def stop_screensaver(self):
            if self.child:
                logger.info("Stopping screensaver child.")
                self.child.terminate()
                if not self.child.waitForFinished(1500):
                    self.child.kill()
                    self.child.waitForFinished(1000)
                self.child = None
            self.screensaver_active = False
            self.status_label.setText("Screensaver stopped.")
            logger.info("Screensaver stopped")

    def excepthook_parent(exctype, value, tb):
        logger.exception("Uncaught exception (parent)", exc_info=(exctype, value, tb))
        try:
            from PyQt6 import QtWidgets as _QtWidgets
            _QtWidgets.QMessageBox.critical(None, "Error", f"Unexpected error: {value}")
        except Exception:
            pass
        sys.__excepthook__(exctype, value, tb)

    def main_parent():
        sys.excepthook = excepthook_parent
        from PyQt6 import QtWidgets as _QtWidgets
        app = _QtWidgets.QApplication([a for a in sys.argv if a not in ("--debug",)])
        app.setApplicationName(APP_NAME)
        w = MainWindow()
        w.show()
        sys.exit(app.exec())

# ============================================================
# Child Process (owns VLC + fullscreen player)
# ============================================================
if CHILD_MODE:
    from PyQt6 import QtCore, QtGui, QtWidgets
    # Lazy import VLC in child
    import vlc

    # VLC path setup (child only)
    def _winreg_get_vlc_dir_from_registry() -> Optional[Path]:
        if not IS_WINDOWS:
            return None
        try:
            import winreg
        except Exception:
            return None
        keys_to_check = [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\VideoLAN\VLC"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\VideoLAN\VLC"),
        ]
        access_flags = [0, getattr(winreg, "KEY_WOW64_64KEY", 0), getattr(winreg, "KEY_WOW64_32KEY", 0)]
        for root, subkey in keys_to_check:
            for flag in access_flags:
                try:
                    k = winreg.OpenKey(root, subkey, 0, winreg.KEY_READ | flag)
                    try:
                        for name in ("InstallDir", "Path"):
                            try:
                                val, _ = winreg.QueryValueEx(k, name)
                                if val:
                                    p = Path(val)
                                    if (p / "libvlc.dll").exists():
                                        return p
                            except FileNotFoundError:
                                continue
                    finally:
                        winreg.CloseKey(k)
                except FileNotFoundError:
                    continue
                except Exception:
                    continue
        return None

    def _candidate_vlc_dirs() -> List[Path]:
        candidates: List[Path] = []
        bases = [Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent)),
                 Path(sys.argv[0]).resolve().parent]
        for base in bases:
            b = base / "VLC"
            if (b / "libvlc.dll").exists():
                candidates.append(b)
        for var in ("VLC_DIR", "PYTHON_VLC_LIB_PATH"):
            v = os.environ.get(var)
            if v:
                p = Path(v)
                if p.is_file() and p.name.lower() == "libvlc.dll":
                    p = p.parent
                if (p / "libvlc.dll").exists():
                    candidates.append(p)
        defaults = [Path(r"C:\Program Files\VideoLAN\VLC"), Path(r"C:\Program Files (x86)\VideoLAN\VLC")]
        for d in defaults:
            if (d / "libvlc.dll").exists():
                candidates.append(d)
        reg = _winreg_get_vlc_dir_from_registry()
        if reg and (reg / "libvlc.dll").exists():
            candidates.append(reg)
        seen = set(); uniq=[]
        for c in candidates:
            key = str(c.resolve()).lower()
            if key not in seen:
                uniq.append(c); seen.add(key)
        return uniq

    def setup_vlc_paths_child() -> Tuple[Optional[Path], Optional[Path]]:
        if not IS_WINDOWS:
            return None, None
        candidates = _candidate_vlc_dirs()
        logger.info("VLC candidates: %s", [str(c) for c in candidates])
        for d in candidates:
            lib = d / "libvlc.dll"
            plugins = d / "plugins"
            if lib.exists():
                try:
                    if hasattr(os, "add_dll_directory"):
                        os.add_dll_directory(str(d))
                        logger.debug("Added to DLL search path: %s", d)
                except Exception as e:
                    logger.warning("add_dll_directory failed for %s: %s", d, e)
                os.environ["PYTHON_VLC_LIB_PATH"] = str(lib)
                if plugins.exists():
                    os.environ["VLC_PLUGIN_PATH"] = str(plugins)
                os.environ["PATH"] = str(d) + os.pathsep + os.environ.get("PATH", "")
                logger.info("Using VLC dir: %s", d)
                if plugins.exists():
                    logger.info("Using VLC plugins: %s", plugins)
                else:
                    logger.warning("VLC plugins directory not found next to libvlc.dll")
                return d, plugins if plugins.exists() else None
        logger.error("No suitable VLC directory found. Install 64-bit VLC at C:\\Program Files\\VideoLAN\\VLC.")
        return None, None

    VLC_DIR, VLC_PLUGINS = setup_vlc_paths_child()

    # Optional VLC file logging in debug
    VLC_FILE_LOGGING_ARGS = []
    if DEBUG_MODE:
        VLC_FILE_LOGGING_ARGS = ["--file-logging", f"--logfile={VLC_LOG_PATH}", "--verbose=2"]

    # Exit codes
    EXIT_TEST_RETURN = 102
    EXIT_USER = 101
    EXIT_UNLOCKED = 200

    # Keyboard/IME helpers (for password field)
    KLF_ACTIVATE = 0x00000001
    def force_english_layout():
        if not IS_WINDOWS:
            return None
        try:
            prev = ctypes.windll.user32.GetKeyboardLayout(0)
            ctypes.windll.user32.LoadKeyboardLayoutW("00000409", KLF_ACTIVATE)
            return prev
        except Exception:
            return None
    def restore_layout(prev_hkl):
        if not IS_WINDOWS or prev_hkl is None:
            return
        try:
            ctypes.windll.user32.ActivateKeyboardLayout(prev_hkl, 0)
        except Exception:
            pass
    def disable_ime_for_hwnd(hwnd):
        if not IS_WINDOWS:
            return None
        try:
            imm32 = ctypes.windll.imm32
            prev = imm32.ImmAssociateContext(wintypes.HWND(hwnd), wintypes.HIMC(0))
            return prev
        except Exception:
            return None
    def restore_ime_for_hwnd(hwnd, prev_himc):
        if not IS_WINDOWS or prev_himc is None:
            return
        try:
            ctypes.windll.imm32.ImmAssociateContext(wintypes.HWND(hwnd), prev_himc)
        except Exception:
            pass

    class TransitionOverlay(QtWidgets.QWidget):
        # Lightweight fade overlay: avoid touching VLC surfaces directly
        def __init__(self, parent=None):
            super().__init__(parent)
            self.setAttribute(QtCore.Qt.WidgetAttribute.WA_TransparentForMouseEvents, True)
            self.setAttribute(QtCore.Qt.WidgetAttribute.WA_NoSystemBackground, True)
            self.setWindowFlags(self.windowFlags() | QtCore.Qt.WindowType.FramelessWindowHint)
            self._opacity = 0.0
            self._anim = QtCore.QPropertyAnimation(self, b"opacity")
            self.hide()
        def paintEvent(self, e):
            if self._opacity <= 0.0:
                return
            p = QtGui.QPainter(self)
            p.setRenderHint(QtGui.QPainter.RenderHint.Antialiasing, False)
            c = QtGui.QColor(0, 0, 0)
            c.setAlphaF(max(0.0, min(1.0, self._opacity)))
            p.fillRect(self.rect(), c)
        def getOpacity(self):
            return self._opacity
        def setOpacity(self, v):
            self._opacity = v
            self.update()
        opacity = QtCore.pyqtProperty(float, fget=getOpacity, fset=setOpacity)
        def crossfade(self, duration_ms=600):
            self._anim.stop()
            self.setOpacity(0.0)
            self.show(); self.raise_()
            self._anim.setDuration(max(50, int(duration_ms)))
            self._anim.setStartValue(0.0)
            self._anim.setEndValue(1.0)
            self._anim.finished.connect(self.hide)
            self._anim.start()

    class VLCPlayerWidget(QtWidgets.QFrame):
        ended = QtCore.pyqtSignal()
        def __init__(self, config: ConfigManager, parent=None):
            super().__init__(parent)
            self.config = config
            self.setStyleSheet("background-color: black;")
            self.video_frame = QtWidgets.QFrame(self)
            self.video_frame.setStyleSheet("background-color: black;")
            self.video_frame.setAttribute(QtCore.Qt.WidgetAttribute.WA_NativeWindow, True)
            layout = QtWidgets.QVBoxLayout(self)
            layout.setContentsMargins(0, 0, 0, 0)
            layout.addWidget(self.video_frame)
            instance_args = ["--no-video-title-show", "--quiet"]
            if self.config.data.get("vlc_force_d3d11", True):
                instance_args += ["--vout=direct3d11"]
            if self.config.data.get("enable_vlc_file_log", False):
                instance_args += VLC_FILE_LOGGING_ARGS
            logger.debug("Child: creating VLC instance with args: %s", instance_args)
            self.instance = vlc.Instance(*instance_args)
            self.media_list_player = self.instance.media_list_player_new()
            self.media_player = self.instance.media_player_new()
            self.media_list_player.set_media_player(self.media_player)
            self.media_list = self.instance.media_list_new()
            self.media_list_player.set_media_list(self.media_list)
            self._playlist_paths: List[str] = []
            self._loop = True
            self._shuffle = False
            self._bound_hwnd = False
            try:
                mlp_em = self.media_list_player.event_manager()
                mlp_em.event_attach(vlc.EventType.MediaListPlayerStopped, self._on_list_stopped)
                mp_em = self.media_player.event_manager()
                mp_em.event_attach(vlc.EventType.MediaPlayerEncounteredError, self._on_player_error)
                mp_em.event_attach(vlc.EventType.MediaPlayerEndReached, self._on_end_reached)
                mp_em.event_attach(vlc.EventType.MediaPlayerPlaying, lambda e: logger.info("VLC: playing"))
                mp_em.event_attach(vlc.EventType.MediaPlayerPaused, lambda e: logger.info("VLC: paused"))
                mp_em.event_attach(vlc.EventType.MediaPlayerStopped, lambda e: logger.info("VLC: stopped"))
            except Exception as e:
                logger.warning("Child: failed to attach VLC events: %s", e)
        def bind_to_window(self):
            try:
                hwnd = int(self.video_frame.winId())
                if hwnd:
                    self.media_player.set_hwnd(hwnd)
                    self._bound_hwnd = True
                    logger.info("Bound VLC to HWND: %s", hwnd)
                else:
                    logger.error("winId() returned 0; cannot bind video output.")
            except Exception as e:
                logger.exception("Failed to bind video output window: %s", e)
        def set_volume(self, vol: int):
            self.media_player.audio_set_volume(max(0, min(100, int(vol))))
        def set_loop(self, loop: bool):
            self._loop = bool(loop)
            try:
                mode = vlc.PlaybackMode.loop if self._loop else vlc.PlaybackMode.default
                self.media_list_player.set_playback_mode(mode)
                logger.info("Playback mode set to: %s", "loop" if self._loop else "default")
            except Exception as e:
                logger.warning("Failed to set playback mode: %s", e)
        def set_shuffle(self, shuffle: bool):
            self._shuffle = bool(shuffle)
        def set_playlist(self, paths: List[str]):
            self._playlist_paths = [p for p in paths if os.path.isfile(p)]
            ordered = list(self._playlist_paths)
            if self._shuffle:
                import random
                random.shuffle(ordered)
            new_list = self.instance.media_list_new()
            for p in ordered:
                m = self.instance.media_new(p)
                new_list.add_media(m)
            self.media_list = new_list
            self.media_list_player.set_media_list(self.media_list)
            logger.info("Playlist set: %d item(s)", len(ordered))
        def play(self):
            if not self._playlist_paths:
                logger.warning("Play requested with empty playlist")
                return
            if not self._bound_hwnd:
                self.bind_to_window()
            self.set_loop(self._loop)
            logger.info("Starting playback")
            self.media_list_player.play()
        def pause(self):
            try:
                self.media_player.pause()
            except Exception as e:
                logger.warning("Pause failed: %s", e)
        def stop(self):
            try:
                self.media_list_player.stop()
            except Exception as e:
                logger.warning("Stop failed: %s", e)
        def _on_list_stopped(self, event):
            logger.debug("MediaListPlayerStopped event")
            if not self._loop:
                logger.info("Playlist finished (no loop).")
                self.ended.emit()
        def _on_player_error(self, event):
            logger.error("VLC MediaPlayer encountered an error")
            try:
                m = self.media_player.get_media()
                if m:
                    mrl = m.get_mrl()
                    logger.error("Error while playing: %s", mrl)
            except Exception:
                pass
        def _on_end_reached(self, event):
            logger.info("VLC: end reached")

    class OverlayPrompt(QtWidgets.QWidget):
        accepted = QtCore.pyqtSignal()
        def __init__(self, parent=None):
            super().__init__(parent)
            self.setAttribute(QtCore.Qt.WidgetAttribute.WA_StyledBackground, True)
            self.setStyleSheet("background-color: rgba(0,0,0,160);")
            self.setFocusPolicy(QtCore.Qt.FocusPolicy.StrongFocus)
            panel = QtWidgets.QFrame(self)
            panel.setStyleSheet("""
                QFrame {
                    background-color: rgba(20,20,20,220);
                    border: 1px solid rgba(255,255,255,80);
                    border-radius: 10px;
                }
                QLabel { color: white; font-size: 18pt; }
            """)
            msg = QtWidgets.QLabel("Hit any key (or click) to return", panel)
            msg.setAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)
            pl = QtWidgets.QVBoxLayout(panel)
            pl.setContentsMargins(24, 24, 24, 24)
            pl.addWidget(msg)
            self._panel = panel
        def resizeEvent(self, e):
            super().resizeEvent(e)
            w, h = 520, 140
            x = (self.width() - w) // 2
            y = (self.height() - h) // 2
            self._panel.setGeometry(x, y, w, h)
        def showEvent(self, e):
            super().showEvent(e)
            self.raise_()
            self.setFocus()
        def keyPressEvent(self, e: QtGui.QKeyEvent):
            self.accepted.emit()
        def mousePressEvent(self, e: QtGui.QMouseEvent):
            self.accepted.emit()

    class UnlockDialog(QtWidgets.QDialog):
        def __init__(self, config: ConfigManager, parent=None):
            super().__init__(parent)
            self.setWindowTitle("Password enter")
            self.setModal(True)
            self.setWindowFlag(QtCore.Qt.WindowType.FramelessWindowHint, True)
            self.setWindowFlag(QtCore.Qt.WindowType.WindowStaysOnTopHint, True)
            self.setAttribute(QtCore.Qt.WidgetAttribute.WA_StyledBackground, True)
            self.setStyleSheet("""
                QDialog {
                    background-color: rgba(20,20,20,230);
                    border: 1px solid rgba(255,255,255,80);
                    border-radius: 10px;
                }
                QLabel, QLineEdit { color: white; font-size: 11pt; }
                QPushButton { padding: 6px 12px; }
            """)
            self.config = config
            self._prev_hkl = None
            self._prev_himc = None
            layout = QtWidgets.QVBoxLayout(self)
            layout.setContentsMargins(24, 24, 24, 24)
            title = QtWidgets.QLabel("Password enter")
            f = title.font(); f.setPointSize(16); f.setBold(True)
            title.setFont(f)
            layout.addWidget(title)
            self.info_label = QtWidgets.QLabel()
            umode = self.config.data.get("unlock_mode", "windows")
            if umode == "windows":
                username, domain = get_current_username_and_domain()
                self.info_label.setText(f"Windows user: {domain}\\{username}")
            elif umode == "custom":
                self.info_label.setText("Custom password")
            else:
                self.info_label.setText("(No password required)")
            layout.addWidget(self.info_label)
            self.password_edit = QtWidgets.QLineEdit()
            self.password_edit.setPlaceholderText("Enter password")
            self.password_edit.setEchoMode(QtWidgets.QLineEdit.EchoMode.Password)
            self.password_edit.returnPressed.connect(self.try_unlock)
            layout.addWidget(self.password_edit)
            btns = QtWidgets.QHBoxLayout()
            self.ok_btn = QtWidgets.QPushButton("Unlock")
            self.cancel_btn = QtWidgets.QPushButton("Cancel")
            btns.addStretch(1); btns.addWidget(self.cancel_btn); btns.addWidget(self.ok_btn)
            layout.addLayout(btns)
            self.ok_btn.clicked.connect(self.try_unlock)
            self.cancel_btn.clicked.connect(self.reject)
            self.result_unlocked = False
        def showEvent(self, e: QtGui.QShowEvent):
            super().showEvent(e)
            self.resize(420, 180)
            parent = self.parentWidget()
            if parent:
                geom = parent.geometry()
                x = geom.x() + (geom.width() - self.width()) // 2
                y = geom.y() + (geom.height() - self.height()) // 2
                self.move(max(0, x), max(0, y))
            self.raise_(); self.activateWindow()
            try:
                self._prev_hkl = force_english_layout()
                hwnd = int(self.password_edit.winId())
                self._prev_himc = disable_ime_for_hwnd(hwnd)
            except Exception:
                pass
            self.password_edit.setFocus()
        def closeEvent(self, e: QtGui.QCloseEvent):
            try:
                hwnd = int(self.password_edit.winId())
                restore_ime_for_hwnd(hwnd, self._prev_himc)
                restore_layout(self._prev_hkl)
            except Exception:
                pass
            super().closeEvent(e)
        def try_unlock(self):
            umode = self.config.data.get("unlock_mode", "windows")
            if umode == "no_password":
                ok = True
            elif umode == "windows":
                ok = verify_windows_password(self.password_edit.text())
            else:
                salt = self.config.data.get("custom_pw_salt", "")
                hash_ = self.config.data.get("custom_pw_hash", "")
                rounds = int(self.config.data.get("custom_pw_rounds", 200000))
                ok = (salt and hash_ and pbkdf2_verify_password(self.password_edit.text(), salt, hash_, rounds))
            if ok:
                self.result_unlocked = True
                self.accept()
            else:
                QtWidgets.QMessageBox.warning(self, "Incorrect Password", "Incorrect password. Try again.")
                self.password_edit.clear()
                self.password_edit.setFocus()

    class ScreensaverChild(QtWidgets.QMainWindow):
        def __init__(self, run_mode: str):
            super().__init__()
            self.config = ConfigManager(CONFIG_PATH)
            self.run_mode = run_mode  # "normal" | "test"
            self.setWindowTitle("MP4Saver - Screensaver (child)")
            self.setWindowFlag(QtCore.Qt.WindowType.FramelessWindowHint, True)
            self.setWindowFlag(QtCore.Qt.WindowType.WindowStaysOnTopHint, True)
            self.setCursor(QtCore.Qt.CursorShape.BlankCursor)
            self.setStyleSheet("background-color: black;")
            self._last_mouse_pos = QtCore.QPoint(-1, -1)
            central = QtWidgets.QWidget(self)
            self.setCentralWidget(central)
            self.stack = QtWidgets.QStackedLayout(central)
            self.stack.setStackingMode(QtWidgets.QStackedLayout.StackingMode.StackAll)
            container = QtWidgets.QWidget(central)
            vbox = QtWidgets.QVBoxLayout(container); vbox.setContentsMargins(0,0,0,0)
            self.player = VLCPlayerWidget(self.config, container)
            vbox.addWidget(self.player)
            self.test_overlay = OverlayPrompt(central)
            self.test_overlay.hide()
            self.test_overlay.accepted.connect(lambda: self._exit(EXIT_TEST_RETURN))
            # A4: Transition overlay
            self.transition_overlay = TransitionOverlay(central)
            self.transition_overlay.hide()
            self.stack.addWidget(container)
            self.stack.addWidget(self.test_overlay)
            self.stack.addWidget(self.transition_overlay)
            # Configure player
            self.player.set_volume(int(self.config.data["volume"]))
            self.player.set_loop(bool(self.config.data["loop"]))
            self.player.set_shuffle(bool(self.config.data["shuffle"]))
            self.player.set_playlist(self.config.data.get("playlist", []))
            self.player.ended.connect(self._on_playlist_finished)
            # ESC
            self.esc_sc = QtGui.QShortcut(QtGui.QKeySequence("Esc"), self)
            self.esc_sc.activated.connect(self._request_unlock)
            # Optional remote control (Flask) — background thread
            self._remote_server = None
            if self.config.data.get("remote_control_enable", False):
                self._start_remote_server()
        # ----- New Features -----
        def setup_multi_monitor(self):
            if not self.config.data.get("multi_monitor_enable", False):
                return
            app = QtWidgets.QApplication.instance()
            screens = app.screens()
            if not screens:
                return
            total = QtCore.QRect()
            for s in screens:
                total = total.united(s.geometry())
            self.setGeometry(total)
        def _do_transition(self):
            if not self.config.data.get("transition_enable", False):
                return
            dur = int(self.config.data.get("transition_duration_ms", 600))
            self.transition_overlay.setGeometry(self.rect())
            self.transition_overlay.crossfade(duration_ms=dur)
        # Remote control (skeleton)
        def _start_remote_server(self):
            try:
                from threading import Thread
                try:
                    from flask import Flask, request, jsonify
                except Exception:
                    logger.warning("Flask not installed; remote control disabled.")
                    return
                app = Flask("MP4SaverRemote")
                cfg = self.config
                @app.get("/api/playlist")
                def get_playlist():
                    return jsonify(cfg.data.get("playlist", []))
                @app.post("/api/playlist")
                def set_playlist():
                    data = request.get_json(silent=True) or {}
                    plist = data.get("playlist", [])
                    if not isinstance(plist, list):
                        return jsonify({"ok": False, "err": "playlist must be a list"}), 400
                    cfg.data["playlist"] = plist
                    cfg.save()
                    return jsonify({"ok": True})
                @app.post("/api/action")
                def action():
                    data = request.get_json(silent=True) or {}
                    cmd = data.get("cmd")
                    if cmd == "pause":
                        self.player.pause(); return jsonify({"ok": True})
                    if cmd == "play":
                        self.player.play(); return jsonify({"ok": True})
                    if cmd == "unlock":
                        QtCore.QTimer.singleShot(0, lambda: self._exit(EXIT_UNLOCKED))
                        return jsonify({"ok": True})
                    return jsonify({"ok": False, "err": "unknown cmd"}), 400
                port = int(self.config.data.get("remote_control_port", 8080))
                def run():
                    app.run(host="127.0.0.1", port=port, debug=False, use_reloader=False)
                t = Thread(target=run, daemon=True)
                t.start()
                self._remote_server = t
                logger.info("Remote control server started on 127.0.0.1:%s", port)
            except Exception as e:
                logger.warning("Remote control server failed: %s", e)

        # ----- Flow -----
        def require_password(self) -> bool:
            if self.run_mode == "test":
                return False
            return self.config.data.get("unlock_mode", "windows") != "no_password"
        def showEvent(self, event: QtGui.QShowEvent):
            super().showEvent(event)
            self.setup_multi_monitor()
            self.showFullScreen()
            QtCore.QTimer.singleShot(50, self.player.bind_to_window)
            if self.config.data.get("power_prevent_sleep", True):
                set_thread_execution_state(True)
            QtCore.QTimer.singleShot(150, self.player.play)
        def resizeEvent(self, e: QtGui.QResizeEvent):
            super().resizeEvent(e)
            self.test_overlay.setGeometry(self.rect())
            self.transition_overlay.setGeometry(self.rect())
        def closeEvent(self, event: QtGui.QCloseEvent):
            if self.config.data.get("power_prevent_sleep", True):
                set_thread_execution_state(False)
            self.setCursor(QtCore.Qt.CursorShape.ArrowCursor)
            super().closeEvent(event)

        # --- A4: optional explicit cleanup ---
        def cleanup_resources(self):
            """Proper cleanup before exit (optional, controlled by config)"""
            logger.info("Child explicit cleanup: begin")
            try:
                try:
                    self.player.stop()
                except Exception:
                    pass
                try:
                    self.player.media_player.release()
                except Exception:
                    pass
                try:
                    self.player.media_list_player.release()
                except Exception:
                    pass
                try:
                    self.player.media_list.release()
                except Exception:
                    pass
                try:
                    self.player.instance.release()
                except Exception:
                    pass
            except Exception as e:
                logger.warning("cleanup_resources exception: %s", e)
            finally:
                logger.info("Child explicit cleanup: QApplication.quit()")
                QtWidgets.QApplication.quit()

        def _exit(self, code: int):
            # Respect config explicit cleanup mode
            if self.config.data.get("explicit_cleanup_on_exit", False):
                # Map exit semantics: schedule cleanup then exit with code via on-aboutToQuit
                app = QtWidgets.QApplication.instance()
                def finalize():
                    os._exit(code)
                app.aboutToQuit.connect(finalize)
                QtCore.QTimer.singleShot(0, self.cleanup_resources)
                return
            # Default: hard exit (most stable)
            os._exit(code)

        def _on_playlist_finished(self):
            logger.info("Child: playlist finished (run_mode=%s)", self.run_mode)
            self._do_transition()
            if self.run_mode == "test":
                self.test_overlay.setGeometry(self.rect())
                self.test_overlay.show(); self.test_overlay.raise_(); self.test_overlay.setFocus()
            else:
                if self.require_password():
                    self._request_unlock()
                else:
                    self._exit(EXIT_USER)

        def _request_unlock(self):
            if not self.require_password():
                self._exit(EXIT_USER if self.run_mode == "normal" else EXIT_TEST_RETURN)
                return
            try:
                self.player.pause()
            except Exception:
                pass
            dlg = UnlockDialog(self.config, self)
            res = dlg.exec()
            if getattr(dlg, "result_unlocked", False):
                self._exit(EXIT_UNLOCKED)
            else:
                try:
                    self.player.play()
                except Exception:
                    pass

        def keyPressEvent(self, event: QtGui.QKeyEvent):
            self._request_unlock()
        def mousePressEvent(self, event: QtGui.QMouseEvent):
            self._request_unlock()
        def mouseMoveEvent(self, event: QtGui.QMouseEvent):
            if self._last_mouse_pos == QtCore.QPoint(-1, -1):
                self._last_mouse_pos = event.globalPosition().toPoint()
                return
            dist = (event.globalPosition().toPoint() - self._last_mouse_pos)
            if abs(dist.x()) > 4 or abs(dist.y()) > 4:
                self._request_unlock()
            self._last_mouse_pos = event.globalPosition().toPoint()

    def excepthook_child(exctype, value, tb):
        logger.exception("Uncaught exception (child)", exc_info=(exctype, value, tb))
        # Hard exit to avoid libVLC finalizers
        os._exit(1)

    def main_child():
        sys.excepthook = excepthook_child
        if DEBUG_MODE:
            try:
                if VLC_LOG_PATH.exists():
                    VLC_LOG_PATH.unlink()
            except Exception:
                pass
        # parse mode
        mode = "normal"
        for arg in sys.argv:
            if arg.startswith("--mode="):
                mode = arg.split("=", 1)[1].strip().lower() or "normal"
        app = QtWidgets.QApplication([a for a in sys.argv if a not in ("--debug","--child") and not a.startswith("--mode=")])
        app.setApplicationName(APP_NAME + " Child")
        w = ScreensaverChild(mode)
        w.show()
        rc = app.exec()
        os._exit(EXIT_USER)

# ============================================================
# Entrypoint
# ============================================================
def excepthook_top(exctype, value, tb):
    logger.exception("Uncaught exception (top)", exc_info=(exctype, value, tb))
    if CHILD_MODE:
        os._exit(1)
    else:
        sys.__excepthook__(exctype, value, tb)

def main():
    sys.excepthook = excepthook_top
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    if DEBUG_MODE:
        try:
            if VLC_LOG_PATH.exists():
                VLC_LOG_PATH.unlink()
        except Exception:
            pass
    if CHILD_MODE:
        main_child()
    else:
        main_parent()

if __name__ == "__main__":
    main()
