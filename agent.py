import sys
import os
import time
import win32api
import win32con
import win32event
import win32file
import pywintypes
from threading import Thread

# Configuración del canal del puerto serie virtual COM1 para reportar logs al Host
SERIAL_PORT = "COM1"

def log_to_host(msg: str):
    """Envía un mensaje formateado al Host a través del puerto serie COM1."""
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    formatted = f"[GUEST-MONITOR] [{timestamp}] {msg}\n"
    print(formatted.strip())
    try:
        # Abrimos el puerto serie COM1 de Windows de forma directa
        handle = win32file.CreateFile(
            f"\\\\.\\{SERIAL_PORT}",
            win32file.GENERIC_WRITE,
            0,
            None,
            win32file.OPEN_EXISTING,
            0,
            None
        )
        win32file.WriteFile(handle, formatted.encode('utf-8'))
        win32file.CloseHandle(handle)
    except Exception as e:
        # Si falla (ej. puerto ocupado o no configurado), se ignora de forma silenciosa
        pass

# ---------------------------------------------------------------------------
# 1. Monitoreo de Filesystem (Cambios en archivos)
# ---------------------------------------------------------------------------
def watch_directory(path: str):
    """Monitorea creación, modificación y borrado de archivos en una ruta dada."""
    if not os.path.exists(path):
        try:
            os.makedirs(path)
        except Exception:
            return

    log_to_host(f"Iniciando monitoreo de filesystem en: {path}")
    hDir = win32file.CreateFile(
        path,
        0x0001,  # FILE_LIST_DIRECTORY
        win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE | win32con.FILE_SHARE_DELETE,
        None,
        win32con.OPEN_EXISTING,
        win32con.FILE_FLAG_BACKUP_SEMANTICS,
        None
    )

    while True:
        try:
            results = win32file.ReadDirectoryChangesW(
                hDir,
                1024,
                True,  # subárboles
                win32con.FILE_NOTIFY_CHANGE_FILE_NAME |
                win32con.FILE_NOTIFY_CHANGE_DIR_NAME |
                win32con.FILE_NOTIFY_CHANGE_ATTRIBUTES |
                win32con.FILE_NOTIFY_CHANGE_SIZE |
                win32con.FILE_NOTIFY_CHANGE_LAST_WRITE |
                win32con.FILE_NOTIFY_CHANGE_SECURITY,
                None,
                None
            )
            for action, file_name in results:
                action_str = {
                    1: "CREADO",
                    2: "BORRADO",
                    3: "MODIFICADO",
                    4: "RENOMBRADO (VIEJO)",
                    5: "RENOMBRADO (NUEVO)"
                }.get(action, "DESCONOCIDO")
                log_to_host(f"FILE_EVENT: [{action_str}] {os.path.join(path, file_name)}")
        except Exception as e:
            time.sleep(1)

# ---------------------------------------------------------------------------
# 2. Monitoreo de Registro (Persistencia / Inicio)
# ---------------------------------------------------------------------------
REG_KEYS = [
    (win32con.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
    (win32con.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
    (win32con.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    (win32con.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce")
]

def watch_registry_key(root, subkey: str):
    """Monitorea adiciones o modificaciones en claves del Registro de Windows."""
    log_to_host(f"Iniciando monitoreo de registro en: {subkey}")
    try:
        # Abrimos la clave con permisos de notificación
        hKey = win32api.RegOpenKeyEx(root, subkey, 0, win32con.KEY_NOTIFY | win32con.KEY_READ)
    except Exception as e:
        log_to_host(f"ERROR: No se pudo abrir clave de registro: {subkey} ({e})")
        return

    # Guardar snapshot inicial de valores
    last_values = {}
    try:
        info = win32api.RegQueryInfoKey(hKey)
        for i in range(info[1]):
            val_name, val_data, _ = win32api.RegEnumValue(hKey, i)
            last_values[val_name] = val_data
    except Exception:
        pass

    event = win32event.CreateEvent(None, 0, 0, None)
    
    while True:
        try:
            # Registrar evento de cambio en el registro
            win32api.RegNotifyChangeKeyValue(
                hKey,
                True,  # subarbol
                win32con.REG_NOTIFY_CHANGE_NAME | win32con.REG_NOTIFY_CHANGE_LAST_SET,
                event,
                True
            )
            # Esperar la notificación
            win32event.WaitForSingleObject(event, win32event.INFINITE)
            
            # Comparar valores actuales con el snapshot anterior para encontrar el cambio exacto
            current_values = {}
            info = win32api.RegQueryInfoKey(hKey)
            for i in range(info[1]):
                val_name, val_data, _ = win32api.RegEnumValue(hKey, i)
                current_values[val_name] = val_data

            # Buscar valores agregados o modificados
            for name, data in current_values.items():
                if name not in last_values:
                    log_to_host(f"REG_EVENT: [NUEVO VALOR] en {subkey} -> Name: '{name}', Data: '{data}'")
                elif last_values[name] != data:
                    log_to_host(f"REG_EVENT: [MODIFICADO] en {subkey} -> Name: '{name}', Viejo: '{last_values[name]}', Nuevo: '{data}'")

            # Buscar valores borrados
            for name in list(last_values.keys()):
                if name not in current_values:
                    log_to_host(f"REG_EVENT: [BORRADO] en {subkey} -> Name: '{name}'")

            last_values = current_values
        except Exception as e:
            time.sleep(1)

# ---------------------------------------------------------------------------
# Inicio del Agente
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    log_to_host("=== Agente de Monitoreo Dinámico Iniciado ===")

    # Rutas típicas de Windows para monitorear archivos
    user_profile = os.environ.get("USERPROFILE", "C:\\")
    paths_to_watch = [
        os.path.join(user_profile, "Desktop"),
        os.path.join(user_profile, "AppData", "Local", "Temp"),
        "C:\\Windows\\System32"
    ]

    threads = []
    # Lanzar hilos de monitoreo de archivos
    for path in paths_to_watch:
        t = Thread(target=watch_directory, args=(path,), daemon=True)
        t.start()
        threads.append(t)

    # Lanzar hilos de monitoreo de registro
    for root, subkey in REG_KEYS:
        t = Thread(target=watch_registry_key, args=(root, subkey), daemon=True)
        t.start()
        threads.append(t)

    # Mantener el script corriendo
    while True:
        try:
            time.sleep(5)
        except KeyboardInterrupt:
            log_to_host("Deteniendo agente...")
            sys.exit(0)
