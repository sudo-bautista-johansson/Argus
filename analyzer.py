"""
analyzer.py — Motor de análisis estático de muestras PE
-------------------------------------------------------
Analiza un ejecutable Windows (PE) sin ejecutarlo, buscando indicadores
de comportamiento malicioso. Genera un reporte estructurado.

Técnicas de análisis:
  1. Metadatos y hashes (MD5, SHA-256)
  2. Cabecera PE (timestamp de compilación, subsistema, flags)
  3. Análisis de secciones (entropía, permisos, nombres anómalos)
  4. Análisis de imports (APIs sospechosas categorizadas por técnica)
  5. Detección de packing/ofuscación (entropía global)
  6. Extracción de strings sospechosos (URLs, IPs, rutas, registros, comandos)
  7. Detección de overlay (datos después del PE)
  8. Puntuación heurística de amenaza
"""

import os
import math
import hashlib
import re
import struct
from datetime import datetime, timezone
from typing import Callable

try:
    import pefile
    HAS_PEFILE = True
except ImportError:
    HAS_PEFILE = False


# ---------------------------------------------------------------------------
# Constantes: APIs sospechosas categorizadas por técnica MITRE ATT&CK
# ---------------------------------------------------------------------------
SUSPICIOUS_IMPORTS = {
    "Inyección de procesos": [
        "CreateRemoteThread", "CreateRemoteThreadEx",
        "NtCreateThreadEx", "RtlCreateUserThread",
        "WriteProcessMemory", "NtWriteVirtualMemory",
        "VirtualAllocEx", "NtAllocateVirtualMemory",
        "QueueUserAPC", "NtQueueApcThread",
        "SetThreadContext", "NtSetContextThread",
    ],
    "Hooking / Intercepción": [
        "SetWindowsHookExA", "SetWindowsHookExW",
        "UnhookWindowsHookEx",
        "GetAsyncKeyState", "GetKeyState", "GetKeyboardState",
        "SetWinEventHook",
    ],
    "Evasión de detección": [
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
        "NtQueryInformationProcess", "OutputDebugStringA",
        "GetTickCount", "QueryPerformanceCounter",
        "NtSetInformationThread",
        "VirtualProtect", "VirtualProtectEx",
    ],
    "Persistencia": [
        "RegSetValueExA", "RegSetValueExW",
        "RegCreateKeyExA", "RegCreateKeyExW",
        "CreateServiceA", "CreateServiceW",
        "StartServiceA", "StartServiceW",
    ],
    "Ejecución / Procesos": [
        "CreateProcessA", "CreateProcessW",
        "CreateProcessInternalW",
        "WinExec", "ShellExecuteA", "ShellExecuteW",
        "ShellExecuteExA", "ShellExecuteExW",
        "NtCreateProcess", "NtCreateProcessEx",
    ],
    "Red / Comunicación C2": [
        "InternetOpenA", "InternetOpenW",
        "InternetOpenUrlA", "InternetOpenUrlW",
        "InternetConnectA", "InternetConnectW",
        "HttpOpenRequestA", "HttpOpenRequestW",
        "HttpSendRequestA", "HttpSendRequestW",
        "URLDownloadToFileA", "URLDownloadToFileW",
        "WSAStartup", "connect", "send", "recv",
        "socket", "bind", "listen", "accept",
    ],
    "Manipulación de archivos": [
        "CreateFileA", "CreateFileW",
        "DeleteFileA", "DeleteFileW",
        "MoveFileA", "MoveFileW",
        "CopyFileA", "CopyFileW",
        "CreateFileMappingA", "CreateFileMappingW",
        "MapViewOfFile",
    ],
    "Criptografía": [
        "CryptEncrypt", "CryptDecrypt",
        "CryptCreateHash", "CryptHashData",
        "CryptAcquireContextA", "CryptAcquireContextW",
        "CryptGenKey", "CryptDeriveKey",
        "CryptImportKey", "CryptExportKey",
        "BCryptEncrypt", "BCryptDecrypt",
    ],
    "Escalada de privilegios": [
        "AdjustTokenPrivileges", "OpenProcessToken",
        "LookupPrivilegeValueA", "LookupPrivilegeValueW",
        "ImpersonateLoggedOnUser", "DuplicateToken",
        "SetTokenInformation",
    ],
    "Enumeración del sistema": [
        "GetSystemInfo", "GetNativeSystemInfo",
        "GetComputerNameA", "GetComputerNameW",
        "GetUserNameA", "GetUserNameW",
        "GetVersionExA", "GetVersionExW",
        "CreateToolhelp32Snapshot",
        "Process32First", "Process32Next",
        "Thread32First", "Thread32Next",
        "Module32First", "Module32Next",
    ],
}

# Nombres de secciones normales vs. sospechosos
NORMAL_SECTIONS = {
    ".text", ".rdata", ".data", ".rsrc", ".reloc",
    ".idata", ".edata", ".pdata", ".tls", ".bss",
    ".CRT", ".debug", ".didat",
}

# Nombres conocidos de packers
PACKER_SECTIONS = {
    "UPX0": "UPX", "UPX1": "UPX", "UPX2": "UPX",
    ".aspack": "ASPack", ".adata": "ASPack",
    ".nsp0": "NsPack", ".nsp1": "NsPack",
    "nsp0": "NsPack", "nsp1": "NsPack",
    ".vmp0": "VMProtect", ".vmp1": "VMProtect",
    ".themida": "Themida", ".winlice": "WinLicense",
    ".petite": "Petite", ".yP": "Y0da Protector",
    ".packed": "Genérico (packed)",
    "MEW": "MEW", ".mew": "MEW",
    ".enigma1": "Enigma Protector", ".enigma2": "Enigma Protector",
}

# Regex para strings sospechosos
SUSPICIOUS_PATTERNS = {
    "URL HTTP/HTTPS": re.compile(rb'https?://[\w\-.]+(?:\.\w{2,})+[^\x00\s"\'<>]*', re.IGNORECASE),
    "Dirección IP": re.compile(rb'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
    "Dirección email": re.compile(rb'[\w.+-]+@[\w-]+\.[\w.]+'),
    "Ruta de registro Windows": re.compile(
        rb'(?:HKEY_LOCAL_MACHINE|HKLM|HKEY_CURRENT_USER|HKCU|SOFTWARE)\\[\w\\]+',
        re.IGNORECASE
    ),
    "Comando de shell": re.compile(
        rb'(?:cmd\.exe|powershell|wscript|cscript|mshta|certutil|bitsadmin|regsvr32|rundll32)',
        re.IGNORECASE
    ),
    "Extensión ejecutable": re.compile(
        rb'[\w\-]+\.(?:exe|dll|bat|ps1|vbs|js|scr|pif|com|cmd)\b',
        re.IGNORECASE
    ),
    "Ruta de archivo Windows": re.compile(
        rb'[A-Z]:\\(?:[\w\s\-.]+\\)*[\w\s\-.]+',
    ),
}


# ---------------------------------------------------------------------------
# Funciones auxiliares
# ---------------------------------------------------------------------------
def _calc_entropy(data: bytes) -> float:
    """Calcula la entropía de Shannon de un bloque de bytes (0.0 - 8.0)."""
    if not data:
        return 0.0
    freq = [0] * 256
    for byte in data:
        freq[byte] += 1
    length = len(data)
    entropy = 0.0
    for count in freq:
        if count:
            p = count / length
            entropy -= p * math.log2(p)
    return entropy


def _extract_strings(data: bytes, min_length: int = 6):
    """Extrae strings ASCII y Unicode legibles de un bloque de bytes."""
    # ASCII
    ascii_re = re.compile(rb'[\x20-\x7e]{%d,}' % min_length)
    for m in ascii_re.finditer(data):
        yield m.group().decode('ascii', errors='replace')

    # UTF-16 LE (cada carácter ocupa 2 bytes, el segundo suele ser 0x00)
    unicode_re = re.compile(
        rb'(?:[\x20-\x7e]\x00){%d,}' % min_length
    )
    for m in unicode_re.finditer(data):
        try:
            yield m.group().decode('utf-16-le', errors='replace')
        except Exception:
            pass


def _format_size(size_bytes: int) -> str:
    """Formatea un tamaño en bytes de forma legible."""
    for unit in ("B", "KB", "MB", "GB"):
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} TB"


# ---------------------------------------------------------------------------
# Clase principal del analizador
# ---------------------------------------------------------------------------
class MalwareAnalyzer:
    """
    Realiza análisis estático completo de un ejecutable PE.
    Emite el reporte línea por línea a través de un callback `emit`.
    """

    def __init__(self, filepath: str, emit: Callable[[str], None]):
        self.filepath = filepath
        self.emit = emit
        self.threat_score = 0
        self.findings = []

    def _flag(self, points: int, finding: str):
        """Registra un hallazgo y suma puntos al score."""
        self.threat_score += points
        self.findings.append((points, finding))

    def analyze(self):
        """Ejecuta todas las fases de análisis."""
        self.emit("━" * 70)
        self.emit("🔬  ANÁLISIS ESTÁTICO DE MALWARE — REPORTE COMPLETO")
        self.emit("━" * 70)

        if not os.path.isfile(self.filepath):
            self.emit(f"❌ ERROR: No se encontró el archivo: {self.filepath}")
            return

        with open(self.filepath, "rb") as f:
            raw_data = f.read()

        self._phase_metadata(raw_data)
        self._phase_pe_headers(raw_data)
        self._phase_sections(raw_data)
        self._phase_imports()
        self._phase_strings(raw_data)
        self._phase_overlay(raw_data)
        self._phase_verdict()

    # ── Fase 1: Metadatos ─────────────────────────────────────────────
    def _phase_metadata(self, raw_data: bytes):
        self.emit("")
        self.emit("┌─────────────────────────────────────────────────────┐")
        self.emit("│  📋  FASE 1: METADATOS DEL ARCHIVO                 │")
        self.emit("└─────────────────────────────────────────────────────┘")

        file_size = os.path.getsize(self.filepath)
        md5 = hashlib.md5(raw_data).hexdigest()
        sha256 = hashlib.sha256(raw_data).hexdigest()
        sha1 = hashlib.sha1(raw_data).hexdigest()

        self.emit(f"  Archivo:   {os.path.basename(self.filepath)}")
        self.emit(f"  Ruta:      {self.filepath}")
        self.emit(f"  Tamaño:    {_format_size(file_size)} ({file_size:,} bytes)")
        self.emit(f"  MD5:       {md5}")
        self.emit(f"  SHA-1:     {sha1}")
        self.emit(f"  SHA-256:   {sha256}")

        # Entropía global
        global_entropy = _calc_entropy(raw_data)
        self.emit(f"  Entropía:  {global_entropy:.4f} / 8.0")

        if global_entropy > 7.2:
            self._flag(25, f"Entropía global muy alta ({global_entropy:.2f}) — probable packing/cifrado")
            self.emit(f"  ⚠️  ALERTA: Entropía alta sugiere que el binario está empaquetado o cifrado")
        elif global_entropy > 6.8:
            self._flag(10, f"Entropía global elevada ({global_entropy:.2f}) — posible compresión parcial")
            self.emit(f"  ⚠️  Entropía elevada, posible compresión parcial")

        # Magic bytes
        if raw_data[:2] == b'MZ':
            self.emit(f"  Formato:   PE (ejecutable Windows)")
        else:
            self.emit(f"  ⚠️  El archivo NO tiene cabecera MZ válida")
            self._flag(5, "Cabecera MZ ausente o corrupta")

    # ── Fase 2: Cabeceras PE ──────────────────────────────────────────
    def _phase_pe_headers(self, raw_data: bytes):
        self.emit("")
        self.emit("┌─────────────────────────────────────────────────────┐")
        self.emit("│  🔧  FASE 2: CABECERA PE                           │")
        self.emit("└─────────────────────────────────────────────────────┘")

        if not HAS_PEFILE:
            self.emit("  ⚠️  Módulo 'pefile' no disponible. Saltando análisis PE.")
            return

        try:
            self.pe = pefile.PE(data=raw_data)
        except pefile.PEFormatError as e:
            self.emit(f"  ❌ Error al parsear PE: {e}")
            self._flag(15, f"No se pudo parsear como PE válido: {e}")
            self.pe = None
            return

        # Timestamp de compilación
        ts = self.pe.FILE_HEADER.TimeDateStamp
        try:
            compile_time = datetime.fromtimestamp(ts, tz=timezone.utc)
            self.emit(f"  Compilado:    {compile_time.strftime('%Y-%m-%d %H:%M:%S')} UTC")

            if compile_time.year < 2000:
                self._flag(10, f"Timestamp de compilación sospechoso (año {compile_time.year})")
                self.emit(f"  ⚠️  Timestamp anómalo (posiblemente falsificado)")
            elif compile_time > datetime.now(tz=timezone.utc):
                self._flag(10, "Timestamp de compilación en el futuro")
                self.emit(f"  ⚠️  Timestamp en el futuro (falsificado)")
        except (ValueError, OSError):
            self.emit(f"  Compilado:    Timestamp inválido (raw: {ts})")
            self._flag(5, "Timestamp inválido")

        # Machine type
        machine = self.pe.FILE_HEADER.Machine
        machine_names = {0x14c: "x86 (32-bit)", 0x8664: "x64 (64-bit)", 0x1c0: "ARM"}
        self.emit(f"  Arquitectura: {machine_names.get(machine, f'Desconocida (0x{machine:x})')}")

        # Subsystem
        subsystem = self.pe.OPTIONAL_HEADER.Subsystem
        sub_names = {
            1: "Nativo (driver)", 2: "GUI Windows", 3: "Consola",
            5: "OS/2", 7: "POSIX", 9: "Windows CE",
        }
        sub_name = sub_names.get(subsystem, f"Desconocido ({subsystem})")
        self.emit(f"  Subsistema:   {sub_name}")
        if subsystem == 1:
            self._flag(20, "Subsistema nativo (posible rootkit/driver)")
            self.emit(f"  ⚠️  Subsistema NATIVO — podría ser un driver/rootkit")

        # Characteristics
        chars = self.pe.FILE_HEADER.Characteristics
        char_flags = []
        if chars & 0x0002:
            char_flags.append("EXECUTABLE_IMAGE")
        if chars & 0x0020:
            char_flags.append("LARGE_ADDRESS_AWARE")
        if chars & 0x0100:
            char_flags.append("32BIT_MACHINE")
        if chars & 0x2000:
            char_flags.append("DLL")
        self.emit(f"  Flags:        {', '.join(char_flags) if char_flags else 'Ninguno'}")

        # DLL Characteristics (seguridad)
        dll_chars = self.pe.OPTIONAL_HEADER.DllCharacteristics
        security = []
        if dll_chars & 0x0040:
            security.append("ASLR ✅")
        else:
            security.append("ASLR ❌")
            self._flag(5, "ASLR deshabilitado")
        if dll_chars & 0x0100:
            security.append("NX/DEP ✅")
        else:
            security.append("NX/DEP ❌")
            self._flag(5, "NX/DEP deshabilitado")
        if dll_chars & 0x4000:
            security.append("Control Flow Guard ✅")
        else:
            security.append("CFG ❌")
        self.emit(f"  Seguridad:    {' | '.join(security)}")

        # Entry point
        ep = self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
        self.emit(f"  Entry Point:  0x{ep:08X}")

        # Verificar si el entry point cae fuera de las secciones conocidas
        ep_in_section = False
        for section in self.pe.sections:
            sec_start = section.VirtualAddress
            sec_end = sec_start + section.Misc_VirtualSize
            if sec_start <= ep < sec_end:
                sec_name = section.Name.decode('ascii', errors='replace').strip('\x00')
                self.emit(f"  EP sección:   {sec_name}")
                if sec_name not in ('.text', '.code', 'CODE', '.init'):
                    self._flag(15, f"Entry point en sección inusual: {sec_name}")
                    self.emit(f"  ⚠️  Entry point en sección NO estándar ({sec_name})")
                ep_in_section = True
                break
        if not ep_in_section:
            self._flag(20, "Entry point fuera de todas las secciones")
            self.emit(f"  ⚠️  Entry point NO pertenece a ninguna sección conocida")

    # ── Fase 3: Secciones ─────────────────────────────────────────────
    def _phase_sections(self, raw_data: bytes):
        self.emit("")
        self.emit("┌─────────────────────────────────────────────────────┐")
        self.emit("│  📦  FASE 3: ANÁLISIS DE SECCIONES                 │")
        self.emit("└─────────────────────────────────────────────────────┘")

        if not hasattr(self, 'pe') or self.pe is None:
            self.emit("  ⚠️  PE no parseado, saltando análisis de secciones.")
            return

        self.emit(f"  {'Nombre':<12} {'VSize':>10} {'RawSize':>10} {'Entropía':>10} {'Permisos':<10} {'Estado'}")
        self.emit(f"  {'─'*12} {'─'*10} {'─'*10} {'─'*10} {'─'*10} {'─'*20}")

        detected_packer = None

        for section in self.pe.sections:
            name = section.Name.decode('ascii', errors='replace').strip('\x00')
            vsize = section.Misc_VirtualSize
            rsize = section.SizeOfRawData
            entropy = section.get_entropy()
            chars = section.Characteristics

            # Permisos
            perms = ""
            if chars & 0x20000000:
                perms += "X"
            if chars & 0x40000000:
                perms += "R"
            if chars & 0x80000000:
                perms += "W"

            # Estado
            status = "✅"
            issues = []

            # Entropía alta
            if entropy > 7.2:
                issues.append("Entropía MUY alta")
                self._flag(10, f"Sección '{name}' con entropía {entropy:.2f} (posible cifrado)")
            elif entropy > 6.8:
                issues.append("Entropía elevada")
                self._flag(5, f"Sección '{name}' con entropía elevada ({entropy:.2f})")

            # Sección con permisos RWX
            if "R" in perms and "W" in perms and "X" in perms:
                issues.append("RWX ⚠️")
                self._flag(15, f"Sección '{name}' tiene permisos RWX (lectura+escritura+ejecución)")

            # Sección ejecutable y escribible sin lectura
            if "W" in perms and "X" in perms:
                self._flag(5, f"Sección '{name}' es escribible y ejecutable")

            # VirtualSize mucho mayor que RawSize (posible unpacking)
            if rsize > 0 and vsize > rsize * 10:
                issues.append("VSize >> RawSize")
                self._flag(10, f"Sección '{name}': VirtualSize ({vsize}) >> RawSize ({rsize})")

            # RawSize es 0 pero VSize es grande
            if rsize == 0 and vsize > 0x1000:
                issues.append("RawSize=0")
                self._flag(10, f"Sección '{name}': RawSize=0 con VSize={vsize} (unpacking)")

            # Sección con nombre de packer conocido
            if name in PACKER_SECTIONS:
                packer = PACKER_SECTIONS[name]
                issues.append(f"Packer: {packer}")
                detected_packer = packer
                self._flag(20, f"Sección '{name}' asociada al packer: {packer}")

            # Nombre no estándar
            if name not in NORMAL_SECTIONS and name not in PACKER_SECTIONS:
                clean = name.replace('\x00', '').strip()
                if clean and not clean.startswith('.'):
                    issues.append("Nombre inusual")
                    self._flag(3, f"Sección con nombre inusual: '{name}'")

            if issues:
                status = "⚠️  " + ", ".join(issues)

            self.emit(f"  {name:<12} {vsize:>10,} {rsize:>10,} {entropy:>10.4f} {perms:<10} {status}")

        if detected_packer:
            self.emit(f"\n  🔒 PACKER DETECTADO: {detected_packer}")
            self.emit(f"     El binario está empaquetado, ocultando su contenido real.")

    # ── Fase 4: Imports ───────────────────────────────────────────────
    def _phase_imports(self):
        self.emit("")
        self.emit("┌─────────────────────────────────────────────────────┐")
        self.emit("│  📡  FASE 4: ANÁLISIS DE IMPORTS (APIs)            │")
        self.emit("└─────────────────────────────────────────────────────┘")

        if not hasattr(self, 'pe') or self.pe is None:
            self.emit("  ⚠️  PE no parseado, saltando análisis de imports.")
            return

        if not hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
            self.emit("  ℹ️  Sin tabla de imports (posible packing completo).")
            self._flag(15, "Sin tabla de imports visible (probable packing)")
            return

        # Recoger todas las funciones importadas
        all_imports = {}
        total_apis = 0
        for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode('ascii', errors='replace')
            funcs = []
            for imp in entry.imports:
                if imp.name:
                    funcs.append(imp.name.decode('ascii', errors='replace'))
                    total_apis += 1
            all_imports[dll_name] = funcs

        self.emit(f"  DLLs importadas: {len(all_imports)}")
        self.emit(f"  APIs totales:    {total_apis}")
        self.emit("")

        # Listar DLLs
        for dll_name, funcs in all_imports.items():
            self.emit(f"  📎 {dll_name} ({len(funcs)} funciones)")

        self.emit("")

        # Buscar APIs sospechosas
        found_categories = {}
        for category, api_list in SUSPICIOUS_IMPORTS.items():
            found = []
            for dll_name, funcs in all_imports.items():
                for func in funcs:
                    if func in api_list:
                        found.append((dll_name, func))
            if found:
                found_categories[category] = found

        if found_categories:
            self.emit("  ╔══════════════════════════════════════════════════╗")
            self.emit("  ║  ⚠️  APIs SOSPECHOSAS DETECTADAS                ║")
            self.emit("  ╚══════════════════════════════════════════════════╝")
            for category, apis in found_categories.items():
                score = len(apis) * 5
                self._flag(score, f"{category}: {len(apis)} APIs sospechosas")
                self.emit(f"\n  🔴 {category} ({len(apis)} APIs):")
                for dll, api in apis:
                    self.emit(f"     └── {api}  ({dll})")
        else:
            self.emit("  ✅ No se detectaron APIs sospechosas en los imports.")

    # ── Fase 5: Strings ───────────────────────────────────────────────
    def _phase_strings(self, raw_data: bytes):
        self.emit("")
        self.emit("┌─────────────────────────────────────────────────────┐")
        self.emit("│  🔤  FASE 5: EXTRACCIÓN DE STRINGS SOSPECHOSOS     │")
        self.emit("└─────────────────────────────────────────────────────┘")

        # Buscar patrones sospechosos directamente en los bytes
        found_patterns = {}
        for pattern_name, regex in SUSPICIOUS_PATTERNS.items():
            matches = set()
            for m in regex.finditer(raw_data):
                try:
                    decoded = m.group().decode('ascii', errors='replace')
                    # Filtrar falsos positivos cortos
                    if len(decoded) >= 4:
                        matches.add(decoded)
                except Exception:
                    pass
            if matches:
                found_patterns[pattern_name] = list(matches)[:15]  # Limitar a 15

        if found_patterns:
            for pattern_name, items in found_patterns.items():
                score = min(len(items) * 3, 20)
                self._flag(score, f"{pattern_name}: {len(items)} coincidencias")
                self.emit(f"\n  🔍 {pattern_name} ({len(items)} encontrados):")
                for item in items:
                    self.emit(f"     └── {item}")
        else:
            self.emit("  ✅ No se encontraron strings sospechosos relevantes.")

        # Buscar strings que parecen base64
        b64_re = re.compile(rb'[A-Za-z0-9+/]{40,}={0,2}')
        b64_matches = list(set(m.group().decode('ascii') for m in b64_re.finditer(raw_data)))
        if b64_matches:
            self.emit(f"\n  🔍 Posibles strings Base64 ({len(b64_matches)} encontrados):")
            for s in b64_matches[:5]:
                preview = s[:80] + "..." if len(s) > 80 else s
                self.emit(f"     └── {preview}")
            self._flag(min(len(b64_matches) * 3, 15), f"Strings Base64 detectados ({len(b64_matches)})")

    # ── Fase 6: Overlay ───────────────────────────────────────────────
    def _phase_overlay(self, raw_data: bytes):
        self.emit("")
        self.emit("┌─────────────────────────────────────────────────────┐")
        self.emit("│  📎  FASE 6: DETECCIÓN DE OVERLAY                  │")
        self.emit("└─────────────────────────────────────────────────────┘")

        if not hasattr(self, 'pe') or self.pe is None:
            self.emit("  ⚠️  PE no parseado, saltando detección de overlay.")
            return

        # Calcular el final real del PE
        overlay_offset = self.pe.get_overlay_data_start_offset()
        if overlay_offset is not None and overlay_offset < len(raw_data):
            overlay_size = len(raw_data) - overlay_offset
            overlay_data = raw_data[overlay_offset:]
            overlay_entropy = _calc_entropy(overlay_data)

            self.emit(f"  ⚠️  OVERLAY DETECTADO")
            self.emit(f"  Offset:    0x{overlay_offset:08X}")
            self.emit(f"  Tamaño:    {_format_size(overlay_size)} ({overlay_size:,} bytes)")
            self.emit(f"  Entropía:  {overlay_entropy:.4f}")

            ratio = (overlay_size / len(raw_data)) * 100
            self.emit(f"  Porcentaje del archivo: {ratio:.1f}%")

            if overlay_entropy > 7.0:
                self._flag(15, f"Overlay con entropía alta ({overlay_entropy:.2f}) — posible payload cifrado")
                self.emit(f"  ⚠️  Entropía alta en overlay: posible payload cifrado o comprimido")
            elif overlay_size > 10000:
                self._flag(5, f"Overlay significativo ({_format_size(overlay_size)})")

            # Verificar magic bytes del overlay
            if overlay_data[:2] == b'MZ':
                self._flag(20, "Overlay contiene otro ejecutable PE embebido")
                self.emit(f"  🔴 ¡El overlay contiene OTRO ejecutable PE!")
            elif overlay_data[:2] == b'PK':
                self._flag(10, "Overlay contiene archivo ZIP embebido")
                self.emit(f"  ⚠️  El overlay parece contener un ZIP")
            elif overlay_data[:4] == b'\x7fELF':
                self._flag(15, "Overlay contiene binario ELF embebido")
                self.emit(f"  🔴 El overlay contiene un binario ELF (Linux)")
        else:
            self.emit("  ✅ No se detectó overlay (datos adicionales después del PE).")

    # ── Veredicto Final ───────────────────────────────────────────────
    def _phase_verdict(self):
        self.emit("")
        self.emit("━" * 70)
        self.emit("📊  VEREDICTO FINAL — PUNTUACIÓN HEURÍSTICA")
        self.emit("━" * 70)

        # Clasificación
        if self.threat_score >= 80:
            level = "🔴 ALTO"
            verdict = "ALTAMENTE SOSPECHOSO — Múltiples indicadores de malware"
            color = "ROJO"
        elif self.threat_score >= 50:
            level = "🟠 MEDIO-ALTO"
            verdict = "SOSPECHOSO — Varios indicadores requieren investigación"
            color = "NARANJA"
        elif self.threat_score >= 25:
            level = "🟡 MEDIO"
            verdict = "MODERADO — Algunos indicadores atípicos detectados"
            color = "AMARILLO"
        elif self.threat_score >= 10:
            level = "🟢 BAJO"
            verdict = "PROBABLEMENTE BENIGNO — Pocos indicadores menores"
            color = "VERDE"
        else:
            level = "✅ MUY BAJO"
            verdict = "SIN INDICADORES SIGNIFICATIVOS"
            color = "VERDE"

        self.emit(f"\n  Puntuación de amenaza: {self.threat_score} / 100+")
        self.emit(f"  Nivel de riesgo:      {level}")
        self.emit(f"  Veredicto:            {verdict}")

        if self.findings:
            self.emit(f"\n  ┌── Hallazgos detallados ({len(self.findings)}) ──")
            for points, finding in sorted(self.findings, key=lambda x: -x[0]):
                icon = "🔴" if points >= 15 else ("🟡" if points >= 5 else "ℹ️")
                self.emit(f"  │ {icon} [{points:+3d} pts] {finding}")
            self.emit(f"  └────────────────────────────────────────────")

        self.emit("")
        self.emit("━" * 70)
        self.emit("  ℹ️  Este es un análisis ESTÁTICO. Para un análisis completo,")
        self.emit("     se recomienda ejecución dinámica dentro de la VM sandbox.")
        self.emit("━" * 70)
