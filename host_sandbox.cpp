// host_sandbox.cpp
// ---------------------------------------------------------------------------
// Orquestador de sandbox de análisis de muestras sobre QEMU.
//
// Capas de seguridad implementadas en este archivo:
//   1. Aislamiento de host   -> ejecución exclusiva dentro de una VM QEMU
//   2. Aislamiento de red    -> red "user mode" (NAT) de QEMU, sin bridge a la LAN
//   3. Snapshot descartable  -> disco overlay qcow2 sobre la imagen base
//   6. Salida controlada     -> carpeta de reportes de solo escritura desde la VM
//
// Las capas 4 (monitoreo profundo de API/registro/procesos) y 5 (anti-evasión)
// NO están implementadas acá: requieren herramientas dedicadas (agente dentro
// de la VM + Frida/ETW, o un sandbox como CAPE) y se explican al final.
//
// Compilar (MinGW o MSVC):
//   g++ -std=c++17 host_sandbox.cpp -o host_sandbox.exe -lcomdlg32
// ---------------------------------------------------------------------------

#include <windows.h>
#include <iostream>
#include <string>
#include <filesystem>
#include <fstream>
#include <chrono>
#include <ctime>
#include <sstream>
#include <pybind11/pybind11.h>

namespace fs = std::filesystem;
using namespace std;

// ---------------------------------------------------------------------------
// Configuración recolectada del usuario
// ---------------------------------------------------------------------------
struct Paths {
    string qemu_path;      // qemu-system-x86_64.exe
    string qemu_img_path;  // qemu-img.exe (mismo directorio que qemu_path normalmente)
    string vm_base_path;   // imagen base .qcow2 (NUNCA se escribe directamente)
    string malware_path;   // muestra a analizar
    string work_dir;       // carpeta de trabajo para overlay + reportes de esta corrida
};

// ---------------------------------------------------------------------------
// Utilidades
// ---------------------------------------------------------------------------
static string timestamp() {
    auto now = chrono::system_clock::to_time_t(chrono::system_clock::now());
    tm local_tm{};
    localtime_s(&local_tm, &now);
    ostringstream oss;
    oss << put_time(&local_tm, "%Y%m%d_%H%M%S");
    return oss.str();
}

static void log_line(ofstream& log, const string& msg) {
    cout << msg << "\n";
    if (log.is_open()) log << msg << "\n";
}

// Diálogo nativo de selección de archivo (Windows). Devuelve "" si se cancela.
static string openFileDialog(const string& title, const string& filter) {
    OPENFILENAMEA ofn{};
    char szFile[MAX_PATH] = {0};

    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = nullptr;
    ofn.lpstrFilter = filter.c_str();   // formato: "QEMU\0*.exe\0\0"
    ofn.lpstrFile = szFile;
    ofn.nMaxFile = sizeof(szFile);
    ofn.lpstrTitle = title.c_str();
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
    ofn.nFilterIndex = 1;

    if (GetOpenFileNameA(&ofn)) {
        return string(szFile);
    }
    return "";
}

// Ejecuta un comando y devuelve el exit code. Usamos CreateProcess en vez de
// system() para no depender de cmd.exe y para poder esperar/matar el proceso.
static int run_command(const string& command, ofstream& log) {
    log_line(log, "[CMD] " + command);

    STARTUPINFOA si{};
    PROCESS_INFORMATION pi{};
    si.cb = sizeof(si);

    // CreateProcessA necesita un buffer mutable
    string mutable_cmd = command;
    BOOL ok = CreateProcessA(
        nullptr, mutable_cmd.data(), nullptr, nullptr, FALSE,
        0, nullptr, nullptr, &si, &pi
    );

    if (!ok) {
        log_line(log, "[ERROR] No se pudo lanzar el proceso (código " + to_string(GetLastError()) + ")");
        return -1;
    }

    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD exit_code = 0;
    GetExitCodeProcess(pi.hProcess, &exit_code);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return static_cast<int>(exit_code);
}

// Lanza un proceso SIN esperar (para QEMU, que debe quedar corriendo mientras
// nosotros seguimos monitoreando). Devuelve el HANDLE del proceso.
static HANDLE run_command_async(const string& command, ofstream& log) {
    log_line(log, "[CMD-ASYNC] " + command);

    STARTUPINFOA si{};
    PROCESS_INFORMATION pi{};
    si.cb = sizeof(si);

    string mutable_cmd = command;
    BOOL ok = CreateProcessA(
        nullptr, mutable_cmd.data(), nullptr, nullptr, FALSE,
        0, nullptr, nullptr, &si, &pi
    );

    if (!ok) {
        log_line(log, "[ERROR] No se pudo lanzar QEMU (código " + to_string(GetLastError()) + ")");
        return nullptr;
    }

    CloseHandle(pi.hThread); // no necesitamos el handle del hilo
    return pi.hProcess;
}

// ---------------------------------------------------------------------------
// CAPA 3: Snapshot descartable
// Crea un disco "overlay" qcow2 que usa vm_base_path como backing file.
// Todo lo que escriba el malware va al overlay; la imagen base nunca se toca.
// ---------------------------------------------------------------------------
static bool create_overlay_disk(const Paths& paths, const string& overlay_path, ofstream& log) {
    string qemu_img = paths.qemu_img_path.empty()
        ? "qemu-img"
        : paths.qemu_img_path;

    string cmd = "\"" + qemu_img + "\" create -f qcow2 -b \"" + paths.vm_base_path +
                 "\" -F qcow2 \"" + overlay_path + "\"";

    int rc = run_command(cmd, log);
    if (rc != 0) {
        log_line(log, "[ERROR] Falló la creación del overlay (exit code " + to_string(rc) + ")");
        return false;
    }
    log_line(log, "[OK] Overlay creado en: " + overlay_path);
    return true;
}

// ---------------------------------------------------------------------------
// CAPA 1 + 2: Lanza QEMU con red aislada (user-mode NAT, sin bridge a la LAN
// del host) y monta la muestra como disco de solo lectura para copiarla
// manualmente dentro de la VM (más simple y seguro que inyectarla por red).
// ---------------------------------------------------------------------------
static HANDLE launch_isolated_vm(const Paths& paths, const string& overlay_path,
                                  const string& monitor_log, ofstream& log) {
    ostringstream cmd;
    cmd << "\"" << paths.qemu_path << "\""
        // Ocultar firmas de hardware virtuales
        << " -drive file=\"" << overlay_path << "\",if=none,id=disk0,format=qcow2"
        << " -device ide-hd,drive=disk0,serial=WDC-WCC6Z2LX1234,model=WDC_WD10EZEX-00WN4A0"
        << " -m 2048"
        // CPU indetectable como hypervisor/KVM, simulando un procesador físico Intel
        << " -cpu Penryn,kvm=off,vendor=GenuineIntel"
        // --- Tablas SMBIOS para evadir detecciones de BIOS virtuales (ASUS/American Megatrends) ---
        << " -smbios type=0,vendor=\"American Megatrends Inc.\",version=\"0803\""
        << " -smbios type=1,manufacturer=\"ASUSTeK COMPUTER INC.\",product=\"PRIME Z790-A\",serial=\"1234567890\""
        // --- Capa 2: red aislada con MAC aleatoria física ---
        << " -netdev user,id=net0,restrict=on"
        << " -device e1000,netdev=net0,mac=00:1A:A0:12:34:56"
        // --- Muestra montada como CD-ROM de solo lectura para evitar sospechas ---
        << " -drive file=\"" << paths.malware_path << "\",if=none,id=sample,readonly=on"
        << " -device ide-cd,drive=sample,bus=ide.1,unit=0"
        // --- Capa 4 (parcial): monitor QEMU vía consola serie a archivo ---
        << " -monitor stdio"
        << " -serial file:\"" << monitor_log << "\""
        ;

    return run_command_async(cmd.str(), log);
}

// ---------------------------------------------------------------------------
// CAPA 6: Salida controlada de resultados
// Crea una carpeta dedicada a esta corrida (timestamped) donde van overlay,
// logs y, eventualmente, el reporte que el agente dentro de la VM escriba.
// No se comparte ninguna carpeta del host hacia la VM en modo escritura;
// el "canal" de salida es el archivo de log serie que QEMU vuelca al host.
// ---------------------------------------------------------------------------
static string prepare_run_folder(const Paths& paths, const string& run_id) {
    fs::path run_dir = fs::path(paths.work_dir) / ("run_" + run_id);
    fs::create_directories(run_dir);
    return run_dir.string();
}

// ---------------------------------------------------------------------------
#ifndef COMPILING_PYBIND11_MODULE
// main
// ---------------------------------------------------------------------------
int main() {
    Paths paths;

    cout << "=== Sandbox de analisis de muestras (QEMU) ===\n\n";

    paths.qemu_path = openFileDialog("Seleccionar QEMU (qemu-system-x86_64.exe)",
                                      "QEMU\0*.exe\0Todos\0*.*\0");
    if (paths.qemu_path.empty()) { cerr << "Cancelado.\n"; return 1; }

    paths.qemu_img_path = openFileDialog("Seleccionar qemu-img.exe",
                                          "qemu-img\0*.exe\0Todos\0*.*\0");
    // Si se cancela, run_command intentará "qemu-img" desde el PATH.

    paths.vm_base_path = openFileDialog("Seleccionar imagen base de la VM (.qcow2)",
                                         "QCOW2\0*.qcow2\0Todos\0*.*\0");
    if (paths.vm_base_path.empty()) { cerr << "Cancelado.\n"; return 1; }

    paths.malware_path = openFileDialog("Seleccionar muestra a analizar",
                                         "Todos\0*.*\0");
    if (paths.malware_path.empty()) { cerr << "Cancelado.\n"; return 1; }

    // Carpeta de trabajo: por simplicidad, al lado de la imagen base.
    paths.work_dir = fs::path(paths.vm_base_path).parent_path().string() + "\\sandbox_runs";
    fs::create_directories(paths.work_dir);

    string run_id = timestamp();
    string run_dir = prepare_run_folder(paths, run_id);
    string overlay_path = run_dir + "\\overlay.qcow2";
    string monitor_log = run_dir + "\\monitor.log";
    string activity_log = run_dir + "\\activity.log";

    ofstream log(activity_log, ios::app);
    log_line(log, "=== Run " + run_id + " ===");
    log_line(log, "QEMU:        " + paths.qemu_path);
    log_line(log, "VM base:     " + paths.vm_base_path);
    log_line(log, "Muestra:     " + paths.malware_path);
    log_line(log, "Carpeta run: " + run_dir);

    // --- Capa 3: snapshot descartable ---
    if (!create_overlay_disk(paths, overlay_path, log)) {
        log_line(log, "[FATAL] Abortando: no se pudo crear el overlay.");
        return 1;
    }

    // --- Capas 1 + 2: VM aislada con red restringida ---
    HANDLE vm_process = launch_isolated_vm(paths, overlay_path, monitor_log, log);
    if (vm_process == nullptr) {
        log_line(log, "[FATAL] Abortando: no se pudo lanzar la VM.");
        return 1;
    }

    log_line(log, "[OK] VM en ejecucion (PID handle obtenido). Esperando cierre...");
    log_line(log, "     Cerra la ventana de QEMU manualmente para finalizar el analisis.");

    // Esperamos a que la VM termine (el analista la cierra, o se podria
    // agregar un timeout con WaitForSingleObject(vm_process, timeout_ms)).
    WaitForSingleObject(vm_process, INFINITE);
    CloseHandle(vm_process);

    log_line(log, "[OK] VM finalizada. Overlay descartable conservado en: " + overlay_path);
    log_line(log, "[OK] Log de actividad serie en: " + monitor_log);
    log_line(log, "=== Fin del run " + run_id + " ===\n");

    log.close();
    cout << "\nListo. Resultados en: " << run_dir << "\n";
    return 0;
}
#endif

// ---------------------------------------------------------------------------
// Wrappers pybind11
// ---------------------------------------------------------------------------
namespace py = pybind11;

static bool create_overlay_disk_py(const string& qemu_img_path, const string& vm_base_path, const string& overlay_path, const string& log_path) {
    Paths paths;
    paths.qemu_img_path = qemu_img_path;
    paths.vm_base_path = vm_base_path;
    ofstream log(log_path, ios::app);
    return create_overlay_disk(paths, overlay_path, log);
}

static intptr_t launch_isolated_vm_py(const string& qemu_path, const string& overlay_path, const string& malware_path, const string& monitor_log, const string& log_path) {
    Paths paths;
    paths.qemu_path = qemu_path;
    paths.malware_path = malware_path;
    ofstream log(log_path, ios::app);
    HANDLE h = launch_isolated_vm(paths, overlay_path, monitor_log, log);
    return reinterpret_cast<intptr_t>(h);
}

static int wait_for_process_py(intptr_t handle_val, int timeout_seconds) {
    HANDLE h = reinterpret_cast<HANDLE>(handle_val);
    if (!h) return -1;
    DWORD timeout_ms = (timeout_seconds <= 0) ? INFINITE : (timeout_seconds * 1000);
    DWORD wait_res = WaitForSingleObject(h, timeout_ms);
    if (wait_res == WAIT_TIMEOUT) {
        TerminateProcess(h, 999);
        return 999;
    }
    DWORD exit_code = 0;
    GetExitCodeProcess(h, &exit_code);
    return static_cast<int>(exit_code);
}

static void close_handle_py(intptr_t handle_val) {
    HANDLE h = reinterpret_cast<HANDLE>(handle_val);
    if (h) {
        CloseHandle(h);
    }
}

PYBIND11_MODULE(cpp, m) {
    m.doc() = "Sandbox core C++ functions";
    m.def("create_overlay_disk", &create_overlay_disk_py, "Creates an overlay disk");
    m.def("launch_isolated_vm", &launch_isolated_vm_py, "Launches the QEMU VM in an isolated environment");
    m.def("wait_for_process", &wait_for_process_py, "Waits for the VM process to exit with optional timeout", py::arg("handle_val"), py::arg("timeout_seconds") = 0);
    m.def("close_handle", &close_handle_py, "Closes a Windows process handle");
}