#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <tlhelp32.h>
#include <shlwapi.h>
#include <iostream>
#include <string>
#include <vector>
#include <filesystem>
#include <algorithm>
#include <thread>
#include <chrono>

#pragma comment(lib, "shlwapi.lib")

namespace fs = std::filesystem;

static void cI(){ SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 11); }
static void cO(){ SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 10); }
static void cE(){ SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 12); }
static void cW(){ SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 14); }
static void cD(){ SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 8);  }
static void cN(){ SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 7);  }

static fs::path exeDir() {
    wchar_t b[MAX_PATH]{};
    GetModuleFileNameW(nullptr, b, MAX_PATH);
    return fs::path(b).parent_path();
}

static std::wstring w8(const std::string& s) {
    if (s.empty()) return L"";
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    if (n <= 0) return L"";
    std::wstring o(n - 1, 0);
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, o.data(), n);
    return o;
}

static bool enablePriv() {
    HANDLE t = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &t))
        return false;
    TOKEN_PRIVILEGES tp{};
    tp.PrivilegeCount = 1;
    if (!LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME, &tp.Privileges[0].Luid)) {
        CloseHandle(t);
        return false;
    }
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    BOOL ok = AdjustTokenPrivileges(t, FALSE, &tp, sizeof(tp), nullptr, nullptr);
    DWORD e = GetLastError();
    CloseHandle(t);
    return ok && e == ERROR_SUCCESS;
}

struct PInfo { std::wstring name; DWORD pid; };

static std::vector<PInfo> allProcs() {
    std::vector<PInfo> v;
    HANDLE s = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (s == INVALID_HANDLE_VALUE) return v;
    PROCESSENTRY32W p{}; p.dwSize = sizeof(p);
    if (Process32FirstW(s, &p)) {
        do { v.push_back({ p.szExeFile, p.th32ProcessID }); } while (Process32NextW(s, &p));
    }
    CloseHandle(s);
    return v;
}

static DWORD findPid(const std::wstring& name) {
    HANDLE s = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (s == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W p{}; p.dwSize = sizeof(p);
    DWORD pid = 0;
    if (Process32FirstW(s, &p)) {
        do {
            if (_wcsicmp(p.szExeFile, name.c_str()) == 0) { pid = p.th32ProcessID; break; }
        } while (Process32NextW(s, &p));
    }
    CloseHandle(s);
    return pid;
}

static bool killPid(DWORD pid) {
    HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (!h) return false;
    BOOL ok = TerminateProcess(h, 0);
    CloseHandle(h);
    return ok;
}

static std::vector<int> parseSel(const std::string& s, int maxn) {
    std::vector<int> o;
    std::string t = s;
    std::transform(t.begin(), t.end(), t.begin(), ::tolower);
    while (!t.empty() && isspace((unsigned char)t.front())) t.erase(t.begin());
    while (!t.empty() && isspace((unsigned char)t.back())) t.pop_back();
    if (t == "all" || t == "*") {
        for (int i = 1; i <= maxn; ++i) o.push_back(i);
        return o;
    }
    std::string cur;
    for (char c : t + ",") {
        if (c == ',' || c == ' ' || c == '\t') {
            if (!cur.empty()) {
                try { int v = std::stoi(cur); if (v >= 1 && v <= maxn) o.push_back(v); } catch (...) {}
                cur.clear();
            }
        } else if (c >= '0' && c <= '9') cur += c;
    }
    std::sort(o.begin(), o.end());
    o.erase(std::unique(o.begin(), o.end()), o.end());
    return o;
}

static bool injectOne(DWORD pid, const fs::path& dll) {
    HANDLE hp = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
        FALSE, pid);
    if (!hp) return false;

    HMODULE k = GetModuleHandleW(L"kernel32.dll");
    if (!k) { CloseHandle(hp); return false; }
    auto pLL = (LPTHREAD_START_ROUTINE)GetProcAddress(k, "LoadLibraryW");
    if (!pLL) { CloseHandle(hp); return false; }

    std::wstring pw = fs::absolute(dll).wstring();
    SIZE_T bytes = (pw.size() + 1) * sizeof(wchar_t);

    LPVOID r = VirtualAllocEx(hp, nullptr, bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!r) { CloseHandle(hp); return false; }

    SIZE_T w = 0;
    if (!WriteProcessMemory(hp, r, pw.c_str(), bytes, &w) || w != bytes) {
        VirtualFreeEx(hp, r, 0, MEM_RELEASE);
        CloseHandle(hp);
        return false;
    }

    HANDLE ht = CreateRemoteThread(hp, nullptr, 0, pLL, r, 0, nullptr);
    if (!ht) {
        VirtualFreeEx(hp, r, 0, MEM_RELEASE);
        CloseHandle(hp);
        return false;
    }

    WaitForSingleObject(ht, 10000);
    DWORD ec = 0;
    GetExitCodeThread(ht, &ec);
    CloseHandle(ht);
    VirtualFreeEx(hp, r, 0, MEM_RELEASE);
    CloseHandle(hp);
    return ec != 0;
}

static void wipeDir(const fs::path& d) {
    if (!fs::exists(d)) return;
    for (auto& e : fs::directory_iterator(d)) {
        std::error_code ec;
        fs::remove_all(e.path(), ec);
    }
}

static std::vector<fs::path> dllsNextToExe() {
    std::vector<fs::path> v;
    for (auto& e : fs::directory_iterator(exeDir())) {
        if (!e.is_regular_file()) continue;
        auto x = e.path().extension().wstring();
        std::transform(x.begin(), x.end(), x.begin(), ::towlower);
        if (x == L".dll") v.push_back(e.path());
    }
    std::sort(v.begin(), v.end(), [](const fs::path& a, const fs::path& b){
        return _wcsicmp(a.filename().c_str(), b.filename().c_str()) < 0;
    });
    return v;
}

static bool launchProc(const fs::path& exe) {
    STARTUPINFOW si{}; si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    std::wstring cmd = L"\"" + exe.wstring() + L"\"";
    std::wstring cwd = exe.parent_path().wstring();
    BOOL ok = CreateProcessW(nullptr, cmd.data(), nullptr, nullptr, FALSE, 0,
                             nullptr, cwd.c_str(), &si, &pi);
    if (!ok) return false;
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return true;
}

int wmain() {
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleTitleW(L"abyx");

    cI();
    std::wcout << L"=========================================\n";
    std::wcout << L"                 a b y x\n";
    std::wcout << L"=========================================\n\n";
    cN();

    if (enablePriv()) {
        cO(); std::wcout << L"[+] SeDebugPrivilege ON\n\n"; cN();
    } else {
        cW(); std::wcout << L"[!] SeDebugPrivilege OFF\n\n"; cN();
    }

    std::string line;

    cI(); std::wcout << L"--- STEP 1: KILL APP ---\n"; cN();
    std::wcout << L"Nhap tu khoa ten app [Enter = discord]: ";
    if (!std::getline(std::cin, line)) return 0;

    std::wstring keyword = line.empty() ? L"discord" : w8(line);
    std::transform(keyword.begin(), keyword.end(), keyword.begin(), ::towlower);

    auto procs = allProcs();
    std::vector<PInfo> matched;
    for (auto& p : procs) {
        std::wstring n = p.name;
        std::transform(n.begin(), n.end(), n.begin(), ::towlower);
        if (n.find(keyword) != std::wstring::npos) matched.push_back(p);
    }

    if (matched.empty()) {
        cW(); std::wcout << L"[!] Khong co process nao khop.\n\n"; cN();
    } else {
        cO();
        std::wcout << L"\nTim thay " << matched.size() << L" process:\n";
        cN();
        for (size_t i = 0; i < matched.size(); ++i) {
            std::wcout << L"  [" << (i + 1) << L"] " << matched[i].name
                       << L"  PID=" << matched[i].pid << L"\n";
        }
        std::wcout << L"\nChon de kill (1 | 1,2 | all | Enter = bo qua): ";
        if (!std::getline(std::cin, line)) return 0;

        auto s = parseSel(line, (int)matched.size());
        if (s.empty()) {
            cD(); std::wcout << L"[~] Bo qua kill.\n\n"; cN();
        } else {
            for (int i : s) {
                if (killPid(matched[i - 1].pid)) {
                    cO();
                    std::wcout << L"  [+] Killed " << matched[i - 1].name
                               << L" (" << matched[i - 1].pid << L")\n";
                    cN();
                } else {
                    cE();
                    std::wcout << L"  [X] Kill fail " << matched[i - 1].name << L"\n";
                    cN();
                }
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(800));
            std::wcout << L"\n";
        }
    }

    cI(); std::wcout << L"--- STEP 2: SWAP MODULE ---\n"; cN();
    std::wcout << L"Nhap duong dan FILE module nguon (Enter = bo qua swap): ";
    if (!std::getline(std::cin, line)) return 0;

    fs::path moduleSrc;
    if (!line.empty()) {
        moduleSrc = fs::path(w8(line));
        if (!fs::exists(moduleSrc)) {
            cE(); std::wcout << L"[X] File khong ton tai.\n\n"; cN();
            moduleSrc.clear();
        }
    }

    if (!moduleSrc.empty()) {
        std::wcout << L"Nhap duong dan FOLDER discord_voice dich: ";
        if (!std::getline(std::cin, line)) return 0;

        if (line.empty()) {
            cW(); std::wcout << L"[!] Khong co duong dan folder. Bo qua swap.\n\n"; cN();
        } else {
            fs::path voiceDir = fs::path(w8(line));
            std::error_code ec;
            if (!fs::exists(voiceDir)) fs::create_directories(voiceDir, ec);

            cW(); std::wcout << L"  [*] Xoa noi dung cu...\n"; cN();
            wipeDir(voiceDir);
            std::this_thread::sleep_for(std::chrono::milliseconds(200));

            cW(); std::wcout << L"  [*] Copy file moi...\n"; cN();

            fs::path target = voiceDir / moduleSrc.filename();
            fs::copy_file(moduleSrc, target, fs::copy_options::overwrite_existing, ec);
            if (ec) {
                cE();
                std::wcout << L"  [X] Copy fail.\n\n"; cN();
            } else {
                cO();
                std::wcout << L"  [+] Da copy " << moduleSrc.filename().wstring()
                           << L" -> " << voiceDir.wstring() << L"\n\n";
                cN();
            }
        }
    } else {
        cD(); std::wcout << L"[~] Bo qua swap module.\n\n"; cN();
    }

    cI(); std::wcout << L"--- STEP 3: CHON DLL ---\n"; cN();
    auto dlls = dllsNextToExe();
    if (dlls.empty()) {
        cE(); std::wcout << L"[X] Khong co .dll nao canh exe.\n\n"; cN();
    } else {
        cO();
        std::wcout << L"Tim thay " << dlls.size() << L" file .dll:\n";
        cN();
        for (size_t i = 0; i < dlls.size(); ++i)
            std::wcout << L"  [" << (i + 1) << L"] " << dlls[i].filename().wstring() << L"\n";
    }

    std::vector<int> dllSel;
    if (!dlls.empty()) {
        std::wcout << L"\nChon DLL (1 | 1,2 | all): ";
        if (!std::getline(std::cin, line)) return 0;
        dllSel = parseSel(line, (int)dlls.size());
    }

    cI(); std::wcout << L"\n--- STEP 4: MO DISCORD ---\n"; cN();
    std::wcout << L"Nhap duong dan discord.exe: ";
    if (!std::getline(std::cin, line)) return 0;

    fs::path discordExe;
    if (!line.empty()) discordExe = fs::path(w8(line));

    if (discordExe.empty() || !fs::exists(discordExe)) {
        cE(); std::wcout << L"[X] Duong dan khong hop le. Thoat.\n"; cN();
        system("pause");
        return 0;
    }

    cW(); std::wcout << L"  [*] Dang mo Discord...\n"; cN();
    if (!launchProc(discordExe)) {
        cE(); std::wcout << L"  [X] Mo that bai.\n"; cN();
        system("pause");
        return 0;
    }
    cO(); std::wcout << L"  [+] Da mo.\n"; cN();

    std::this_thread::sleep_for(std::chrono::milliseconds(4000));

    cI(); std::wcout << L"\n--- STEP 5: INJECT ---\n"; cN();
    DWORD pid = findPid(discordExe.filename().wstring());
    if (pid == 0) {
        cE(); std::wcout << L"[X] Khong tim thay PID Discord.\n"; cN();
        system("pause");
        return 0;
    }

    cO(); std::wcout << L"[TARGET] " << discordExe.filename().wstring()
                     << L"  PID=" << pid << L"\n"; cN();

    for (int i : dllSel) {
        const fs::path& d = dlls[i - 1];
        cW(); std::wcout << L"  [>] " << d.filename().wstring() << L" ... "; cN();
        if (injectOne(pid, d)) {
            cO(); std::wcout << L"OK\n"; cN();
        } else {
            cE(); std::wcout << L"FAIL\n"; cN();
        }
    }

    cI();
    std::wcout << L"\n--- STEP 6: KEEP ALIVE ---\n";
    cN();
    cD();
    std::wcout << L"[~] Monitor Discord. Dong cmd de dung.\n\n";
    cN();

    std::wstring procName = discordExe.filename().wstring();

    while (true) {
        Sleep(2000);

        DWORD curPid = findPid(procName);
        if (curPid == 0) {
            cW(); std::wcout << L"[!] Discord tat. Relaunch...\n"; cN();
            if (launchProc(discordExe)) {
                Sleep(4000);
                curPid = findPid(procName);
                if (curPid != 0) {
                    for (int i : dllSel) {
                        const fs::path& d = dlls[i - 1];
                        if (injectOne(curPid, d)) {
                            cO(); std::wcout << L"  [+] Reinject " << d.filename().wstring() << L"\n"; cN();
                        } else {
                            cE(); std::wcout << L"  [X] Reinject fail " << d.filename().wstring() << L"\n"; cN();
                        }
                    }
                }
            }
        }
    }

    return 0;
}
