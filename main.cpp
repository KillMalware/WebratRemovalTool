#define _WIN32_DCOM
#include <windows.h>
#include <tlhelp32.h>
#include <initguid.h>
#include <taskschd.h>
#include <shlobj.h>
#include <comdef.h>
#include <conio.h>
#include <iostream>
#include <vector>
#include <string>
#include <algorithm>
#include <cstdint>
#include <set>

struct com_scope {
    HRESULT hr;
    com_scope() { hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED); }
    ~com_scope() { if (SUCCEEDED(hr) || hr == RPC_E_CHANGED_MODE) CoUninitialize(); }
    bool valid() const { return SUCCEEDED(hr) || hr == RPC_E_CHANGED_MODE; }
};

static const std::vector<uint8_t> SIG_STORE[] = {
    {0x37, 0x3b, 0x33, 0x34, 0x74, 0x3e, 0x3f, 0x39, 0x35, 0x3e, 0x3f, 0x1c, 0x28, 0x35, 0x37, 0x0e, 0x35, 0x34, 0x1b, 0x3e, 0x3e, 0x28, 0x3f, 0x29, 0x29}, // ton clipper (25 bytes)
    {0x37, 0x3b, 0x33, 0x34, 0x74, 0x1d, 0x3f, 0x2e, 0x1b, 0x2a, 0x2a, 0x18, 0x35, 0x2f, 0x34, 0x3e, 0x11, 0x3f, 0x23}, // appbound key (19 bytes)
    {0x37, 0x3b, 0x33, 0x34, 0x74, 0x29, 0x2e, 0x3b, 0x2e, 0x33, 0x39, 0x33, 0x34, 0x29, 0x2e, 0x3b, 0x36, 0x36}, // persistence install (18 bytes)
    {0x37, 0x3b, 0x33, 0x34, 0x74, 0x3d, 0x3f, 0x2e, 0x08, 0x3b, 0x34, 0x3e, 0x35, 0x37, 0x1c, 0x35, 0x36, 0x3e, 0x3f, 0x28, 0x29}, // getRandomFolders (21 bytes)
    {0x37, 0x3b, 0x33, 0x34, 0x74, 0x29, 0x2f, 0x29, 0x2a, 0x3f, 0x34, 0x3e, 0x0a, 0x28, 0x35, 0x39, 0x3f, 0x29, 0x29, 0x0e, 0x32, 0x28, 0x3f, 0x3b, 0x3e, 0x29}, // suspendProcessThreads (26 bytes)
    {0x3d, 0x33, 0x2e, 0x32, 0x2f, 0x38, 0x74, 0x39, 0x35, 0x37, 0x75, 0x39, 0x3b, 0x2a, 0x34, 0x29, 0x2a, 0x3b, 0x39, 0x3f, 0x32, 0x35, 0x35, 0x31, 0x75, 0x2e, 0x3b, 0x29, 0x31, 0x37, 0x3b, 0x29, 0x2e, 0x3f, 0x28}, // taskmaster (35 bytes)
    {0x3d, 0x33, 0x2e, 0x32, 0x2f, 0x38, 0x74, 0x39, 0x35, 0x37, 0x75, 0x22, 0x29, 0x29, 0x34, 0x33, 0x39, 0x31, 0x75, 0x2e, 0x35, 0x34, 0x2f, 0x2e, 0x33, 0x36, 0x29, 0x77, 0x3d, 0x35}, // tonutils-go (30 bytes)
    {0x3d, 0x33, 0x2e, 0x32, 0x2f, 0x38, 0x74, 0x39, 0x35, 0x37, 0x75, 0x28, 0x35, 0x3e, 0x35, 0x36, 0x3c, 0x35, 0x3b, 0x3d, 0x75, 0x3d, 0x35, 0x2d, 0x69, 0x68, 0x74, 0x19, 0x28, 0x3f, 0x3b, 0x2e, 0x3f, 0x17, 0x2f, 0x2e, 0x3f, 0x22}, // gow32.CreateMutex (38 bytes)
    {0x0f, 0x0a, 0x02, 0x7b, 0x57, 0x53, 0x54, 0x50, 0x2b, 0x52, 0x4b, 0x27}  // upx packed header (12 bytes)
};

constexpr size_t CARRY_SIZE = 128;

struct ThreatRecord {
    std::wstring fullPath;
    std::wstring fileName;
    std::wstring fileStem;
};

static std::vector<std::vector<uint8_t>> load_signatures() {
    std::vector<std::vector<uint8_t>> sigs;
    sigs.reserve(sizeof(SIG_STORE) / sizeof(SIG_STORE[0]));
    for (const auto& blob : SIG_STORE) {
        if (blob.size() > CARRY_SIZE) continue;
        std::vector<uint8_t> item;
        item.reserve(blob.size());
        for (uint8_t b : blob) {
            item.push_back(b ^ 0x5a);
        }
        sigs.push_back(std::move(item));
    }
    return sigs;
}

static bool is_elevated() {
    BOOL admin = FALSE;
    PSID adminGroup = nullptr;
    SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&ntAuth, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup)) {
        CheckTokenMembership(nullptr, adminGroup, &admin);
        FreeSid(adminGroup);
    }
    return admin != FALSE;
}

static bool set_privilege(const wchar_t* priv) {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
        return false;

    LUID luid{};
    if (!LookupPrivilegeValueW(nullptr, priv, &luid)) {
        CloseHandle(token);
        return false;
    }

    TOKEN_PRIVILEGES tp{};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    bool res = AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), nullptr, nullptr);
    CloseHandle(token);
    return res && (GetLastError() == ERROR_SUCCESS);
}

static std::wstring to_lower(std::wstring str) {
    std::transform(str.begin(), str.end(), str.begin(), ::towlower);
    return str;
}

static bool starts_with_path(const std::wstring& path, const std::wstring& base) {
    if (path.size() < base.size()) return false;
    if (path.compare(0, base.size(), base) != 0) return false;
    return path.size() == base.size() || path[base.size()] == L'\\';
}

static bool is_system_trusted_binary(const std::wstring& path) {
    std::wstring p = to_lower(path);
    if (p.find(L"msmpeng.exe") != std::wstring::npos ||
        p.find(L"mpdefenderservice") != std::wstring::npos ||
        p.find(L"mpdefendercore") != std::wstring::npos ||
        p.find(L"securityhealthservice") != std::wstring::npos ||
        p.find(L"onedrive.exe") != std::wstring::npos ||
        p.find(L"onedrive.sync") != std::wstring::npos ||
        p.find(L"\\windows defender\\") != std::wstring::npos ||
        p.find(L"\\microsoft\\onedrive\\") != std::wstring::npos ||
        p.find(L"\\microsoft\\edge\\") != std::wstring::npos ||
        p.find(L"explorer.exe") != std::wstring::npos ||
        p.find(L"cmd.exe") != std::wstring::npos ||
        p.find(L"powershell.exe") != std::wstring::npos ||
        p.find(L"conhost.exe") != std::wstring::npos ||
        p.find(L"taskhostw.exe") != std::wstring::npos ||
        p.find(L"svchost.exe") != std::wstring::npos ||
        p.find(L"runtimebroker.exe") != std::wstring::npos ||
        p.find(L"sihost.exe") != std::wstring::npos ||
        p.find(L"searchapp.exe") != std::wstring::npos ||
        p.find(L"startmenuexperiencehost.exe") != std::wstring::npos) {
        return true;
    }
    return false;
}

static std::wstring canonicalize_path(const std::wstring& path) {
    if (path.empty()) return L"";

    wchar_t expanded[8192];
    DWORD expLen = ExpandEnvironmentStringsW(path.c_str(), expanded, 8192);
    std::wstring s = (expLen > 0 && expLen < 8192) ? expanded : path;

    size_t start = s.find_first_not_of(L" \t\r\n\"");
    if (start == std::wstring::npos) return L"";
    size_t end = s.find_last_not_of(L" \t\r\n\"");
    s = s.substr(start, end - start + 1);

    for (auto& ch : s) {
        if (ch == L'/') ch = L'\\';
    }

    wchar_t longPath[8192];
    DWORD longLen = GetLongPathNameW(s.c_str(), longPath, 8192);
    if (longLen > 0 && longLen < 8192) {
        s = longPath;
    }

    return to_lower(s);
}

static std::wstring get_filename(const std::wstring& path) {
    std::wstring p = canonicalize_path(path);
    size_t pos = p.find_last_of(L"\\/");
    return (pos != std::wstring::npos) ? p.substr(pos + 1) : p;
}

static std::wstring get_stem(const std::wstring& path) {
    std::wstring fn = get_filename(path);
    size_t dot = fn.find_last_of(L'.');
    return (dot != std::wstring::npos) ? fn.substr(0, dot) : fn;
}

static bool is_matching_threat(const std::wstring& testStr, const std::vector<ThreatRecord>& threats) {
    if (testStr.empty() || threats.empty()) return false;
    std::wstring norm = canonicalize_path(testStr);
    std::wstring normFn = get_filename(norm);
    std::wstring normStem = get_stem(norm);
    std::wstring rawLower = to_lower(testStr);

    for (const auto& tr : threats) {
        if (!tr.fullPath.empty()) {
            if (norm == tr.fullPath) return true;
            if (rawLower.find(tr.fullPath) != std::wstring::npos) return true;
        }
        if (!tr.fileName.empty() && !is_system_trusted_binary(tr.fileName)) {
            if (normFn == tr.fileName) return true;
            if (rawLower.find(tr.fileName) != std::wstring::npos) return true;
        }
        if (!tr.fileStem.empty() && !is_system_trusted_binary(tr.fileStem)) {
            if (norm == tr.fileStem || normStem == tr.fileStem) return true;
        }
    }
    return false;
}

static bool is_volatile_orphaned_entry(const std::wstring& exePath) {
    if (exePath.empty()) return false;
    if (GetFileAttributesW(exePath.c_str()) != INVALID_FILE_ATTRIBUTES) return false;

    std::wstring p = canonicalize_path(exePath);
    if (p.empty() || is_system_trusted_binary(p)) return false;

    if (p.find(L"\\temp\\") != std::wstring::npos ||
        p.find(L"\\appdata\\") != std::wstring::npos ||
        p.find(L"\\desktop\\") != std::wstring::npos ||
        p.find(L"\\downloads\\") != std::wstring::npos) {
        return true;
    }

    wchar_t buf[MAX_PATH];
    if (GetTempPathW(MAX_PATH, buf)) {
        std::wstring tp = canonicalize_path(buf);
        if (starts_with_path(p, tp)) return true;
    }
    if (GetEnvironmentVariableW(L"APPDATA", buf, MAX_PATH)) {
        std::wstring ap = canonicalize_path(buf);
        if (starts_with_path(p, ap)) return true;
    }
    if (GetEnvironmentVariableW(L"LOCALAPPDATA", buf, MAX_PATH)) {
        std::wstring lap = canonicalize_path(buf);
        if (starts_with_path(p, lap)) return true;
    }
    if (GetEnvironmentVariableW(L"USERPROFILE", buf, MAX_PATH)) {
        std::wstring up = canonicalize_path(buf);
        if (starts_with_path(p, up)) {
            if (p.find(L"\\desktop\\") != std::wstring::npos ||
                p.find(L"\\downloads\\") != std::wstring::npos) {
                return true;
            }
        }
    }
    return false;
}

static bool add_threat(std::vector<ThreatRecord>& threats, const std::wstring& path) {
    if (path.empty() || is_system_trusted_binary(path)) return false;
    std::wstring norm = canonicalize_path(path);
    if (norm.empty()) return false;

    for (const auto& tr : threats) {
        if (tr.fullPath == norm) return false;
    }

    ThreatRecord tr;
    tr.fullPath = norm;
    tr.fileName = get_filename(norm);
    tr.fileStem = get_stem(norm);
    threats.push_back(tr);
    return true;
}

static std::wstring extract_executable_path(const std::wstring& cmd) {
    if (cmd.empty()) return L"";

    wchar_t expanded[8192];
    DWORD expLen = ExpandEnvironmentStringsW(cmd.c_str(), expanded, 8192);
    std::wstring s = (expLen > 0 && expLen < 8192) ? expanded : cmd;

    size_t start = s.find_first_not_of(L" \t\r\n");
    if (start == std::wstring::npos) return L"";
    s = s.substr(start);

    std::wstring exePath;
    if (s.front() == L'\"') {
        size_t closeQuote = s.find(L'\"', 1);
        if (closeQuote != std::wstring::npos) {
            exePath = s.substr(1, closeQuote - 1);
        } else {
            exePath = s.substr(1);
        }
    } else {
        size_t space = s.find(L' ');
        if (space == std::wstring::npos) {
            exePath = s;
        } else {
            std::wstring cand = s.substr(0, space);
            if (GetFileAttributesW(cand.c_str()) != INVALID_FILE_ATTRIBUTES) {
                exePath = cand;
            } else {
                size_t exePos = to_lower(s).find(L".exe");
                if (exePos != std::wstring::npos) {
                    exePath = s.substr(0, exePos + 4);
                } else {
                    exePath = cand;
                }
            }
        }
    }

    wchar_t longPath[8192];
    DWORD longLen = GetLongPathNameW(exePath.c_str(), longPath, 8192);
    if (longLen > 0 && longLen < 8192) {
        exePath = longPath;
    }

    return exePath;
}

static std::vector<std::wstring> extract_all_executable_paths(const std::wstring& cmd) {
    std::vector<std::wstring> results;
    std::wstring primary = extract_executable_path(cmd);
    if (!primary.empty()) results.push_back(primary);

    std::wstring lowerCmd = to_lower(cmd);
    size_t pos = 0;
    while ((pos = lowerCmd.find(L".exe", pos)) != std::wstring::npos) {
        size_t pStart = lowerCmd.rfind(L'\"', pos);
        if (pStart != std::wstring::npos && pStart < pos) {
            std::wstring cand = cmd.substr(pStart + 1, pos + 4 - (pStart + 1));
            std::wstring exp = extract_executable_path(cand);
            if (!exp.empty() && std::find(results.begin(), results.end(), exp) == results.end()) {
                results.push_back(exp);
            }
        } else {
            size_t sStart = lowerCmd.rfind(L' ', pos);
            size_t actualStart = (sStart != std::wstring::npos) ? sStart + 1 : 0;
            std::wstring cand = cmd.substr(actualStart, pos + 4 - actualStart);
            std::wstring exp = extract_executable_path(cand);
            if (!exp.empty() && std::find(results.begin(), results.end(), exp) == results.end()) {
                results.push_back(exp);
            }
        }
        pos += 4;
    }
    return results;
}

static bool has_pattern(const uint8_t* buf, size_t bufLen, const uint8_t* pat, size_t patLen) {
    if (!buf || bufLen < patLen || patLen == 0) return false;
    const uint8_t* limit = buf + bufLen - patLen + 1;
    for (const uint8_t* cur = buf; cur < limit; ++cur) {
        if (*cur == pat[0] && memcmp(cur, pat, patLen) == 0)
            return true;
    }
    return false;
}

static bool scan_file(const std::wstring& path, const std::vector<std::vector<uint8_t>>& sigs) {
    if (is_system_trusted_binary(path)) return false;

    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           nullptr, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;

    LARGE_INTEGER sz;
    if (!GetFileSizeEx(h, &sz) || sz.QuadPart == 0 || sz.QuadPart > 120 * 1024 * 1024) {
        CloseHandle(h);
        return false;
    }

    constexpr size_t BLOCK = 64 * 1024;
    std::vector<uint8_t> buffer(BLOCK + CARRY_SIZE);
    DWORD readBytes = 0;
    size_t carry = 0;

    while (ReadFile(h, buffer.data() + carry, (DWORD)BLOCK, &readBytes, nullptr) && readBytes > 0) {
        size_t total = carry + readBytes;
        for (const auto& sig : sigs) {
            if (has_pattern(buffer.data(), total, sig.data(), sig.size())) {
                CloseHandle(h);
                return true;
            }
        }
        carry = std::min(total, CARRY_SIZE);
        memmove(buffer.data(), buffer.data() + total - carry, carry);
    }

    CloseHandle(h);
    return false;
}

static bool scan_process_memory(HANDLE proc, const std::vector<std::vector<uint8_t>>& sigs) {
    MEMORY_BASIC_INFORMATION mbi{};
    uint8_t* ptr = nullptr;
    std::vector<uint8_t> buffer(64 * 1024 + CARRY_SIZE);
    size_t carry = 0;
    uint8_t* lastEnd = nullptr;

    while (VirtualQueryEx(proc, ptr, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT && !(mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS))) {
            if ((uint8_t*)mbi.BaseAddress != lastEnd) {
                carry = 0;
            }

            size_t off = 0;
            while (off < mbi.RegionSize) {
                size_t req = std::min((size_t)64 * 1024, mbi.RegionSize - off);
                SIZE_T done = 0;

                if (!ReadProcessMemory(proc, (uint8_t*)mbi.BaseAddress + off, buffer.data() + carry, req, &done) || done == 0)
                    break;

                size_t total = carry + done;
                for (const auto& sig : sigs) {
                    if (has_pattern(buffer.data(), total, sig.data(), sig.size()))
                        return true;
                }

                carry = std::min(total, CARRY_SIZE);
                memmove(buffer.data(), buffer.data() + total - carry, carry);
                off += done;
            }
            lastEnd = (uint8_t*)mbi.BaseAddress + mbi.RegionSize;
        } else {
            carry = 0;
            lastEnd = nullptr;
        }
        ptr = (uint8_t*)mbi.BaseAddress + mbi.RegionSize;
    }
    return false;
}

static void suspend_process(DWORD pid) {
    typedef LONG(NTAPI* pfnNtSuspendProcess)(HANDLE ProcessHandle);
    static auto NtSuspendProcess = (pfnNtSuspendProcess)(void*)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtSuspendProcess");

    HANDLE h = OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, pid);
    if (h) {
        if (NtSuspendProcess) {
            NtSuspendProcess(h);
        }
        CloseHandle(h);
    }

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap != INVALID_HANDLE_VALUE) {
        THREADENTRY32 te{};
        te.dwSize = sizeof(te);
        if (Thread32First(snap, &te)) {
            do {
                if (te.th32OwnerProcessID == pid) {
                    HANDLE th = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
                    if (th) {
                        SuspendThread(th);
                        CloseHandle(th);
                    }
                }
            } while (Thread32Next(snap, &te));
        }
        CloseHandle(snap);
    }
}

static void kill_process_tree(DWORD parentPid) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    std::vector<DWORD> children;
    if (Process32FirstW(snap, &pe)) {
        do {
            if (pe.th32ParentProcessID == parentPid && pe.th32ProcessID != parentPid && pe.th32ProcessID > 4) {
                children.push_back(pe.th32ProcessID);
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);

    for (DWORD cpid : children) {
        suspend_process(cpid);
        kill_process_tree(cpid);
        HANDLE child = OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, FALSE, cpid);
        if (child) {
            TerminateProcess(child, 1);
            WaitForSingleObject(child, 500);
            CloseHandle(child);
            std::wcout << L"killed child process: " << cpid << L"\n";
        }
    }
}

static void kill_processes_by_path(const std::wstring& targetPath) {
    if (targetPath.empty() || is_system_trusted_binary(targetPath)) return;
    std::wstring normTarget = canonicalize_path(targetPath);
    std::wstring targetFn = get_filename(normTarget);

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    DWORD selfPid = GetCurrentProcessId();

    if (Process32FirstW(snap, &pe)) {
        do {
            if (pe.th32ProcessID <= 4 || pe.th32ProcessID == selfPid) continue;

            HANDLE proc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
            if (!proc) continue;

            wchar_t imgPath[MAX_PATH * 2] = {0};
            DWORD sz = MAX_PATH * 2;
            std::wstring p;
            if (QueryFullProcessImageNameW(proc, 0, imgPath, &sz)) {
                p = imgPath;
            }
            CloseHandle(proc);

            std::wstring normProc = canonicalize_path(p);
            std::wstring procFn = to_lower(pe.szExeFile);

            bool matches = false;
            if (!normProc.empty() && normProc == normTarget) {
                matches = true;
            } else if (!targetFn.empty() && procFn == targetFn && !is_system_trusted_binary(procFn)) {
                matches = true;
            }

            if (matches) {
                suspend_process(pe.th32ProcessID);
                kill_process_tree(pe.th32ProcessID);
                HANDLE kproc = OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, FALSE, pe.th32ProcessID);
                if (kproc) {
                    TerminateProcess(kproc, 1);
                    WaitForSingleObject(kproc, 1000);
                    CloseHandle(kproc);
                    std::wcout << L"killed process: " << pe.szExeFile << L" (pid " << pe.th32ProcessID << L")\n";
                }
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
}

static bool wipe_and_delete(std::wstring path) {
    if (is_system_trusted_binary(path)) return false;
    if (GetFileAttributesW(path.c_str()) == INVALID_FILE_ATTRIBUTES)
        return true;

    SetFileAttributesW(path.c_str(), FILE_ATTRIBUTE_NORMAL);

    std::wstring tempDead = path + L".dead_" + std::to_wstring(GetTickCount64());
    if (MoveFileW(path.c_str(), tempDead.c_str())) {
        path = tempDead;
    }

    bool shredded = false;
    for (int retry = 0; retry < 25; ++retry) {
        HANDLE h = CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE,
                               FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                               nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h != INVALID_HANDLE_VALUE) {
            LARGE_INTEGER sz{};
            if (GetFileSizeEx(h, &sz) && sz.QuadPart > 0) {
                std::vector<uint8_t> zeroes(64 * 1024, 0);
                LONGLONG remain = std::min(sz.QuadPart, (LONGLONG)64 * 1024 * 1024);
                while (remain > 0) {
                    DWORD chunk = (DWORD)std::min((LONGLONG)zeroes.size(), remain);
                    DWORD written = 0;
                    if (!WriteFile(h, zeroes.data(), chunk, &written, nullptr) || written == 0)
                        break;
                    remain -= written;
                }
                SetFilePointer(h, 0, nullptr, FILE_BEGIN);
                SetEndOfFile(h);
                FlushFileBuffers(h);
            }
            CloseHandle(h);
            shredded = true;
            break;
        }
        Sleep(100);
    }

    for (int retry = 0; retry < 10; ++retry) {
        if (DeleteFileW(path.c_str())) return true;
        Sleep(100);
    }

    if (MoveFileExW(path.c_str(), nullptr, MOVEFILE_DELAY_UNTIL_REBOOT))
        return true;

    return shredded;
}

static size_t scan_and_clean_autoruns(const std::vector<std::vector<uint8_t>>& sigs,
                                     std::vector<ThreatRecord>& threats,
                                     bool dryRun) {
    size_t totalRemoved = 0;
    const HKEY hives[] = { HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE };
    const wchar_t* subkeys[] = {
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx",
        L"Software\\Microsoft\\Windows\\CurrentVersion\\RunServices",
        L"Software\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce",
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run"
    };
    const REGSAM views[] = { KEY_WOW64_64KEY, KEY_WOW64_32KEY };

    for (HKEY hive : hives) {
        for (const wchar_t* subkey : subkeys) {
            for (REGSAM view : views) {
                HKEY key = nullptr;
                REGSAM access = KEY_READ | (dryRun ? 0 : KEY_SET_VALUE) | view;
                if (RegOpenKeyExW(hive, subkey, 0, access, &key) == ERROR_SUCCESS) {
                    DWORD idx = 0;
                    wchar_t valName[256];
                    std::vector<BYTE> data(4096);
                    std::vector<std::wstring> toDelete;

                    while (true) {
                        DWORD valLen = 256;
                        DWORD dataLen = (DWORD)data.size();
                        DWORD type = 0;
                        LSTATUS st = RegEnumValueW(key, idx, valName, &valLen, nullptr, &type, data.data(), &dataLen);

                        if (st == ERROR_NO_MORE_ITEMS) break;
                        if (st == ERROR_MORE_DATA) {
                            data.resize(dataLen + 256);
                            continue;
                        }

                        if (st == ERROR_SUCCESS && (type == REG_SZ || type == REG_EXPAND_SZ)) {
                            size_t chars = dataLen / sizeof(wchar_t);
                            while (chars > 0 && ((wchar_t*)data.data())[chars - 1] == L'\0') chars--;
                            std::wstring raw((wchar_t*)data.data(), chars);

                            bool isMalware = false;

                            if (is_matching_threat(valName, threats)) {
                                isMalware = true;
                            }

                            auto exes = extract_all_executable_paths(raw);
                            for (const auto& exe : exes) {
                                if (exe.empty() || is_system_trusted_binary(exe)) continue;

                                if (is_matching_threat(exe, threats)) {
                                    isMalware = true;
                                    break;
                                }

                                if (GetFileAttributesW(exe.c_str()) != INVALID_FILE_ATTRIBUTES) {
                                    if (scan_file(exe, sigs)) {
                                        isMalware = true;
                                        add_threat(threats, exe);
                                        std::wcout << L"found autorun threat: " << valName << L" -> " << exe << L"\n";
                                        if (!dryRun) {
                                            kill_processes_by_path(exe);
                                        }
                                        break;
                                    }
                                } else {
                                    if (is_volatile_orphaned_entry(exe)) {
                                        isMalware = true;
                                        break;
                                    }
                                }
                            }

                            if (!isMalware && is_matching_threat(raw, threats)) {
                                isMalware = true;
                            }

                            if (isMalware) {
                                toDelete.push_back(valName);
                            }
                        }
                        idx++;
                    }

                    if (!dryRun) {
                        for (const auto& name : toDelete) {
                            if (RegDeleteValueW(key, name.c_str()) == ERROR_SUCCESS) {
                                std::wcout << L"removed autorun: " << name << L"\n";
                                totalRemoved++;
                            }
                        }
                    } else if (!toDelete.empty()) {
                        for (const auto& name : toDelete) {
                            std::wcout << L"[dry-run] autorun detected: " << name << L"\n";
                            totalRemoved++;
                        }
                    }
                    RegCloseKey(key);
                }
            }
        }
    }
    return totalRemoved;
}

static size_t scan_and_clean_tasks_folder(ITaskFolder* folder,
                                         const std::vector<std::vector<uint8_t>>& sigs,
                                         std::vector<ThreatRecord>& threats,
                                         bool dryRun) {
    if (!folder) return 0;
    size_t totalRemoved = 0;

    IRegisteredTaskCollection* tasks = nullptr;
    if (SUCCEEDED(folder->GetTasks(TASK_ENUM_HIDDEN, &tasks)) && tasks) {
        LONG count = 0;
        tasks->get_Count(&count);
        for (LONG i = 1; i <= count; ++i) {
            IRegisteredTask* t = nullptr;
            if (FAILED(tasks->get_Item(_variant_t(i), &t)) || !t) continue;

            BSTR name = nullptr;
            t->get_Name(&name);
            std::wstring taskName = name ? name : L"";

            ITaskDefinition* def = nullptr;
            if (SUCCEEDED(t->get_Definition(&def)) && def) {
                IActionCollection* acts = nullptr;
                if (SUCCEEDED(def->get_Actions(&acts)) && acts) {
                    LONG actCount = 0;
                    acts->get_Count(&actCount);
                    bool taskMalicious = false;

                    if (!taskName.empty() && is_matching_threat(taskName, threats)) {
                        taskMalicious = true;
                    }

                    for (LONG j = 1; j <= actCount && !taskMalicious; ++j) {
                        IAction* a = nullptr;
                        if (FAILED(acts->get_Item(j, &a)) || !a) continue;

                        TASK_ACTION_TYPE type;
                        a->get_Type(&type);
                        if (type == TASK_ACTION_EXEC) {
                            IExecAction* exec = nullptr;
                            if (SUCCEEDED(a->QueryInterface(IID_IExecAction, (void**)&exec)) && exec) {
                                BSTR ep = nullptr;
                                exec->get_Path(&ep);
                                BSTR args = nullptr;
                                exec->get_Arguments(&args);

                                std::wstring fullCmd = (ep ? ep : L"");
                                if (args) {
                                    fullCmd += L" ";
                                    fullCmd += args;
                                }

                                auto exes = extract_all_executable_paths(fullCmd);
                                for (const auto& exe : exes) {
                                    if (exe.empty() || is_system_trusted_binary(exe)) continue;

                                    if (is_matching_threat(exe, threats)) {
                                        taskMalicious = true;
                                        break;
                                    }

                                    if (GetFileAttributesW(exe.c_str()) != INVALID_FILE_ATTRIBUTES) {
                                        if (scan_file(exe, sigs)) {
                                            taskMalicious = true;
                                            add_threat(threats, exe);
                                            std::wcout << L"found scheduled task threat: " << taskName << L" -> " << exe << L"\n";
                                            if (!dryRun) {
                                                kill_processes_by_path(exe);
                                            }
                                            break;
                                        }
                                    } else {
                                        if (is_volatile_orphaned_entry(exe)) {
                                            taskMalicious = true;
                                            break;
                                        }
                                    }
                                }

                                if (!taskMalicious && is_matching_threat(fullCmd, threats)) {
                                    taskMalicious = true;
                                }

                                if (ep) SysFreeString(ep);
                                if (args) SysFreeString(args);
                                exec->Release();
                            }
                        }
                        a->Release();
                    }

                    if (taskMalicious && name) {
                        if (!dryRun) {
                            if (SUCCEEDED(folder->DeleteTask(name, 0))) {
                                std::wcout << L"removed task: " << name << L"\n";
                                totalRemoved++;
                            }
                        } else {
                            std::wcout << L"[dry-run] task detected: " << name << L"\n";
                            totalRemoved++;
                        }
                    }
                    acts->Release();
                }
                def->Release();
            }
            if (name) SysFreeString(name);
            t->Release();
        }
        tasks->Release();
    }

    ITaskFolderCollection* subFolders = nullptr;
    if (SUCCEEDED(folder->GetFolders(0, &subFolders)) && subFolders) {
        LONG subCount = 0;
        subFolders->get_Count(&subCount);
        for (LONG i = 1; i <= subCount; ++i) {
            ITaskFolder* sub = nullptr;
            if (SUCCEEDED(subFolders->get_Item(_variant_t(i), &sub)) && sub) {
                totalRemoved += scan_and_clean_tasks_folder(sub, sigs, threats, dryRun);
                sub->Release();
            }
        }
        subFolders->Release();
    }
    return totalRemoved;
}

static size_t scan_and_clean_scheduled_tasks(const std::vector<std::vector<uint8_t>>& sigs,
                                           std::vector<ThreatRecord>& threats,
                                           bool dryRun) {
    com_scope com;
    if (!com.valid()) return 0;

    ITaskService* svc = nullptr;
    if (FAILED(CoCreateInstance(CLSID_TaskScheduler, nullptr, CLSCTX_INPROC_SERVER, IID_ITaskService, (void**)&svc)) || !svc)
        return 0;

    size_t removed = 0;
    if (SUCCEEDED(svc->Connect(_variant_t(), _variant_t(), _variant_t(), _variant_t()))) {
        ITaskFolder* root = nullptr;
        if (SUCCEEDED(svc->GetFolder(_bstr_t(L"\\"), &root)) && root) {
            removed = scan_and_clean_tasks_folder(root, sigs, threats, dryRun);
            root->Release();
        }
    }
    svc->Release();
    return removed;
}

static size_t scan_and_clean_startup_dir(const std::wstring& dir,
                                       const std::wstring& myPath,
                                       const std::vector<std::vector<uint8_t>>& sigs,
                                       std::vector<ThreatRecord>& threats,
                                       bool dryRun) {
    if (dir.empty()) return 0;
    WIN32_FIND_DATAW fd;
    HANDLE hFind = FindFirstFileW((dir + L"\\*").c_str(), &fd);
    if (hFind == INVALID_HANDLE_VALUE) return 0;

    size_t totalRemoved = 0;
    do {
        if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;
        std::wstring full = dir + L"\\" + fd.cFileName;
        if (_wcsicmp(full.c_str(), myPath.c_str()) == 0) continue;

        std::wstring lowerName = to_lower(fd.cFileName);
        bool isMalware = false;

        if (lowerName.size() > 4 && lowerName.substr(lowerName.size() - 4) == L".lnk") {
            com_scope com;
            if (com.valid()) {
                IShellLinkW* sl = nullptr;
                if (SUCCEEDED(CoCreateInstance(CLSID_ShellLink, nullptr, CLSCTX_INPROC_SERVER, IID_IShellLinkW, (void**)&sl))) {
                    IPersistFile* pf = nullptr;
                    if (SUCCEEDED(sl->QueryInterface(IID_IPersistFile, (void**)&pf))) {
                        if (SUCCEEDED(pf->Load(full.c_str(), STGM_READ))) {
                            wchar_t targetBuf[MAX_PATH];
                            if (SUCCEEDED(sl->GetPath(targetBuf, MAX_PATH, nullptr, 0))) {
                                std::wstring targetExe = targetBuf;
                                if (!targetExe.empty()) {
                                    if (is_matching_threat(targetExe, threats)) {
                                        isMalware = true;
                                    } else if (GetFileAttributesW(targetExe.c_str()) != INVALID_FILE_ATTRIBUTES) {
                                        if (scan_file(targetExe, sigs)) {
                                            isMalware = true;
                                            add_threat(threats, targetExe);
                                            if (!dryRun) {
                                                kill_processes_by_path(targetExe);
                                            }
                                        }
                                    } else if (is_volatile_orphaned_entry(targetExe)) {
                                        isMalware = true;
                                    }
                                }
                            }
                        }
                        pf->Release();
                    }
                    sl->Release();
                }
            }
            if (!isMalware && is_matching_threat(fd.cFileName, threats)) {
                isMalware = true;
            }

            if (isMalware) {
                if (!dryRun) {
                    DeleteFileW(full.c_str());
                    std::wcout << L"removed startup shortcut: " << fd.cFileName << L"\n";
                } else {
                    std::wcout << L"[dry-run] startup shortcut detected: " << fd.cFileName << L"\n";
                }
                totalRemoved++;
            }
        } else if (lowerName.size() > 4 && lowerName.substr(lowerName.size() - 4) == L".exe") {
            if (is_matching_threat(full, threats) || is_matching_threat(fd.cFileName, threats)) {
                isMalware = true;
            } else if (scan_file(full, sigs)) {
                isMalware = true;
                add_threat(threats, full);
            }

            if (isMalware) {
                if (!dryRun) {
                    kill_processes_by_path(full);
                    wipe_and_delete(full);
                    std::wcout << L"removed startup executable: " << fd.cFileName << L"\n";
                } else {
                    std::wcout << L"[dry-run] startup executable detected: " << fd.cFileName << L"\n";
                }
                totalRemoved++;
            }
        }
    } while (FindNextFileW(hFind, &fd));
    FindClose(hFind);
    return totalRemoved;
}

static size_t scan_and_clean_all_startup_dirs(const std::wstring& myPath,
                                              const std::vector<std::vector<uint8_t>>& sigs,
                                              std::vector<ThreatRecord>& threats,
                                              bool dryRun) {
    size_t removed = 0;
    wchar_t pathBuf[MAX_PATH];

    if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_STARTUP, nullptr, 0, pathBuf))) {
        removed += scan_and_clean_startup_dir(pathBuf, myPath, sigs, threats, dryRun);
    }
    if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_COMMON_STARTUP, nullptr, 0, pathBuf))) {
        removed += scan_and_clean_startup_dir(pathBuf, myPath, sigs, threats, dryRun);
    }
    if (GetEnvironmentVariableW(L"APPDATA", pathBuf, MAX_PATH)) {
        removed += scan_and_clean_startup_dir(std::wstring(pathBuf) + L"\\Microsoft\\Windows\\Start Menu\\Programs\\Startup", myPath, sigs, threats, dryRun);
    }
    if (GetEnvironmentVariableW(L"ProgramData", pathBuf, MAX_PATH)) {
        removed += scan_and_clean_startup_dir(std::wstring(pathBuf) + L"\\Microsoft\\Windows\\Start Menu\\Programs\\Startup", myPath, sigs, threats, dryRun);
    }
    return removed;
}

static void scan_directory_recursive(const std::wstring& dir, int maxDepth,
                                     const std::wstring& myPath,
                                     const std::vector<std::vector<uint8_t>>& sigs,
                                     std::vector<ThreatRecord>& threats,
                                     bool dryRun) {
    if (dir.empty() || maxDepth < 0) return;
    WIN32_FIND_DATAW fd;
    HANDLE hFind = FindFirstFileW((dir + L"\\*").c_str(), &fd);
    if (hFind == INVALID_HANDLE_VALUE) return;

    do {
        if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;
        std::wstring full = dir + L"\\" + fd.cFileName;

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (_wcsicmp(fd.cFileName, L"Microsoft") == 0 ||
                _wcsicmp(fd.cFileName, L"Google") == 0 ||
                _wcsicmp(fd.cFileName, L"Packages") == 0 ||
                _wcsicmp(fd.cFileName, L"WindowsApps") == 0) continue;

            if (maxDepth > 0) {
                scan_directory_recursive(full, maxDepth - 1, myPath, sigs, threats, dryRun);
            }
        } else {
            if (_wcsicmp(full.c_str(), myPath.c_str()) == 0) continue;
            std::wstring lower = to_lower(fd.cFileName);
            if (lower.size() > 4 && lower.substr(lower.size() - 4) == L".exe") {
                if (scan_file(full, sigs)) {
                    if (add_threat(threats, full)) {
                        std::wcout << L"found threat binary: " << fd.cFileName << L" (" << full << L")\n";
                        if (!dryRun) {
                            kill_processes_by_path(full);
                        }
                    }
                }
            }
        }
    } while (FindNextFileW(hFind, &fd));
    FindClose(hFind);
}

static void scan_persistence_locations(const std::wstring& myPath,
                                      const std::vector<std::vector<uint8_t>>& sigs,
                                      std::vector<ThreatRecord>& threats,
                                      bool dryRun) {
    std::wstring myDir = myPath;
    size_t pos = myDir.find_last_of(L"\\/");
    if (pos != std::wstring::npos) {
        scan_directory_recursive(myDir.substr(0, pos), 0, myPath, sigs, threats, dryRun);
    }

    wchar_t pathBuf[MAX_PATH];
    if (GetTempPathW(MAX_PATH, pathBuf)) {
        std::wstring tp = pathBuf;
        if (!tp.empty() && tp.back() == L'\\') tp.pop_back();
        scan_directory_recursive(tp, 1, myPath, sigs, threats, dryRun);
    }

    if (GetEnvironmentVariableW(L"USERPROFILE", pathBuf, MAX_PATH)) {
        std::wstring up = pathBuf;
        scan_directory_recursive(up + L"\\Desktop", 1, myPath, sigs, threats, dryRun);
        scan_directory_recursive(up + L"\\Downloads", 1, myPath, sigs, threats, dryRun);
    }

    if (GetEnvironmentVariableW(L"APPDATA", pathBuf, MAX_PATH)) {
        std::wstring appdata = pathBuf;
        scan_directory_recursive(appdata, 2, myPath, sigs, threats, dryRun);
    }

    if (GetEnvironmentVariableW(L"ProgramData", pathBuf, MAX_PATH)) {
        std::wstring pdata = pathBuf;
        scan_directory_recursive(pdata, 2, myPath, sigs, threats, dryRun);
    }

    if (GetEnvironmentVariableW(L"LOCALAPPDATA", pathBuf, MAX_PATH)) {
        std::wstring base = pathBuf;
        scan_directory_recursive(base, 2, myPath, sigs, threats, dryRun);
    }

    if (GetEnvironmentVariableW(L"ProgramFiles", pathBuf, MAX_PATH)) {
        std::wstring pf = pathBuf;
        scan_directory_recursive(pf, 2, myPath, sigs, threats, dryRun);
    }

    if (GetEnvironmentVariableW(L"ProgramFiles(x86)", pathBuf, MAX_PATH)) {
        std::wstring pf86 = pathBuf;
        scan_directory_recursive(pf86, 2, myPath, sigs, threats, dryRun);
    }
}

static bool remediate_system_settings(bool dryRun) {
    bool remediated = false;

    HKEY hKey = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
                      0, KEY_READ | (dryRun ? 0 : KEY_SET_VALUE) | KEY_WOW64_64KEY, &hKey) == ERROR_SUCCESS) {
        DWORD enableLua = 0;
        DWORD sz = sizeof(enableLua);
        DWORD type = REG_DWORD;
        if (RegQueryValueExW(hKey, L"EnableLUA", nullptr, &type, (LPBYTE)&enableLua, &sz) == ERROR_SUCCESS) {
            if (enableLua == 0) {
                if (!dryRun) {
                    enableLua = 1;
                    if (RegSetValueExW(hKey, L"EnableLUA", 0, REG_DWORD, (const BYTE*)&enableLua, sizeof(enableLua)) == ERROR_SUCCESS) {
                        std::wcout << L"restored UAC policy (EnableLUA = 1)\n";
                    }
                } else {
                    std::wcout << L"[dry-run] disabled UAC policy detected (EnableLUA = 0)\n";
                }
                remediated = true;
            }
        }
        RegCloseKey(hKey);
    }

    if (!dryRun) {
        std::vector<std::wstring> tempPaths;
        wchar_t tempBuf[MAX_PATH];
        if (GetTempPathW(MAX_PATH, tempBuf)) {
            std::wstring tp = tempBuf;
            if (!tp.empty() && tp.back() != L'\\') tp += L'\\';
            tempPaths.push_back(tp);
        }
        if (GetEnvironmentVariableW(L"LOCALAPPDATA", tempBuf, MAX_PATH)) {
            tempPaths.push_back(std::wstring(tempBuf) + L"\\Temp\\");
        }
        if (GetEnvironmentVariableW(L"USERPROFILE", tempBuf, MAX_PATH)) {
            tempPaths.push_back(std::wstring(tempBuf) + L"\\AppData\\Local\\Temp\\");
        }
        tempPaths.push_back(L"C:\\Windows\\Temp\\");

        const wchar_t* auxFiles[] = { L"7z.dll", L"7z.exe", L"MSTSCLib.dll", L"AxMSTSCLib.dll", L"ffmpeg.exe" };
        for (const auto& tp : tempPaths) {
            for (const auto* af : auxFiles) {
                std::wstring fp = tp + af;
                if (GetFileAttributesW(fp.c_str()) != INVALID_FILE_ATTRIBUTES) {
                    DeleteFileW(fp.c_str());
                    remediated = true;
                }
            }
        }
    }

    return remediated;
}

static void restore_recovery_environment() {
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi{};
    wchar_t cmd[] = L"reagentc.exe /enable";
    if (CreateProcessW(nullptr, cmd, nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, 5000);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        std::wcout << L"restored Windows Recovery Environment (reagentc /enable)\n";
    }
}

static bool verify_processes(const std::vector<DWORD>& killedPids) {
    if (killedPids.empty()) return true;
    for (DWORD kpid : killedPids) {
        HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, kpid);
        if (h) {
            DWORD exitCode = 0;
            if (GetExitCodeProcess(h, &exitCode) && exitCode == STILL_ACTIVE) {
                CloseHandle(h);
                return false;
            }
            CloseHandle(h);
        }
    }
    return true;
}

static bool verify_disk(const std::vector<ThreatRecord>& threats) {
    for (const auto& tr : threats) {
        if (!tr.fullPath.empty() && GetFileAttributesW(tr.fullPath.c_str()) != INVALID_FILE_ATTRIBUTES) {
            return false;
        }
    }
    return true;
}

static bool verify_autoruns(const std::vector<ThreatRecord>& threats) {
    const HKEY hives[] = { HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE };
    const wchar_t* subkeys[] = {
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx",
        L"Software\\Microsoft\\Windows\\CurrentVersion\\RunServices",
        L"Software\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce",
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run"
    };
    const REGSAM views[] = { KEY_WOW64_64KEY, KEY_WOW64_32KEY };

    for (HKEY hive : hives) {
        for (const wchar_t* subkey : subkeys) {
            for (REGSAM view : views) {
                HKEY key = nullptr;
                if (RegOpenKeyExW(hive, subkey, 0, KEY_READ | view, &key) == ERROR_SUCCESS) {
                    DWORD idx = 0;
                    wchar_t valName[256];
                    std::vector<BYTE> data(4096);

                    while (true) {
                        DWORD valLen = 256;
                        DWORD dataLen = (DWORD)data.size();
                        DWORD type = 0;
                        LSTATUS st = RegEnumValueW(key, idx, valName, &valLen, nullptr, &type, data.data(), &dataLen);
                        if (st == ERROR_NO_MORE_ITEMS) break;
                        if (st == ERROR_MORE_DATA) {
                            data.resize(dataLen + 256);
                            continue;
                        }
                        if (st == ERROR_SUCCESS && (type == REG_SZ || type == REG_EXPAND_SZ)) {
                            size_t chars = dataLen / sizeof(wchar_t);
                            while (chars > 0 && ((wchar_t*)data.data())[chars - 1] == L'\0') chars--;
                            std::wstring raw((wchar_t*)data.data(), chars);

                            if (is_matching_threat(valName, threats) || is_matching_threat(raw, threats)) {
                                RegCloseKey(key);
                                return false;
                            }
                            auto exes = extract_all_executable_paths(raw);
                            for (const auto& exe : exes) {
                                if (is_matching_threat(exe, threats)) {
                                    RegCloseKey(key);
                                    return false;
                                }
                            }
                        }
                        idx++;
                    }
                    RegCloseKey(key);
                }
            }
        }
    }
    return true;
}

static bool check_tasks_folder_has_threat(ITaskFolder* folder, const std::vector<ThreatRecord>& threats) {
    if (!folder) return false;
    IRegisteredTaskCollection* tasks = nullptr;
    if (SUCCEEDED(folder->GetTasks(TASK_ENUM_HIDDEN, &tasks)) && tasks) {
        LONG count = 0;
        tasks->get_Count(&count);
        for (LONG i = 1; i <= count; ++i) {
            IRegisteredTask* t = nullptr;
            if (FAILED(tasks->get_Item(_variant_t(i), &t)) || !t) continue;
            BSTR name = nullptr;
            t->get_Name(&name);
            std::wstring taskName = name ? name : L"";

            if (!taskName.empty() && is_matching_threat(taskName, threats)) {
                if (name) SysFreeString(name);
                t->Release();
                tasks->Release();
                return true;
            }

            ITaskDefinition* def = nullptr;
            if (SUCCEEDED(t->get_Definition(&def)) && def) {
                IActionCollection* acts = nullptr;
                if (SUCCEEDED(def->get_Actions(&acts)) && acts) {
                    LONG actCount = 0;
                    acts->get_Count(&actCount);
                    for (LONG j = 1; j <= actCount; ++j) {
                        IAction* a = nullptr;
                        if (FAILED(acts->get_Item(j, &a)) || !a) continue;
                        TASK_ACTION_TYPE type;
                        a->get_Type(&type);
                        if (type == TASK_ACTION_EXEC) {
                            IExecAction* exec = nullptr;
                            if (SUCCEEDED(a->QueryInterface(IID_IExecAction, (void**)&exec)) && exec) {
                                BSTR ep = nullptr;
                                exec->get_Path(&ep);
                                BSTR args = nullptr;
                                exec->get_Arguments(&args);

                                std::wstring fullCmd = (ep ? ep : L"");
                                if (args) { fullCmd += L" "; fullCmd += args; }

                                if (is_matching_threat(fullCmd, threats)) {
                                    if (ep) SysFreeString(ep);
                                    if (args) SysFreeString(args);
                                    exec->Release();
                                    a->Release();
                                    acts->Release();
                                    def->Release();
                                    if (name) SysFreeString(name);
                                    t->Release();
                                    tasks->Release();
                                    return true;
                                }

                                auto exes = extract_all_executable_paths(fullCmd);
                                for (const auto& exe : exes) {
                                    if (is_matching_threat(exe, threats)) {
                                        if (ep) SysFreeString(ep);
                                        if (args) SysFreeString(args);
                                        exec->Release();
                                        a->Release();
                                        acts->Release();
                                        def->Release();
                                        if (name) SysFreeString(name);
                                        t->Release();
                                        tasks->Release();
                                        return true;
                                    }
                                }

                                if (ep) SysFreeString(ep);
                                if (args) SysFreeString(args);
                                exec->Release();
                            }
                        }
                        a->Release();
                    }
                    acts->Release();
                }
                def->Release();
            }
            if (name) SysFreeString(name);
            t->Release();
        }
        tasks->Release();
    }

    ITaskFolderCollection* subFolders = nullptr;
    if (SUCCEEDED(folder->GetFolders(0, &subFolders)) && subFolders) {
        LONG subCount = 0;
        subFolders->get_Count(&subCount);
        for (LONG i = 1; i <= subCount; ++i) {
            ITaskFolder* sub = nullptr;
            if (SUCCEEDED(subFolders->get_Item(_variant_t(i), &sub)) && sub) {
                if (check_tasks_folder_has_threat(sub, threats)) {
                    sub->Release();
                    subFolders->Release();
                    return true;
                }
                sub->Release();
            }
        }
        subFolders->Release();
    }
    return false;
}

static bool verify_tasks(const std::vector<ThreatRecord>& threats) {
    com_scope com;
    if (!com.valid()) return true;
    ITaskService* svc = nullptr;
    if (FAILED(CoCreateInstance(CLSID_TaskScheduler, nullptr, CLSCTX_INPROC_SERVER, IID_ITaskService, (void**)&svc)) || !svc)
        return true;
    bool found = false;
    if (SUCCEEDED(svc->Connect(_variant_t(), _variant_t(), _variant_t(), _variant_t()))) {
        ITaskFolder* root = nullptr;
        if (SUCCEEDED(svc->GetFolder(_bstr_t(L"\\"), &root)) && root) {
            found = check_tasks_folder_has_threat(root, threats);
            root->Release();
        }
    }
    svc->Release();
    return !found;
}

int wmain(int argc, wchar_t* argv[]) {
    if (!is_elevated()) {
        std::wcout << L"[-] Warning: not running as Administrator. Some processes or keys may be inaccessible.\n\n";
    }
    set_privilege(L"SeDebugPrivilege");

    bool batchMode = false;
    bool dryRun = false;
    for (int i = 1; i < argc; ++i) {
        std::wstring arg = argv[i];
        if (arg == L"-b" || arg == L"--batch") batchMode = true;
        if (arg == L"-s" || arg == L"--scan" || arg == L"-n" || arg == L"--dry-run") dryRun = true;
    }

    std::wcout << L"WebratRemovalTool\n\n";
    if (dryRun) std::wcout << L"[mode: scan only]\n";
    std::wcout << L"scanning...\n";

    wchar_t myPathBuf[MAX_PATH] = {0};
    GetModuleFileNameW(nullptr, myPathBuf, MAX_PATH);
    std::wstring myPath = myPathBuf;

    auto sigs = load_signatures();

    std::vector<ThreatRecord> threats;
    std::vector<DWORD> killedPids;
    DWORD selfPid = GetCurrentProcessId();

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe{};
        pe.dwSize = sizeof(pe);

        if (Process32FirstW(snap, &pe)) {
            do {
                if (pe.th32ProcessID <= 4 || pe.th32ProcessID == selfPid)
                    continue;

                std::wstring path;
                HANDLE qproc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
                if (qproc) {
                    wchar_t imgPath[MAX_PATH * 2] = {0};
                    DWORD sz = MAX_PATH * 2;
                    if (QueryFullProcessImageNameW(qproc, 0, imgPath, &sz)) {
                        path = imgPath;
                    }
                    CloseHandle(qproc);
                }

                if (!path.empty() && (is_system_trusted_binary(path) || _wcsicmp(path.c_str(), myPath.c_str()) == 0)) {
                    continue;
                }

                bool match = false;
                if (!path.empty()) {
                    match = scan_file(path, sigs);
                }

                if (!match) {
                    HANDLE vmProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe.th32ProcessID);
                    if (vmProc) {
                        match = scan_process_memory(vmProc, sigs);
                        CloseHandle(vmProc);
                    }
                }

                if (match) {
                    std::wcout << L"found: " << pe.szExeFile << L" (pid " << pe.th32ProcessID << L")\n";

                    if (!dryRun) {
                        suspend_process(pe.th32ProcessID);
                        kill_process_tree(pe.th32ProcessID);

                        HANDLE kproc = OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, FALSE, pe.th32ProcessID);
                        if (kproc) {
                            if (TerminateProcess(kproc, 1)) {
                                WaitForSingleObject(kproc, 1000);
                                std::wcout << L"killed\n";
                            }
                            CloseHandle(kproc);
                        }
                        killedPids.push_back(pe.th32ProcessID);
                    }
                    if (!path.empty()) {
                        add_threat(threats, path);
                    }
                }
            } while (Process32NextW(snap, &pe));
        }
        CloseHandle(snap);
    }

    scan_persistence_locations(myPath, sigs, threats, dryRun);
    size_t autorunsCleaned = scan_and_clean_autoruns(sigs, threats, dryRun);
    size_t tasksCleaned = scan_and_clean_scheduled_tasks(sigs, threats, dryRun);
    size_t shortcutsCleaned = scan_and_clean_all_startup_dirs(myPath, sigs, threats, dryRun);

    bool sysRemediated = false;
    if (!dryRun) {
        sysRemediated = remediate_system_settings(dryRun);
    }

    size_t totalThreats = threats.size() + killedPids.size() + autorunsCleaned + tasksCleaned + shortcutsCleaned + (sysRemediated ? 1 : 0);

    if (totalThreats == 0) {
        std::wcout << L"no threats found\n";
    } else {
        size_t actualShredded = 0;
        if (!dryRun) {
            std::wcout << L"\ncleaning persistence...\n";
            for (const auto& tr : threats) {
                if (wipe_and_delete(tr.fullPath)) {
                    std::wcout << L"shredded: " << tr.fullPath << L"\n";
                    actualShredded++;
                }
            }

            // Pass 2: multi-pass verification to eliminate race conditions
            scan_and_clean_autoruns(sigs, threats, dryRun);
            scan_and_clean_scheduled_tasks(sigs, threats, dryRun);
            scan_and_clean_all_startup_dirs(myPath, sigs, threats, dryRun);
            remediate_system_settings(dryRun);
            restore_recovery_environment();

            std::wcout << L"\nverifying...\n";
            bool procsClean = verify_processes(killedPids);
            std::wcout << L"processes: " << (procsClean ? L"clean" : L"threats still active") << L"\n";

            bool diskClean = verify_disk(threats);
            std::wcout << L"disk artifacts: " << (diskClean ? L"clean" : L"pending reboot cleanup") << L"\n";

            bool autorunClean = verify_autoruns(threats);
            std::wcout << L"autorun: " << (autorunClean ? L"clean" : L"threats still registered") << L"\n";

            bool tasksClean = verify_tasks(threats);
            std::wcout << L"scheduled tasks: " << (tasksClean ? L"clean" : L"threats still registered") << L"\n";

            std::wcout << L"\ndone (" << actualShredded << L" shredded, " << killedPids.size() << L" processes killed)\n";
        } else {
            std::wcout << L"\n[scan results: " << totalThreats << L" threats detected]\n";
        }
    }

    if (!batchMode) {
        std::wcout << L"\npress any key to exit...";
        _getch();
    }

    return 0;
}
