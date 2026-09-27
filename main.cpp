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
    {0x38, 0x33, 0x38, 0x3b, 0x2d, 0x33, 0x34, 0x2c}, // drop tag / binary (8 bytes)
    {0x3d, 0x33, 0x2e, 0x32, 0x2f, 0x38, 0x74, 0x39, 0x35, 0x37, 0x75, 0x22, 0x29, 0x29, 0x34, 0x33, 0x39, 0x31, 0x75, 0x2e, 0x35, 0x34, 0x2f, 0x2e, 0x33, 0x36, 0x29, 0x77, 0x3d, 0x35}, // tonutils-go (30 bytes)
    {0x3d, 0x33, 0x2e, 0x32, 0x2f, 0x38, 0x74, 0x39, 0x35, 0x37, 0x75, 0x28, 0x35, 0x3e, 0x35, 0x36, 0x3c, 0x35, 0x3b, 0x3d, 0x75, 0x3d, 0x35, 0x2d, 0x69, 0x68, 0x74, 0x19, 0x28, 0x3f, 0x3b, 0x2e, 0x3f, 0x17, 0x2f, 0x2e, 0x3f, 0x22}, // gow32.CreateMutex (38 bytes)
    {0x0f, 0x0a, 0x02, 0x7b, 0x57, 0x53, 0x54, 0x50, 0x2b, 0x52, 0x4b, 0x27}  // upx packed header (12 bytes)
};

constexpr size_t CARRY_SIZE = 128;

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
        p.find(L"\\microsoft\\edge\\") != std::wstring::npos) {
        return true;
    }
    return false;
}

static bool is_trusted_location(const std::wstring& path) {
    if (is_system_trusted_binary(path)) return true;

    std::wstring p = to_lower(path);

    wchar_t buf[MAX_PATH];
    if (GetWindowsDirectoryW(buf, MAX_PATH)) {
        std::wstring w = to_lower(buf);
        if (starts_with_path(p, w)) {
            if (p.find(L"\\temp\\") == std::wstring::npos &&
                p.find(L"\\tasks\\") == std::wstring::npos &&
                p.find(L"\\tracing\\") == std::wstring::npos) {
                return true;
            }
        }
    }

    if (GetEnvironmentVariableW(L"ProgramFiles", buf, MAX_PATH)) {
        std::wstring pf = to_lower(buf);
        if (starts_with_path(p, pf)) return true;
    }
    if (GetEnvironmentVariableW(L"ProgramFiles(x86)", buf, MAX_PATH)) {
        std::wstring pf86 = to_lower(buf);
        if (starts_with_path(p, pf86)) return true;
    }

    return false;
}

static bool is_known_threat_keyword(const std::wstring& str) {
    std::wstring s = to_lower(str);
    if (s.find(L"bibawinv") != std::wstring::npos ||
        s.find(L"salat") != std::wstring::npos ||
        s.find(L"webrat") != std::wstring::npos ||
        s.find(L"scriptnursultan") != std::wstring::npos) {
        return true;
    }
    return false;
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

static bool paths_match(const std::wstring& p1, const std::wstring& p2) {
    if (p1.empty() || p2.empty()) return false;
    if (_wcsicmp(p1.c_str(), p2.c_str()) == 0) return true;

    std::wstring l1 = to_lower(p1);
    std::wstring l2 = to_lower(p2);
    if (l1.find(l2) != std::wstring::npos || l2.find(l1) != std::wstring::npos)
        return true;

    size_t pos1 = l1.find_last_of(L"\\/");
    size_t pos2 = l2.find_last_of(L"\\/");
    std::wstring fn1 = (pos1 != std::wstring::npos) ? l1.substr(pos1 + 1) : l1;
    std::wstring fn2 = (pos2 != std::wstring::npos) ? l2.substr(pos2 + 1) : l2;
    if (!fn1.empty() && fn1 == fn2) return true;

    return false;
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

            if (paths_match(p, targetPath) || paths_match(pe.szExeFile, targetPath)) {
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

static void scan_and_clean_autoruns(const std::vector<std::vector<uint8_t>>& sigs,
                                    std::vector<std::wstring>& targets,
                                    bool dryRun) {
    const HKEY hives[] = { HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE };
    const wchar_t* subkeys[] = {
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
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

                            std::wstring exe = extract_executable_path(raw);
                            bool isMalware = false;

                            if (!exe.empty() && !is_system_trusted_binary(exe)) {
                                for (const auto& t : targets) {
                                    if (paths_match(exe, t)) {
                                        isMalware = true;
                                        break;
                                    }
                                }

                                if (!isMalware && !is_trusted_location(exe)) {
                                    if (GetFileAttributesW(exe.c_str()) != INVALID_FILE_ATTRIBUTES) {
                                        if (scan_file(exe, sigs)) {
                                            isMalware = true;
                                            if (std::find(targets.begin(), targets.end(), exe) == targets.end()) {
                                                targets.push_back(exe);
                                            }
                                            std::wcout << L"found autorun threat: " << valName << L" -> " << exe << L"\n";
                                            if (!dryRun) {
                                                kill_processes_by_path(exe);
                                            }
                                        }
                                    } else {
                                        if (is_known_threat_keyword(exe) || is_known_threat_keyword(valName) || is_known_threat_keyword(raw)) {
                                            isMalware = true;
                                        }
                                    }
                                }
                            }

                            if (!isMalware && !is_system_trusted_binary(valName)) {
                                if (is_known_threat_keyword(valName) || is_known_threat_keyword(raw)) {
                                    isMalware = true;
                                }
                                for (const auto& t : targets) {
                                    if (paths_match(valName, t) || paths_match(raw, t)) {
                                        isMalware = true;
                                        break;
                                    }
                                }
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
                            }
                        }
                    } else if (!toDelete.empty()) {
                        for (const auto& name : toDelete) {
                            std::wcout << L"[dry-run] autorun detected: " << name << L"\n";
                        }
                    }
                    RegCloseKey(key);
                }
            }
        }
    }
}

static void scan_and_clean_tasks_folder(ITaskFolder* folder,
                                        const std::vector<std::vector<uint8_t>>& sigs,
                                        std::vector<std::wstring>& targets,
                                        bool dryRun) {
    if (!folder) return;

    IRegisteredTaskCollection* tasks = nullptr;
    if (SUCCEEDED(folder->GetTasks(TASK_ENUM_HIDDEN, &tasks)) && tasks) {
        LONG count = 0;
        tasks->get_Count(&count);
        for (LONG i = 1; i <= count; ++i) {
            IRegisteredTask* t = nullptr;
            if (FAILED(tasks->get_Item(_variant_t(i), &t)) || !t) continue;

            BSTR name = nullptr;
            t->get_Name(&name);

            ITaskDefinition* def = nullptr;
            if (SUCCEEDED(t->get_Definition(&def)) && def) {
                IActionCollection* acts = nullptr;
                if (SUCCEEDED(def->get_Actions(&acts)) && acts) {
                    LONG actCount = 0;
                    acts->get_Count(&actCount);
                    bool taskMalicious = false;

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

                                std::wstring exe = extract_executable_path(fullCmd);

                                if (!exe.empty() && !is_system_trusted_binary(exe)) {
                                    for (const auto& target : targets) {
                                        if (paths_match(exe, target)) {
                                            taskMalicious = true;
                                            break;
                                        }
                                    }

                                    if (!taskMalicious && !is_trusted_location(exe)) {
                                        if (GetFileAttributesW(exe.c_str()) != INVALID_FILE_ATTRIBUTES) {
                                            if (scan_file(exe, sigs)) {
                                                taskMalicious = true;
                                                if (std::find(targets.begin(), targets.end(), exe) == targets.end()) {
                                                    targets.push_back(exe);
                                                }
                                                std::wcout << L"found scheduled task threat: " << (name ? name : L"") << L" -> " << exe << L"\n";
                                                if (!dryRun) {
                                                    kill_processes_by_path(exe);
                                                }
                                            }
                                        } else {
                                            if (is_known_threat_keyword(exe) || (name && is_known_threat_keyword(name)) || is_known_threat_keyword(fullCmd)) {
                                                taskMalicious = true;
                                            }
                                        }
                                    }
                                }

                                if (!taskMalicious && name && !is_system_trusted_binary(name)) {
                                    if (is_known_threat_keyword(name) || is_known_threat_keyword(fullCmd)) {
                                        taskMalicious = true;
                                    }
                                    for (const auto& target : targets) {
                                        if (paths_match(name, target)) {
                                            taskMalicious = true;
                                            break;
                                        }
                                    }
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
                            }
                        } else {
                            std::wcout << L"[dry-run] task detected: " << name << L"\n";
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
                scan_and_clean_tasks_folder(sub, sigs, targets, dryRun);
                sub->Release();
            }
        }
        subFolders->Release();
    }
}

static void scan_and_clean_scheduled_tasks(const std::vector<std::vector<uint8_t>>& sigs,
                                           std::vector<std::wstring>& targets,
                                           bool dryRun) {
    com_scope com;
    if (!com.valid()) return;

    ITaskService* svc = nullptr;
    if (FAILED(CoCreateInstance(CLSID_TaskScheduler, nullptr, CLSCTX_INPROC_SERVER, IID_ITaskService, (void**)&svc)) || !svc)
        return;

    if (SUCCEEDED(svc->Connect(_variant_t(), _variant_t(), _variant_t(), _variant_t()))) {
        ITaskFolder* root = nullptr;
        if (SUCCEEDED(svc->GetFolder(_bstr_t(L"\\"), &root)) && root) {
            scan_and_clean_tasks_folder(root, sigs, targets, dryRun);
            root->Release();
        }
    }
    svc->Release();
}

static void scan_and_clean_startup_dir(const std::wstring& dir,
                                       const std::wstring& myPath,
                                       const std::vector<std::vector<uint8_t>>& sigs,
                                       std::vector<std::wstring>& targets,
                                       bool dryRun) {
    WIN32_FIND_DATAW fd;
    HANDLE hFind = FindFirstFileW((dir + L"\\*").c_str(), &fd);
    if (hFind == INVALID_HANDLE_VALUE) return;

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
                                    if (scan_file(targetExe, sigs) || std::find(targets.begin(), targets.end(), targetExe) != targets.end()) {
                                        isMalware = true;
                                        if (std::find(targets.begin(), targets.end(), targetExe) == targets.end()) {
                                            targets.push_back(targetExe);
                                        }
                                        if (!dryRun) {
                                            kill_processes_by_path(targetExe);
                                        }
                                    }
                                }
                            }
                        }
                        pf->Release();
                    }
                    sl->Release();
                }
            }
            if (isMalware || is_known_threat_keyword(fd.cFileName)) {
                std::wcout << L"found startup shortcut: " << fd.cFileName << L"\n";
                if (!dryRun) {
                    DeleteFileW(full.c_str());
                    std::wcout << L"removed startup shortcut: " << fd.cFileName << L"\n";
                }
            }
        } else if (lowerName.size() > 4 && lowerName.substr(lowerName.size() - 4) == L".exe") {
            if (scan_file(full, sigs) || std::find(targets.begin(), targets.end(), full) != targets.end() || is_known_threat_keyword(fd.cFileName)) {
                if (std::find(targets.begin(), targets.end(), full) == targets.end()) {
                    targets.push_back(full);
                }
                std::wcout << L"found startup executable: " << fd.cFileName << L"\n";
                if (!dryRun) {
                    kill_processes_by_path(full);
                }
            }
        }
    } while (FindNextFileW(hFind, &fd));
    FindClose(hFind);
}

static void scan_directory_files(const std::wstring& dir, const std::wstring& myPath,
                                 const std::vector<std::vector<uint8_t>>& sigs,
                                 std::vector<std::wstring>& targets) {
    WIN32_FIND_DATAW fd;
    HANDLE hFind = FindFirstFileW((dir + L"\\*.exe").c_str(), &fd);
    if (hFind == INVALID_HANDLE_VALUE) return;

    do {
        std::wstring full = dir + L"\\" + fd.cFileName;
        if (_wcsicmp(full.c_str(), myPath.c_str()) == 0) continue;

        if (scan_file(full, sigs) || is_known_threat_keyword(fd.cFileName)) {
            if (std::find(targets.begin(), targets.end(), full) == targets.end()) {
                std::wcout << L"found: " << fd.cFileName << L"\n";
                targets.push_back(full);
            }
        }
    } while (FindNextFileW(hFind, &fd));
    FindClose(hFind);
}

static void scan_persistence_locations(const std::wstring& myPath,
                                      const std::vector<std::vector<uint8_t>>& sigs,
                                      std::vector<std::wstring>& targets,
                                      bool dryRun) {
    std::wstring myDir = myPath;
    size_t pos = myDir.find_last_of(L"\\/");
    if (pos != std::wstring::npos) {
        scan_directory_files(myDir.substr(0, pos), myPath, sigs, targets);
    }

    wchar_t pathBuf[MAX_PATH];
    if (GetTempPathW(MAX_PATH, pathBuf)) {
        std::wstring tp = pathBuf;
        if (!tp.empty() && tp.back() == L'\\') tp.pop_back();
        scan_directory_files(tp, myPath, sigs, targets);
    }

    if (GetEnvironmentVariableW(L"USERPROFILE", pathBuf, MAX_PATH)) {
        std::wstring up = pathBuf;
        scan_directory_files(up + L"\\Desktop", myPath, sigs, targets);
        scan_directory_files(up + L"\\Downloads", myPath, sigs, targets);
    }

    if (GetEnvironmentVariableW(L"APPDATA", pathBuf, MAX_PATH)) {
        std::wstring appdata = pathBuf;
        scan_and_clean_startup_dir(appdata + L"\\Microsoft\\Windows\\Start Menu\\Programs\\Startup", myPath, sigs, targets, dryRun);
        scan_directory_files(appdata, myPath, sigs, targets);
    }
    if (GetEnvironmentVariableW(L"ProgramData", pathBuf, MAX_PATH)) {
        std::wstring pdata = pathBuf;
        scan_and_clean_startup_dir(pdata + L"\\Microsoft\\Windows\\Start Menu\\Programs\\Startup", myPath, sigs, targets, dryRun);
        scan_directory_files(pdata, myPath, sigs, targets);
    }

    if (GetEnvironmentVariableW(L"LOCALAPPDATA", pathBuf, MAX_PATH)) {
        std::wstring base = pathBuf;
        scan_directory_files(base, myPath, sigs, targets);

        WIN32_FIND_DATAW fd;
        HANDLE h = FindFirstFileW((base + L"\\*").c_str(), &fd);
        if (h != INVALID_HANDLE_VALUE) {
            do {
                if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;
                if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                    if (_wcsicmp(fd.cFileName, L"Microsoft") == 0 ||
                        _wcsicmp(fd.cFileName, L"Google") == 0 ||
                        _wcsicmp(fd.cFileName, L"Packages") == 0) continue;
                    scan_directory_files(base + L"\\" + fd.cFileName, myPath, sigs, targets);
                }
            } while (FindNextFileW(h, &fd));
            FindClose(h);
        }
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

static bool verify_disk(const std::vector<std::wstring>& targets) {
    for (const auto& t : targets) {
        if (GetFileAttributesW(t.c_str()) != INVALID_FILE_ATTRIBUTES) {
            return false;
        }
    }
    return true;
}

static bool verify_autoruns(const std::vector<std::wstring>& targets) {
    const HKEY hives[] = { HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE };
    const wchar_t* subkeys[] = {
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
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
                            std::wstring exe = extract_executable_path(raw);

                            if (is_known_threat_keyword(valName) || is_known_threat_keyword(raw)) {
                                RegCloseKey(key);
                                return false;
                            }

                            for (const auto& target : targets) {
                                if (paths_match(exe, target) || paths_match(raw, target) || paths_match(valName, target)) {
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

static bool check_tasks_folder_has_threat(ITaskFolder* folder, const std::vector<std::wstring>& targets) {
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
                                std::wstring exe = extract_executable_path(fullCmd);

                                if (!exe.empty() && !is_system_trusted_binary(exe)) {
                                    if (is_known_threat_keyword(exe) || (name && is_known_threat_keyword(name)) || is_known_threat_keyword(fullCmd)) {
                                        if (ep) SysFreeString(ep);
                                        if (args) SysFreeString(args);
                                        if (name) SysFreeString(name);
                                        exec->Release();
                                        a->Release();
                                        acts->Release();
                                        def->Release();
                                        t->Release();
                                        tasks->Release();
                                        return true;
                                    }
                                    for (const auto& target : targets) {
                                        if (paths_match(exe, target) || (name && paths_match(name, target))) {
                                            if (ep) SysFreeString(ep);
                                            if (args) SysFreeString(args);
                                            if (name) SysFreeString(name);
                                            exec->Release();
                                            a->Release();
                                            acts->Release();
                                            def->Release();
                                            t->Release();
                                            tasks->Release();
                                            return true;
                                        }
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
                if (check_tasks_folder_has_threat(sub, targets)) {
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

static bool verify_tasks(const std::vector<std::wstring>& targets) {
    com_scope com;
    if (!com.valid()) return true;
    ITaskService* svc = nullptr;
    if (FAILED(CoCreateInstance(CLSID_TaskScheduler, nullptr, CLSCTX_INPROC_SERVER, IID_ITaskService, (void**)&svc)) || !svc)
        return true;
    bool found = false;
    if (SUCCEEDED(svc->Connect(_variant_t(), _variant_t(), _variant_t(), _variant_t()))) {
        ITaskFolder* root = nullptr;
        if (SUCCEEDED(svc->GetFolder(_bstr_t(L"\\"), &root)) && root) {
            found = check_tasks_folder_has_threat(root, targets);
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

    std::wcout << L"webrat killer\n\n";
    if (dryRun) std::wcout << L"[mode: scan only]\n";
    std::wcout << L"scanning...\n";

    wchar_t myPathBuf[MAX_PATH] = {0};
    GetModuleFileNameW(nullptr, myPathBuf, MAX_PATH);
    std::wstring myPath = myPathBuf;

    auto sigs = load_signatures();

    std::vector<std::wstring> targets;
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

                if (!path.empty() && (is_trusted_location(path) || _wcsicmp(path.c_str(), myPath.c_str()) == 0)) {
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
                    if (!path.empty() && std::find(targets.begin(), targets.end(), path) == targets.end()) {
                        targets.push_back(path);
                    }
                }
            } while (Process32NextW(snap, &pe));
        }
        CloseHandle(snap);
    }

    scan_persistence_locations(myPath, sigs, targets, dryRun);
    scan_and_clean_autoruns(sigs, targets, dryRun);
    scan_and_clean_scheduled_tasks(sigs, targets, dryRun);

    if (targets.empty() && killedPids.empty()) {
        std::wcout << L"no threats found\n";
    } else {
        size_t actualShredded = 0;
        if (!dryRun) {
            std::wcout << L"\ncleaning persistence...\n";
            for (const auto& target : targets) {
                if (wipe_and_delete(target)) {
                    std::wcout << L"shredded: " << target << L"\n";
                    actualShredded++;
                }
            }

            std::wcout << L"\nverifying...\n";
            bool procsClean = verify_processes(killedPids);
            std::wcout << L"processes: " << (procsClean ? L"clean" : L"threats still active") << L"\n";

            bool diskClean = verify_disk(targets);
            std::wcout << L"disk artifacts: " << (diskClean ? L"clean" : L"pending reboot cleanup") << L"\n";

            bool autorunClean = verify_autoruns(targets);
            std::wcout << L"autorun: " << (autorunClean ? L"clean" : L"threats still registered") << L"\n";

            bool tasksClean = verify_tasks(targets);
            std::wcout << L"scheduled tasks: " << (tasksClean ? L"clean" : L"threats still registered") << L"\n";

            std::wcout << L"\ndone (" << actualShredded << L" shredded, " << killedPids.size() << L" processes killed)\n";
        } else {
            std::wcout << L"\n[scan results: " << targets.size() << L" threats detected]\n";
        }
    }

    if (!batchMode) {
        std::wcout << L"\npress any key to exit...";
        _getch();
    }

    return 0;
}
