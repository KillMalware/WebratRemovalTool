#define _WIN32_DCOM
#include <windows.h>
#include <tlhelp32.h>
#include <initguid.h>
#include <taskschd.h>
#include <comdef.h>
#include <conio.h>
#include <iostream>
#include <vector>
#include <string>
#include <algorithm>
#include <cstdint>

struct com_scope {
    HRESULT hr;
    com_scope() { hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED); }
    ~com_scope() { if (SUCCEEDED(hr) || hr == RPC_E_CHANGED_MODE) CoUninitialize(); }
    bool valid() const { return SUCCEEDED(hr) || hr == RPC_E_CHANGED_MODE; }
};

static const std::vector<uint8_t> SIG_STORE[] = {
    {0x37, 0x3b, 0x33, 0x34, 0x74, 0x3e, 0x3f, 0x39, 0x35, 0x3e, 0x3f, 0x1c, 0x28, 0x35, 0x37, 0x0e, 0x35, 0x34, 0x1b, 0x3e, 0x3e, 0x28, 0x3f, 0x29, 0x29}, // ton clipper
    {0x37, 0x3b, 0x33, 0x34, 0x74, 0x1d, 0x3f, 0x2e, 0x1b, 0x2a, 0x2a, 0x18, 0x35, 0x2f, 0x34, 0x3e, 0x11, 0x3f, 0x23}, // appbound key
    {0x37, 0x3b, 0x33, 0x34, 0x74, 0x29, 0x2e, 0x3b, 0x2e, 0x33, 0x39, 0x33, 0x34, 0x29, 0x2e, 0x3b, 0x36, 0x36}, // persistence install
    {0x38, 0x33, 0x38, 0x3b, 0x2d, 0x33, 0x34, 0x2c}, // drop tag
    {0xff, 0xfd, 0xff, 0xff}, // c2 config header
    {0xe3, 0x23, 0x6d, 0xc4}, // tea decryptor
    {0x0f, 0x0a, 0x02, 0x7b, 0x57, 0x53, 0x54, 0x50, 0x2b, 0x52, 0x4b, 0x27}  // upx packed header
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

static bool starts_with_path(const std::wstring& path, const std::wstring& base) {
    if (path.size() < base.size()) return false;
    if (path.compare(0, base.size(), base) != 0) return false;
    return path.size() == base.size() || path[base.size()] == L'\\';
}

static bool is_trusted_location(const std::wstring& path) {
    std::wstring p = path;
    std::transform(p.begin(), p.end(), p.begin(), ::towlower);

    static const wchar_t* WRITABLE[] = {
        L"\\temp\\", L"\\tmp\\", L"\\tasks\\", L"\\tracing\\", L"\\users\\"
    };
    for (const auto* d : WRITABLE) {
        if (p.find(d) != std::wstring::npos) return false;
    }

    wchar_t buf[MAX_PATH];
    if (GetWindowsDirectoryW(buf, MAX_PATH)) {
        std::wstring w = buf;
        std::transform(w.begin(), w.end(), w.begin(), ::towlower);
        if (starts_with_path(p, w)) return true;
    }
    if (GetEnvironmentVariableW(L"ProgramFiles", buf, MAX_PATH)) {
        std::wstring pf = buf;
        std::transform(pf.begin(), pf.end(), pf.begin(), ::towlower);
        if (starts_with_path(p, pf)) return true;
    }
    if (GetEnvironmentVariableW(L"ProgramFiles(x86)", buf, MAX_PATH)) {
        std::wstring pf86 = buf;
        std::transform(pf86.begin(), pf86.end(), pf86.begin(), ::towlower);
        if (starts_with_path(p, pf86)) return true;
    }

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
    size_t totalScanned = 0;
    constexpr size_t MAX_PROC_SCAN = 64 * 1024 * 1024;
    size_t carry = 0;
    uint8_t* lastEnd = nullptr;

    while (totalScanned < MAX_PROC_SCAN && VirtualQueryEx(proc, ptr, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT && !(mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS))) {
            if ((uint8_t*)mbi.BaseAddress != lastEnd) {
                carry = 0;
            }

            size_t off = 0;
            while (off < mbi.RegionSize && totalScanned < MAX_PROC_SCAN) {
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
                totalScanned += done;
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

static bool wipe_and_delete(const std::wstring& path) {
    SetFileAttributesW(path.c_str(), FILE_ATTRIBUTE_NORMAL);

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
    }

    if (DeleteFileW(path.c_str()))
        return true;

    return MoveFileExW(path.c_str(), nullptr, MOVEFILE_DELAY_UNTIL_REBOOT) != 0;
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
        kill_process_tree(cpid);
        HANDLE child = OpenProcess(PROCESS_TERMINATE, FALSE, cpid);
        if (child) {
            TerminateProcess(child, 1);
            CloseHandle(child);
            std::wcout << L"killed child process: " << cpid << L"\n";
        }
    }
}

static void clean_autoruns(const std::vector<std::wstring>& targets) {
    if (targets.empty()) return;

    const HKEY hives[] = { HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE };
    const wchar_t* subkeys[] = {
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"
    };
    const REGSAM views[] = { KEY_WOW64_64KEY, KEY_WOW64_32KEY };

    for (HKEY hive : hives) {
        for (const wchar_t* subkey : subkeys) {
            for (REGSAM view : views) {
                HKEY key = nullptr;
                if (RegOpenKeyExW(hive, subkey, 0, KEY_READ | KEY_SET_VALUE | view, &key) == ERROR_SUCCESS) {
                    DWORD idx = 0;
                    wchar_t valName[256];
                    std::vector<BYTE> data(4096);
                    std::vector<std::wstring> toDelete;

                    while (true) {
                        DWORD valLen = 256;
                        DWORD dataLen = (DWORD)data.size();
                        DWORD type = 0;
                        LSTATUS st = RegEnumValueW(key, idx, valName, &valLen, nullptr, &type, data.data(), &dataLen);

                        if (st == ERROR_NO_MORE_ITEMS)
                            break;

                        if (st == ERROR_MORE_DATA) {
                            data.resize(dataLen + 256);
                            continue;
                        }

                        if (st == ERROR_SUCCESS && (type == REG_SZ || type == REG_EXPAND_SZ)) {
                            size_t chars = dataLen / sizeof(wchar_t);
                            while (chars > 0 && ((wchar_t*)data.data())[chars - 1] == L'\0')
                                chars--;

                            std::wstring raw((wchar_t*)data.data(), chars);
                            std::transform(raw.begin(), raw.end(), raw.begin(), ::towlower);

                            for (const auto& target : targets) {
                                std::wstring tLower = target;
                                std::transform(tLower.begin(), tLower.end(), tLower.begin(), ::towlower);

                                if (!tLower.empty() && raw.find(tLower) != std::wstring::npos) {
                                    toDelete.push_back(valName);
                                    break;
                                }
                            }
                        }
                        idx++;
                    }

                    for (const auto& name : toDelete) {
                        if (RegDeleteValueW(key, name.c_str()) == ERROR_SUCCESS) {
                            std::wcout << L"removed autorun: " << name << L"\n";
                        }
                    }
                    RegCloseKey(key);
                }
            }
        }
    }
}

static void clean_tasks_in_folder(ITaskFolder* folder, const std::vector<std::wstring>& targets) {
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
                    bool taskRemoved = false;

                    for (LONG j = 1; j <= actCount && !taskRemoved; ++j) {
                        IAction* a = nullptr;
                        if (FAILED(acts->get_Item(j, &a)) || !a) continue;

                        TASK_ACTION_TYPE type;
                        a->get_Type(&type);
                        if (type == TASK_ACTION_EXEC) {
                            IExecAction* exec = nullptr;
                            if (SUCCEEDED(a->QueryInterface(IID_IExecAction, (void**)&exec)) && exec) {
                                BSTR execPath = nullptr;
                                exec->get_Path(&execPath);
                                if (execPath) {
                                    std::wstring ep = execPath;
                                    std::transform(ep.begin(), ep.end(), ep.begin(), ::towlower);
                                    for (const auto& target : targets) {
                                        std::wstring tLower = target;
                                        std::transform(tLower.begin(), tLower.end(), tLower.begin(), ::towlower);
                                        if (!tLower.empty() && ep.find(tLower) != std::wstring::npos) {
                                            if (SUCCEEDED(folder->DeleteTask(name, 0))) {
                                                std::wcout << L"removed task: " << (name ? name : L"") << L"\n";
                                                taskRemoved = true;
                                            }
                                            break;
                                        }
                                    }
                                    SysFreeString(execPath);
                                }
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
                BSTR folderName = nullptr;
                sub->get_Name(&folderName);
                if (!folderName || _wcsicmp(folderName, L"Microsoft") != 0) {
                    clean_tasks_in_folder(sub, targets);
                }
                if (folderName) SysFreeString(folderName);
                sub->Release();
            }
        }
        subFolders->Release();
    }
}

static void clean_scheduled_tasks(const std::vector<std::wstring>& targets) {
    if (targets.empty()) return;

    com_scope com;
    if (!com.valid()) return;

    ITaskService* svc = nullptr;
    HRESULT hr = CoCreateInstance(CLSID_TaskScheduler, nullptr, CLSCTX_INPROC_SERVER, IID_ITaskService, (void**)&svc);
    if (FAILED(hr) || !svc) return;

    hr = svc->Connect(_variant_t(), _variant_t(), _variant_t(), _variant_t());
    if (SUCCEEDED(hr)) {
        ITaskFolder* root = nullptr;
        hr = svc->GetFolder(_bstr_t(L"\\"), &root);
        if (SUCCEEDED(hr) && root) {
            clean_tasks_in_folder(root, targets);
            root->Release();
        }
    }
    svc->Release();
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

        if (scan_file(full, sigs)) {
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
                                      std::vector<std::wstring>& targets) {
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

    if (GetEnvironmentVariableW(L"APPDATA", pathBuf, MAX_PATH)) {
        scan_directory_files(std::wstring(pathBuf) + L"\\Microsoft\\Windows\\Start Menu\\Programs\\Startup", myPath, sigs, targets);
    }
    if (GetEnvironmentVariableW(L"ProgramData", pathBuf, MAX_PATH)) {
        scan_directory_files(std::wstring(pathBuf) + L"\\Microsoft\\Windows\\Start Menu\\Programs\\Startup", myPath, sigs, targets);
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
        L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"
    };
    const REGSAM views[] = { KEY_WOW64_64KEY, KEY_WOW64_32KEY };

    for (HKEY hive : hives) {
        for (const wchar_t* subkey : subkeys) {
            for (REGSAM view : views) {
                HKEY key = nullptr;
                if (RegOpenKeyExW(hive, subkey, 0, KEY_READ | view, &key) == ERROR_SUCCESS) {
                    DWORD idx = 0;
                    wchar_t valName[256];
                    std::vector<BYTE> data(2048);

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
                            std::transform(raw.begin(), raw.end(), raw.begin(), ::towlower);

                            for (const auto& target : targets) {
                                std::wstring tLower = target;
                                std::transform(tLower.begin(), tLower.end(), tLower.begin(), ::towlower);
                                if (!tLower.empty() && raw.find(tLower) != std::wstring::npos) {
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

static bool check_tasks_active(ITaskFolder* folder, const std::vector<std::wstring>& targets) {
    if (!folder) return false;
    IRegisteredTaskCollection* tasks = nullptr;
    if (SUCCEEDED(folder->GetTasks(TASK_ENUM_HIDDEN, &tasks)) && tasks) {
        LONG count = 0;
        tasks->get_Count(&count);
        for (LONG i = 1; i <= count; ++i) {
            IRegisteredTask* t = nullptr;
            if (FAILED(tasks->get_Item(_variant_t(i), &t)) || !t) continue;
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
                                if (ep) {
                                    std::wstring p = ep;
                                    std::transform(p.begin(), p.end(), p.begin(), ::towlower);
                                    for (const auto& target : targets) {
                                        std::wstring tl = target;
                                        std::transform(tl.begin(), tl.end(), tl.begin(), ::towlower);
                                        if (!tl.empty() && p.find(tl) != std::wstring::npos) {
                                            SysFreeString(ep);
                                            exec->Release();
                                            a->Release();
                                            acts->Release();
                                            def->Release();
                                            t->Release();
                                            tasks->Release();
                                            return true;
                                        }
                                    }
                                    SysFreeString(ep);
                                }
                                exec->Release();
                            }
                        }
                        a->Release();
                    }
                    acts->Release();
                }
                def->Release();
            }
            t->Release();
        }
        tasks->Release();
    }
    return false;
}

static bool verify_tasks(const std::vector<std::wstring>& targets) {
    if (targets.empty()) return true;
    com_scope com;
    if (!com.valid()) return true;
    ITaskService* svc = nullptr;
    if (FAILED(CoCreateInstance(CLSID_TaskScheduler, nullptr, CLSCTX_INPROC_SERVER, IID_ITaskService, (void**)&svc)) || !svc)
        return true;
    bool found = false;
    if (SUCCEEDED(svc->Connect(_variant_t(), _variant_t(), _variant_t(), _variant_t()))) {
        ITaskFolder* root = nullptr;
        if (SUCCEEDED(svc->GetFolder(_bstr_t(L"\\"), &root)) && root) {
            found = check_tasks_active(root, targets);
            root->Release();
        }
    }
    svc->Release();
    return !found;
}

int wmain(int argc, wchar_t* argv[]) {
    if (!is_elevated()) {
        std::wcout << L"[-] Warning: not running as Administrator. Some processes may be inaccessible.\n\n";
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

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        std::wcerr << L"error: unable to snapshot processes\n";
        return 1;
    }

    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    DWORD selfPid = GetCurrentProcessId();
    std::vector<std::wstring> targets;
    std::vector<DWORD> killedPids;

    if (Process32FirstW(snap, &pe)) {
        do {
            if (pe.th32ProcessID <= 4 || pe.th32ProcessID == selfPid)
                continue;

            HANDLE proc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_TERMINATE | SYNCHRONIZE,
                                      FALSE, pe.th32ProcessID);
            if (!proc) continue;

            wchar_t imgPath[MAX_PATH * 2] = {0};
            DWORD sz = MAX_PATH * 2;
            std::wstring path;
            if (QueryFullProcessImageNameW(proc, 0, imgPath, &sz)) {
                path = imgPath;
            }

            if (path.empty() || is_trusted_location(path) || _wcsicmp(path.c_str(), myPath.c_str()) == 0) {
                CloseHandle(proc);
                continue;
            }

            bool match = scan_file(path, sigs);
            if (!match) {
                match = scan_process_memory(proc, sigs);
            }

            if (match) {
                std::wcout << L"found: " << pe.szExeFile << L" (pid " << pe.th32ProcessID << L")\n";

                if (!dryRun) {
                    kill_process_tree(pe.th32ProcessID);

                    if (TerminateProcess(proc, 1)) {
                        WaitForSingleObject(proc, 1000);
                        std::wcout << L"killed\n";
                    }
                    killedPids.push_back(pe.th32ProcessID);
                }
                targets.push_back(path);
            }
            CloseHandle(proc);
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);

    scan_persistence_locations(myPath, sigs, targets);

    if (targets.empty()) {
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
            clean_autoruns(targets);
            clean_scheduled_tasks(targets);

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
