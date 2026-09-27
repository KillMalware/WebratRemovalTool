# WebratRemovalTool

[English](#english) | [Русский](#russian)

---

<a name="english"></a>
## English

**WebratRemovalTool** is a standalone, single-file incident response and malware eradication utility written in C++17 for Windows. It is specifically engineered to detect, terminate, shred, and completely eradicate **WebRAT** (Go-based info-stealer and crypto-clipper).

### 📥 Download Pre-Compiled Binary
* **Direct Binary (Git Tree):** [`bin/WebratRemovalTool.exe`](https://github.com/KillMalware/WebratRemovalTool/raw/main/bin/WebratRemovalTool.exe)
* **GitHub Releases:** [Download Latest Release v1.0.1](https://github.com/KillMalware/WebratRemovalTool/releases/latest)

### Threat Profile (WebRAT)
WebRAT is a modular stealer and clipboard hijacker compiled with the Go runtime (typically 32-bit PE / WOW64). Its primary malicious capabilities include:
* **Cryptocurrency Clipper:** Real-time clipboard hijacking targeting TON, BTC, ETH, and other cryptocurrency addresses (`main.decodeFromTonAddress`).
* **Credential & Session Theft:** Extraction of Chromium v20+ credentials with App-Bound Encryption bypass (`main.GetAppBoundKey`), Discord tokens, Telegram session files, and browser cookies.
* **Aggressive Persistence & Reinstatement:**
  * Windows Task Scheduler 2.0 tasks registered via COM (`ITaskService` / `github.com/capnspacehook/taskmaster`) with `LogonTrigger` and repeating 30-second `TimeTrigger`, placed in the root directory `\` or disguised subtrees.
  * Windows Registry `Run`, `RunOnce`, and `Policies\Explorer\Run` keys across both 64-bit (`KEY_WOW64_64KEY`) and 32-bit (`KEY_WOW64_32KEY`) views.
  * Random installation locations selected via `main.getRandomFolders` (`%ProgramFiles%`, `%ProgramFiles(x86)%`, `%LOCALAPPDATA%`, `%APPDATA%`).
  * Startup folder shortcuts (`.lnk`) with obfuscated targets.
* **System Tampering:**
  * Disables User Account Control (UAC) by setting `EnableLUA = 0` in `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`.
  * Disables Windows Recovery Environment via `reagentc /disable`.
  * Drops auxiliary tools into `%TEMP%` (`7z.dll`, `7z.exe`, `ffmpeg.exe`, `MSTSCLib.dll`, `AxMSTSCLib.dll`).
* **Packing:** Packed with UPX to evade static on-disk signature detection.

---

### Core Capabilities

1. **Dual Memory & Disk Detection:**
   * **In-Memory RAM Scanner:** Direct inspection of committed process memory via `VirtualQueryEx` and `ReadProcessMemory` with `PROCESS_QUERY_INFORMATION`. Unpacks and catches UPX-packed payloads in RAM regardless of obfuscation or binary renaming.
   * **Authentic Go Signature Engine:** Evaluates uncompressed Go runtime routines, TON address decoder, AppBound key extractor, static installation routines, and mutex creators.
   * **Anti-Self-Detection (XOR 0x5A):** Internal signature store is XOR-encoded to prevent Windows Defender, antivirus heuristics, and YARA scanners from falsely flagging the removal tool itself.

2. **Anti-Reinstatement & Process Suspension:**
   * Freezes all target threads and child worker processes prior to termination (`NtSuspendProcess` / `SuspendThread`) to eliminate watchdog reinstatement loops.
   * Recursively discovers and terminates entire process trees via `CreateToolhelp32Snapshot`.

3. **Secure Binary Shredding:**
   * Overwrites the payload with zeroes (capped to 64 MB to safely corrupt PE headers, imports, and code sections without stalling on massive files).
   * Renames to temporary dead files, truncates to 0 bytes, and deletes with `DeleteFileW`.
   * Falls back to `MoveFileExW(MOVEFILE_DELAY_UNTIL_REBOOT)` if a driver or system handle holds the file open.

4. **Deep Persistence Eradication:**
   * **Task Scheduler 2.0 (COM):** Recursively traverses root `\` and all subfolders in `ITaskFolder`, inspects `IExecAction` executable paths, scans binaries for threat signatures, and deletes malicious tasks.
   * **Registry Autoruns:** Scans `HKCU` and `HKLM` under `Run`, `RunOnce`, `RunServices`, and policies across both `KEY_WOW64_64KEY` and `KEY_WOW64_32KEY`.
   * **Orphaned / Volatile Entry Purger:** Automatically identifies and purges dead autoruns or scheduled tasks pointing to non-existent droppers in `%TEMP%`, `%APPDATA%`, `%LOCALAPPDATA%`, `Desktop`, and `Downloads`.
   * **Startup Shortcuts:** Analyzes `.lnk` files in user and system Startup folders via `IShellLinkW`, resolves target executables, and removes threat shortcuts.

5. **System Remediation & Integrity Restoration:**
   * Automatically restores UAC policy (`EnableLUA = 1`) if tampered by malware.
   * Re-enables Windows Recovery Environment (`reagentc.exe /enable`).
   * Purges dropped auxiliary droppers (`7z.dll`, `ffmpeg.exe`, etc.) from all temp directories.

6. **Multi-Pass Verification Engine:**
   * Actively queries process termination status using `GetExitCodeProcess` (verifying processes are no longer `STILL_ACTIVE`).
   * Validates disk artifacts via `GetFileAttributesW`.
   * Re-verifies autoruns and scheduled tasks to ensure zero remnants remain.

---

### Building from Source

#### Prerequisites
* **MinGW-w64** (Linux cross-compiler or MSYS2 on Windows) or **MSVC**.

#### Compilation (MinGW-w64 on Linux / Windows)
```bash
# 1. Compile UAC Administrator manifest resource:
x86_64-w64-mingw32-windres res.rc -O coff -o res.o

# 2. Build static standalone executable:
x86_64-w64-mingw32-g++ -Wall -Wextra -std=c++17 -O2 main.cpp res.o \
  -ladvapi32 -lshell32 -lole32 -loleaut32 -luuid -ltaskschd -municode -static -s \
  -o bin/WebratRemovalTool.exe
```

---

### Usage

Run as **Administrator**:

```cmd
:: Standard interactive scan & cleanup (holds console on completion):
WebratRemovalTool.exe

:: Scan only / Dry-Run (displays detections without modifying system):
WebratRemovalTool.exe -s
WebratRemovalTool.exe --scan

:: Batch automation mode (exits without prompt upon completion):
WebratRemovalTool.exe -b
```

---

<a name="russian"></a>
## Русский

**WebratRemovalTool** — это автономная утилита для реагирования на инциденты (Incident Response) и полного удаления вредоносного ПО, написанная на C++17 под Windows. Специально разработана для обнаружения, нейтрализации, уничтожения и вычищения **WebRAT** (Go-стилер, крипто-клиппер и бэкдор), а также всех механизмов его персистенса, дропнутых утилит и системных модификаций.

### 📥 Скачать готовый бинарник
* **Прямая ссылка (из репозитория):** [`bin/WebratRemovalTool.exe`](https://github.com/KillMalware/WebratRemovalTool/raw/main/bin/WebratRemovalTool.exe)
* **Релизы на GitHub:** [Скачать последний релиз v1.0.1](https://github.com/KillMalware/WebratRemovalTool/releases/latest)

### Профиль угрозы (WebRAT)
WebRAT — модульный стилер и клиппер, написанный на Go (как правило, 32-битный PE / WOW64). Основные возможности зловреда:
* **Крипто-клиппер:** Подмена адресов кошельков в буфере обмена (TON, BTC, ETH и др.) в реальном времени (`main.decodeFromTonAddress`).
* **Кража учетных данных:** Обход защиты Chromium v20+ App-Bound Encryption (`main.GetAppBoundKey`), кража сессий Telegram, токенов Discord и браузерных паролей/куков.
* **Агрессивный персистенс и самовосстановление (Reinstatement):**
  * Задачи в Планировщике Windows (Task Scheduler 2.0) через COM API (`ITaskService` / `github.com/capnspacehook/taskmaster`) с триггерами при входе в систему (`LogonTrigger`) и периодическим повтором каждые 30 секунд (`TimeTrigger`), создаваемые в корне `\` или системных подкаталогах.
  * Ключи `Run`, `RunOnce` и `Policies\Explorer\Run` в ветках `HKCU` и `HKLM` (как 64-битные `KEY_WOW64_64KEY`, так и 32-битные `KEY_WOW64_32KEY`).
  * Случайные папки установки через алгоритм `main.getRandomFolders` (`%ProgramFiles%`, `%ProgramFiles(x86)%`, `%LOCALAPPDATA%`, `%APPDATA%`).
  * Ярлыки автозагрузки (`.lnk`) с маскированными путями.
* **Системные повреждения:**
  * Отключение контроля учетных записей (UAC) установкой `EnableLUA = 0` в реестре.
  * Отключение среды восстановления Windows через `reagentc /disable`.
  * Дроп вспомогательных инструментов в `%TEMP%` (`7z.dll`, `7z.exe`, `ffmpeg.exe`, `MSTSCLib.dll`, `AxMSTSCLib.dll`).
* **Упаковка:** Часто упаковывается с помощью UPX для обхода сигнатур на диске.

---

### Основные возможности утилиты

1. **Двойное сканирование (Память + Диск):**
   * **Сканер памяти RAM:** Прямой анализ выделенных страниц памяти через `VirtualQueryEx` и `ReadProcessMemory` с дескриптором `PROCESS_QUERY_INFORMATION`. Находит распакованную малварь в оперативной памяти независимо от переименования или UPX-упаковщика.
   * **Детект на диске:** Обнаруживает открытые строки рантайма Go, модуль декодирования адресов TON, модуль извлечения AppBound ключей, модули инсталляции и создания мьютексов.
   * **Защита от самодетекта (XOR 0x5A):** Сигнатуры зашифрованы однобайтным XOR, что предотвращает ложное срабатывание антивирусов (Windows Defender) на сам killer.

2. **Защита от самовосстановления (Anti-Reinstatement):**
   * Замораживает потоки процесса и дочернее дерево (`NtSuspendProcess` / `SuspendThread`) перед завершением, исключая перезапуск копий процессами-watchdog.
   * Рекурсивно завершает все связанные ветви процессов через `CreateToolhelp32Snapshot`.

3. **Гарантированное уничтожение файлов (Shredding):**
   * Затирает файл нулями (лимит 64 МБ гарантированно разрушает заголовки PE, импорты и код за миллисекунды, не зависая на огромных файлах).
   * Переименовывает во временный мертвый файл, обнуляет размер файла через `SetEndOfFile` и удаляет его с диска.
   * Если файл заблокирован системой/драйвером, ставит его в очередь удаления при перезагрузке через `MoveFileExW(MOVEFILE_DELAY_UNTIL_REBOOT)`.

4. **Полная очистка автозагрузки и персистенса:**
   * **Планировщик задач (COM):** Подключается к `ITaskService`, рекурсивно обходит корень `\` и все подкаталоги задач, сверяет пути `IExecAction` и удаляет малварные таски.
   * **Реестр:** Очищает обе разрядности (`KEY_WOW64_64KEY` и `KEY_WOW64_32KEY`) для веток `HKCU` и `HKLM` (`Run` и `RunOnce`).
   * **Очистка сиротских записей (Orphaned / Volatile Hunter):** Находит и удаляет битые ключи автозагрузки и задачи, ссылающиеся на несуществующие дропперы в `%TEMP%`, `%APPDATA%`, `%LOCALAPPDATA%`, `Desktop`, `Downloads`.
   * **Ярлыки автозагрузки (`.lnk`):** Проверяет папки автозагрузки через `IShellLinkW`, вычисляет целевые бинарники и удаляет малварные ярлыки.

5. **Восстановление целостности ОС:**
   * Восстанавливает политику UAC (`EnableLUA = 1`).
   * Включает среду восстановления Windows (`reagentc.exe /enable`).
   * Удаляет дропнутые вспомогательные библиотеки и утилиты (`7z.dll`, `ffmpeg.exe` и др.) во всех директориях Temp.

6. **Мультипроходная верификация:**
   * Проверяет завершение процессов через `GetExitCodeProcess` (контроль, что процесс больше не находится в состоянии `STILL_ACTIVE`).
   * Проверяет удаление файлов через `GetFileAttributesW`.
   * Повторно опрашивает реестр и планировщик задач.

---

### Сборка из исходников

```bash
# 1. Компиляция UAC-манифеста администратора:
x86_64-w64-mingw32-windres res.rc -O coff -o res.o

# 2. Сборка статического бинарника:
x86_64-w64-mingw32-g++ -Wall -Wextra -std=c++17 -O2 main.cpp res.o \
  -ladvapi32 -lshell32 -lole32 -loleaut32 -luuid -ltaskschd -municode -static -s \
  -o bin/WebratRemovalTool.exe
```

---

### Использование

Запускать от имени **Администратора**:

```cmd
:: Обычный интерактивный режим (сканирование, удаление, ожидание нажатия клавиши):
WebratRemovalTool.exe

:: Только сканирование без изменений (Dry-run):
WebratRemovalTool.exe -s
WebratRemovalTool.exe --scan

:: Пакетный режим для автоматизации (без ожидания клавиши при выходе):
WebratRemovalTool.exe -b
```

---

### Лицензия
MIT License.
