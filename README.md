# WebratRemovalTool

[English](#english) | [Русский](#russian)

---

<a name="english"></a>
## English

**WebratRemovalTool** (`salat_killer`) is a standalone, single-file incident response and malware eradication utility written in C++17 for Windows. It is specifically engineered to detect, terminate, shred, and completely eradicate **WebRAT** (also known in the wild as *Nursultan*, *Salat Stealer*, or *TON Clipper*).

### Threat Profile (WebRAT / Nursultan)
WebRAT is a modular stealer and clipboard hijacker compiled with the Go runtime (typically 32-bit PE / WOW64). Its primary malicious capabilities include:
* **Cryptocurrency Clipper:** Real-time clipboard hijacking targeting TON, BTC, ETH, and other cryptocurrency addresses (`main.decodeFromTonAddress`).
* **Credential & Session Theft:** Extraction of Chromium v20+ credentials with App-Bound Encryption bypass (`main.GetAppBoundKey`), Discord tokens, Telegram session files, and browser cookies.
* **Encrypted C2 Configuration:** Hardcoded C2 configuration block with a magic header `0xA5 0xA7 0xA5 0xA5` decrypted using a custom TEA/XTEA routine (`0x9E3779B9`).
* **Multi-Layered Persistence:**
  * Windows Registry `Run` and `RunOnce` keys (both 64-bit and `WOW6432Node` views).
  * Windows Task Scheduler 2.0 tasks registered via COM (`ITaskService`).
  * Dropped binaries in `%LOCALAPPDATA%`, `%TEMP%`, and Startup folders.
* **Packing:** Commonly packed with UPX to evade static on-disk signature detection.

---

### Core Capabilities

1. **Dual Memory & Disk Detection:**
   * **In-Memory RAM Scanner:** Direct inspection of committed process memory via `VirtualQueryEx` and `ReadProcessMemory` with `PROCESS_QUERY_INFORMATION`. Unpacks and catches UPX-packed payloads in RAM regardless of obfuscation or binary renaming.
   * **Disk Signature Engine:** Evaluates uncompressed Go runtime routines, encrypted C2 magic headers (`\xa5\xa7\xa5\xa5`), TEA decryptor constants (`\xb9\x79\x37\x9e` / `0x9E3779B9` surviving `-ldflags "-s -w"` stripped builds), and UPX header checksums.
   * **Anti-Self-Detection (XOR 0x5A):** Internal signature store is XOR-encoded to prevent Windows Defender, antivirus heuristics, and YARA scanners from falsely flagging the removal tool itself.

2. **Recursive Process Tree Elimination:**
   * Uses `CreateToolhelp32Snapshot` to recursively identify and terminate all parent processes, child worker threads, and grandchild keylogger instances (`-k`).

3. **Secure Binary Shredding:**
   * Overwrites the payload with zeroes (capped to 64 MB to safely corrupt PE headers, imports, and code sections without stalling on massive files).
   * Truncates the file to 0 bytes with `SetEndOfFile` and deletes it.
   * Falls back to `MoveFileExW(MOVEFILE_DELAY_UNTIL_REBOOT)` if a driver or system handle holds the file open.

4. **Deep Persistence Eradication:**
   * **Registry:** Scans `HKCU` and `HKLM` under `Software\Microsoft\Windows\CurrentVersion\Run` and `RunOnce` across both `KEY_WOW64_64KEY` and `KEY_WOW64_32KEY`. Handles dynamic buffer resizing on `ERROR_MORE_DATA`.
   * **Task Scheduler 2.0 (COM):** Connects to `CLSID_TaskScheduler` (`ITaskService`), recursively traverses folders (ignoring internal Microsoft system tasks), inspects `IExecAction` binary paths, and unregisters malicious tasks.
   * **Filesystem Drops:** Cleans dropped copies in current working directory, `%TEMP%`, `%LOCALAPPDATA%` (and first-level subdirectories), and user/system Startup directories.

5. **Genuine System Verification Engine:**
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
  -ladvapi32 -lshell32 -lole32 -loleaut32 -municode -static \
  -o salat_killer.exe
```

---

### Usage

Run as **Administrator**:

```cmd
:: Standard interactive scan & cleanup (holds console on completion):
salat_killer.exe

:: Scan only / Dry-Run (displays detections without modifying system):
salat_killer.exe -s
salat_killer.exe --scan

:: Batch automation mode (exits without prompt upon completion):
salat_killer.exe -b
```

---

<a name="russian"></a>
## Русский

**WebratRemovalTool** (`salat_killer`) — это автономная утилита для реагирования на инциденты (Incident Response) и полного удаления вредоносного ПО, написанная на C++17 под Windows. Специально разработана для обнаружения, нейтрализации, уничтожения и вычищения **WebRAT** (в сети также известен как *Nursultan*, *Salat Stealer* или *TON Clipper*).

### Профиль угрозы (WebRAT / Nursultan)
WebRAT — модульный стилер и клиппер, написанный на Go (как правило, 32-битный PE / WOW64). Основные возможности зловреда:
* **Крипто-клиппер:** Подмена адресов кошельков в буфере обмена (TON, BTC, ETH и др.) в реальном времени (`main.decodeFromTonAddress`).
* **Кража учетных данных:** Обход защиты Chromium v20+ App-Bound Encryption (`main.GetAppBoundKey`), кража сессий Telegram, токенов Discord и браузерных паролей/куков.
* **Шифрование конфигурации:** Зашифрованный блок C2 с магическим заголовком `\xa5\xa7\xa5\xa5`, расшифровываемый алгоритмом TEA/XTEA с константой `0x9E3779B9` (`\xb9\x79\x37\x9e`).
* **Многоуровневый персистенс:**
  * Ключи `Run` и `RunOnce` в ветках `HKCU` и `HKLM` (как 64-битные, так и 32-битные `WOW6432Node`).
  * Задачи в Планировщике Windows (Task Scheduler 2.0) через COM API (`ITaskService`).
  * Дроп бинарников в `%LOCALAPPDATA%`, `%TEMP%` и папки автозагрузки `Startup`.
* **Упаковка:** Часто упаковывается с помощью UPX для обхода сигнатур на диске.

---

### Основные возможности утилиты

1. **Двойное сканирование (Память + Диск):**
   * **Сканер памяти RAM:** Прямой анализ выделенных страниц памяти через `VirtualQueryEx` и `ReadProcessMemory` с дескриптором `PROCESS_QUERY_INFORMATION`. Находит распакованную малварь в оперативной памяти независимо от переименования или UPX-упаковщика.
   * **Детект на диске:** Обнаруживает открытые строки рантайма Go, константы дешифратора C2 (`0x9E3779B9`, которые сохраняются даже при компиляции со стрипом символов `-ldflags "-s -w"`), заголовок конфига и заголовки UPX-упаковщика.
   * **Защита от самодетекта (XOR 0x5A):** Сигнатуры зашифрованы однобайтным XOR, что предотвращает ложное срабатывание антивирусов (Windows Defender) на сам killer.

2. **Рекурсивное завершение дерева процессов:**
   * Находит и принудительно завершает родительские процессы, дочерние воркеры и дочерние кейлоггеры (запущенные с флагом `-k`).

3. **Гарантированное уничтожение файлов (Shredding):**
   * Затирает файл нулями (лимит 64 МБ гарантированно разрушает заголовки PE, импорты и код за миллисекунды, не зависая на огромных файлах).
   * Обнуляет размер файла через `SetEndOfFile` и удаляет его с диска.
   * Если файл заблокирован системой/драйвером, ставит его в очередь удаления при перезагрузке через `MoveFileExW(MOVEFILE_DELAY_UNTIL_REBOOT)`.

4. **Полная очистка автозагрузки и персистенса:**
   * **Реестр:** Очищает обе разрядности (`KEY_WOW64_64KEY` и `KEY_WOW64_32KEY`) для веток `HKCU` и `HKLM` (`Run` и `RunOnce`).
   * **Планировщик задач (COM):** Подключается к `ITaskService`, рекурсивно обходит каталоги задач, сверяет исполняемые пути `IExecAction` и безопасно удаляет вредоносные задачи.
   * **Файловые локации:** Сканирует рабочий каталог, `%TEMP%`, подкаталоги `%LOCALAPPDATA%` и папки автозагрузки `Startup`.

5. **Реальная верификация:**
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
  -ladvapi32 -lshell32 -lole32 -loleaut32 -municode -static \
  -o salat_killer.exe
```

---

### Использование

Запускать от имени **Администратора**:

```cmd
:: Обычный интерактивный режим (сканирование, удаление, ожидание нажатия клавиши):
salat_killer.exe

:: Только сканирование без изменений (Dry-run):
salat_killer.exe -s
salat_killer.exe --scan

:: Пакетный режим для автоматизации (без ожидания клавиши при выходе):
salat_killer.exe -b
```

---

### Лицензия
MIT License.
