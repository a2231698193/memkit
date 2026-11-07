// tools/injprobe.cpp —— 注入痕迹实测
//
// 不靠猜：每一种注入方式都在真实进程上跑一遍，量出它留下什么。
//
// 用法：
//   injprobe.exe                 # 基线扫描（扫自己）
//   injprobe.exe self thread     # 自建目标 + CreateRemoteThread 注入
//   injprobe.exe self apc        # 自建目标 + QueueUserAPC 注入
//
// 实测结论见 docs/injection-survey.md。
#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <vector>

#pragma comment(lib, "psapi.lib")

// ---------- 目标侧状态测量 ----------
//
// 注意：这段必须**在注入之后**才调用。
// 对刚创建、尚未初始化完的进程调 VirtualQueryEx / EnumProcessModules
// 会让目标处于奇怪状态，实测会导致注入后目标崩在 0xC0000005。
struct TargetState {
    int modules = 0;
    int threads = 0;
    int rwxPages = 0;
    int privateExecPages = 0;
    bool alive = false;
    DWORD exitCode = 0;
};

static TargetState measure_target(HANDLE hProc, DWORD pid, HANDLE hProcessForExit) {
    TargetState s;

    if (hProcessForExit) {
        GetExitCodeProcess(hProcessForExit, &s.exitCode);
        s.alive = (s.exitCode == STILL_ACTIVE);
    }
    if (!s.alive) return s;

    // 模块：走 Toolhelp 快照（比 EnumProcessModules 对新建进程更稳）
    HANDLE mSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (mSnap != INVALID_HANDLE_VALUE) {
        MODULEENTRY32W me{};
        me.dwSize = sizeof(me);
        if (Module32FirstW(mSnap, &me)) {
            do { ++s.modules; } while (Module32NextW(mSnap, &me));
        }
        CloseHandle(mSnap);
    }

    // 线程
    HANDLE tSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (tSnap != INVALID_HANDLE_VALUE) {
        THREADENTRY32 te{};
        te.dwSize = sizeof(te);
        if (Thread32First(tSnap, &te)) {
            do {
                if (te.th32OwnerProcessID == pid) ++s.threads;
            } while (Thread32Next(tSnap, &te));
        }
        CloseHandle(tSnap);
    }

    // 内存页
    MEMORY_BASIC_INFORMATION mbi{};
    uintptr_t a = 0;
    while (VirtualQueryEx(hProc, (LPCVOID)a, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT) {
            const DWORD p = mbi.Protect & 0xFF;
            const bool exec = (p == PAGE_EXECUTE || p == PAGE_EXECUTE_READ ||
                               p == PAGE_EXECUTE_READWRITE || p == PAGE_EXECUTE_WRITECOPY);
            const bool wr = (p == PAGE_READWRITE || p == PAGE_EXECUTE_READWRITE ||
                             p == PAGE_WRITECOPY || p == PAGE_EXECUTE_WRITECOPY);
            if (exec && wr) ++s.rwxPages;
            if (exec && mbi.Type != MEM_IMAGE) ++s.privateExecPages;
        }
        const uintptr_t next = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
        if (next <= a) break;
        a = next;
    }

    return s;
}

static void report(const char* tag, const TargetState& s) {
    printf("  [%s] 模块=%d 线程=%d RWX页=%d 非映像可执行页=%d",
           tag, s.modules, s.threads, s.rwxPages, s.privateExecPages);
    if (!s.alive) printf("  <<< 进程已退出 0x%08lX", s.exitCode);
    printf("\n");
    fflush(stdout);
}

// ---------- shellcode ----------
//
// 目标：证明代码能在目标进程里执行，且**不破坏目标**。
//
//   sub  rsp, 0x28        48 83 EC 28     影子空间 + 16 字节对齐
//   mov  ecx, 1500        B9 DC 05 00 00  Sleep(1500)，留时间观察
//   mov  rax, <Sleep>     48 B8 <8 bytes>
//   call rax              FF D0
//   add  rsp, 0x28        48 83 C4 28     <<< 必须恢复
//   xor  eax, eax         31 C0
//   ret                   C3              交给系统收尾
//
// 三个踩过的坑：
//   1. `call [rip+disp]` 的 disp 算错 → 改用 mov rax, imm64 / call rax
//   2. 忘了 add rsp 恢复 → ret 弹到垃圾地址
//   3. 结尾用 ExitThread → 它走异常展开，而远程线程没有 unwind 信息，
//      直接 0xC0000005。必须 `ret`，让系统走 RtlExitUserThread 的正确路径。
static std::vector<uint8_t> make_stub(uint64_t sleepAddr) {
    std::vector<uint8_t> c;
    auto push64 = [&](uint64_t v) {
        for (int i = 0; i < 8; ++i) c.push_back(static_cast<uint8_t>((v >> (8 * i)) & 0xFF));
    };

    c.insert(c.end(), {0x48, 0x83, 0xEC, 0x28});              // sub rsp, 0x28
    c.insert(c.end(), {0xB9, 0xDC, 0x05, 0x00, 0x00});        // mov ecx, 1500
    c.push_back(0x48); c.push_back(0xB8); push64(sleepAddr);  // mov rax, Sleep
    c.push_back(0xFF); c.push_back(0xD0);                     // call rax
    c.insert(c.end(), {0x48, 0x83, 0xC4, 0x28});              // add rsp, 0x28
    c.insert(c.end(), {0x31, 0xC0});                          // xor eax, eax
    c.push_back(0xC3);                                        // ret
    return c;
}

// ---------- 注入方式 A ----------
static bool inject_remote_thread(HANDLE hProc, const std::vector<uint8_t>& code) {
    void* remote = VirtualAllocEx(hProc, nullptr, code.size(),
                                  MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remote) return false;

    SIZE_T wrote = 0;
    if (!WriteProcessMemory(hProc, remote, code.data(), code.size(), &wrote) ||
        wrote != code.size()) {
        return false;
    }

    HANDLE th = CreateRemoteThread(hProc, nullptr, 0,
                                   (LPTHREAD_START_ROUTINE)remote, nullptr, 0, nullptr);
    if (!th) return false;

    CloseHandle(th);
    // 故意不释放 remote：留着让外部能观察到 RWX 页
    return true;
}

// ---------- 注入方式 B ----------
static bool inject_apc(HANDLE hProc, DWORD pid, const std::vector<uint8_t>& code) {
    void* remote = VirtualAllocEx(hProc, nullptr, code.size(),
                                  MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remote) return false;

    SIZE_T wrote = 0;
    if (!WriteProcessMemory(hProc, remote, code.data(), code.size(), &wrote) ||
        wrote != code.size()) {
        return false;
    }

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return false;

    THREADENTRY32 te{};
    te.dwSize = sizeof(te);
    DWORD tid = 0;
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) { tid = te.th32ThreadID; break; }
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    if (tid == 0) return false;

    HANDLE hThread = OpenThread(THREAD_SET_CONTEXT, FALSE, tid);
    if (!hThread) return false;

    const DWORD ok = QueueUserAPC((PAPCFUNC)remote, hThread, 0);
    CloseHandle(hThread);
    return ok != 0;
}

// ---------- 自扫 ----------
static void scan_self() {
    const uintptr_t base = (uintptr_t)GetModuleHandleW(nullptr);
    const auto* dos = (const IMAGE_DOS_HEADER*)base;
    const auto* nt = (const IMAGE_NT_HEADERS64*)(base + dos->e_lfanew);
    const auto* sec = IMAGE_FIRST_SECTION(nt);

    uint64_t textHash = 0;
    for (int i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        if (!(sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;
        uint64_t sum = 0;
        const BYTE* p = (const BYTE*)base + sec[i].VirtualAddress;
        const DWORD n = sec[i].Misc.VirtualSize < 0x40000 ? sec[i].Misc.VirtualSize : 0x40000;
        for (DWORD j = 0; j < n; ++j) sum = sum * 131 + p[j];
        textHash = sum;
        break;
    }

    HMODULE mods[1024];
    DWORD need = 0;
    int nmods = 0;
    if (EnumProcessModules(GetCurrentProcess(), mods, sizeof(mods), &need)) {
        nmods = static_cast<int>(need / sizeof(HMODULE));
    }

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    int nthr = 0;
    if (snap != INVALID_HANDLE_VALUE) {
        THREADENTRY32 te{};
        te.dwSize = sizeof(te);
        if (Thread32First(snap, &te)) {
            do {
                if (te.th32OwnerProcessID == GetCurrentProcessId()) ++nthr;
            } while (Thread32Next(snap, &te));
        }
        CloseHandle(snap);
    }

    MEMORY_BASIC_INFORMATION mbi{};
    uintptr_t a = 0;
    int rwx = 0, privExec = 0;
    while (VirtualQuery((LPCVOID)a, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT) {
            const DWORD p = mbi.Protect & 0xFF;
            const bool exec = (p == PAGE_EXECUTE || p == PAGE_EXECUTE_READ ||
                               p == PAGE_EXECUTE_READWRITE || p == PAGE_EXECUTE_WRITECOPY);
            const bool wr = (p == PAGE_READWRITE || p == PAGE_EXECUTE_READWRITE ||
                             p == PAGE_WRITECOPY || p == PAGE_EXECUTE_WRITECOPY);
            if (exec && wr) ++rwx;
            if (exec && mbi.Type != MEM_IMAGE) ++privExec;
        }
        const uintptr_t next = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
        if (next <= a) break;
        a = next;
    }

    printf("=== 基线（自身进程）===\n");
    printf("  模块数           %d\n", nmods);
    printf("  线程数           %d\n", nthr);
    printf("  RWX 页           %d\n", rwx);
    printf("  非映像可执行页   %d\n", privExec);
    printf("  .text 指纹       0x%016llX\n", (unsigned long long)textHash);
}

int main(int argc, char** argv) {
    SetConsoleOutputCP(936);

    // ---------- 被注入侧 ----------
    if (argc >= 2 && strcmp(argv[1], "sleeper") == 0) {
        for (;;) Sleep(500);
    }

    // ---------- 基线 ----------
    if (argc < 2) {
        scan_self();
        printf("\n用法：\n");
        printf("  injprobe.exe              基线扫描\n");
        printf("  injprobe.exe self thread  自建目标 + CreateRemoteThread\n");
        printf("  injprobe.exe self apc     自建目标 + QueueUserAPC\n");
        return 0;
    }

    // ---------- 自建目标 + 注入 ----------
    if (strcmp(argv[1], "self") != 0) {
        printf("未知模式：%s\n", argv[1]);
        return 1;
    }
    const char* mode = (argc > 2) ? argv[2] : "thread";
    const bool useApc = (strcmp(mode, "apc") == 0);

    printf("=== 自建目标 + 注入（%s）===\n\n", mode);

    wchar_t self[MAX_PATH] = {};
    GetModuleFileNameW(nullptr, self, MAX_PATH);
    wchar_t cmd[512];
    swprintf(cmd, 512, L"\"%ls\" sleeper", self);

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    if (!CreateProcessW(nullptr, cmd, nullptr, nullptr, FALSE, 0, nullptr, nullptr, &si, &pi)) {
        printf("CreateProcess 失败 %lu\n", GetLastError());
        return 1;
    }

    // 等目标把运行时初始化完再动手。600ms 实测够用；
    // 更短的话目标还在 loader 阶段，注入会让它崩。
    Sleep(700);
    printf("目标 pid = %lu\n", pi.dwProcessId);

    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pi.dwProcessId);
    if (!hProc) {
        printf("OpenProcess 失败 %lu\n", GetLastError());
        TerminateProcess(pi.hProcess, 0);
        return 1;
    }

    // 注入前只量最轻的两项（不动 VirtualQueryEx，避免干扰新建进程）
    {
        TargetState before;
        GetExitCodeProcess(pi.hProcess, &before.exitCode);
        before.alive = (before.exitCode == STILL_ACTIVE);

        HANDLE mSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
                                                pi.dwProcessId);
        if (mSnap != INVALID_HANDLE_VALUE) {
            MODULEENTRY32W me{};
            me.dwSize = sizeof(me);
            if (Module32FirstW(mSnap, &me)) {
                do { ++before.modules; } while (Module32NextW(mSnap, &me));
            }
            CloseHandle(mSnap);
        }
        HANDLE tSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (tSnap != INVALID_HANDLE_VALUE) {
            THREADENTRY32 te{};
            te.dwSize = sizeof(te);
            if (Thread32First(tSnap, &te)) {
                do {
                    if (te.th32OwnerProcessID == pi.dwProcessId) ++before.threads;
                } while (Thread32Next(tSnap, &te));
            }
            CloseHandle(tSnap);
        }
        report("注入前", before);
    }

    const std::vector<uint8_t> stub = make_stub(
        (uint64_t)(uintptr_t)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "Sleep"));
    printf("\n  shellcode = %zu 字节\n", stub.size());

    const bool ok = useApc ? inject_apc(hProc, pi.dwProcessId, stub)
                           : inject_remote_thread(hProc, stub);
    printf("  注入 = %s\n\n", ok ? "成功" : "失败");

    // 按时间线采样，看痕迹何时出现、何时消失
    const char* labels[] = {"+200ms", "+600ms", "+1200ms", "+2400ms"};
    const int waits[] = {200, 400, 600, 1200};
    for (int i = 0; i < 4; ++i) {
        Sleep(waits[i]);
        const TargetState st = measure_target(hProc, pi.dwProcessId, pi.hProcess);
        report(labels[i], st);
        if (!st.alive) break;
    }

    TerminateProcess(pi.hProcess, 0);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    CloseHandle(hProc);
    return 0;
}
