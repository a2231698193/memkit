// stealth/antidebug.hpp —— 启动自查：一旦被分析立即静默退出（不写日志、不留窗口）
#pragma once

#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>

#include <cstdint>
#include <string>

#include "common/hash.hpp"
#include "stealth/api.hpp"

namespace adbg {

// 1. PEB->BeingDebugged
inline bool peb_flag() noexcept {
#ifdef _WIN64
    const auto* peb = reinterpret_cast<const PEB*>(__readgsqword(0x60));
    return peb && peb->BeingDebugged != 0;
#else
    return false;
#endif
}

// 2. 调试对象：NtQueryInformationProcess 的 DebugPort(7) 与 DebugFlags(0x1F)
inline bool debug_object() noexcept {
    using Fn = LONG(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    static Fn q = api::get<Fn>(api::mod::ntdll, hash::ascii("NtQueryInformationProcess"));
    if (!q) return false;

    ULONG_PTR port = 0;
    ULONG flags = 0;
    const LONG st1 = q(GetCurrentProcess(), 7 /*ProcessDebugPort*/, &port, sizeof(port), nullptr);
    const LONG st2 = q(GetCurrentProcess(), 0x1F /*ProcessDebugFlags*/, &flags, sizeof(flags), nullptr);
    // 仅在调用成功时判断：DebugPort 非 0 或 DebugFlags==0 均说明被调试
    return (st1 >= 0 && port != 0) || (st2 >= 0 && flags == 0);
}

// 3. 硬件断点：Dr0-Dr3 任一非零即视为被下断
//    注意：GetThreadContext 走动态解析，不产生静态导入（静态导入本身就是特征）
inline bool hw_breakpoint() noexcept {
#ifdef _WIN64
    using Fn = BOOL(WINAPI*)(HANDLE, LPCONTEXT);
    static Fn gtc = api::get<Fn>(api::mod::kernel32, hash::ascii("GetThreadContext"));
    if (!gtc) return false;

    CONTEXT c{};
    c.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!gtc(GetCurrentThread(), &c)) return false;
    return (c.Dr0 | c.Dr1 | c.Dr2 | c.Dr3) != 0;
#else
    return false;
#endif
}

// 4. 黑名单加载器特征（仅在自身进程内查已加载模块）
inline bool hostile_module() noexcept {
    static const uint32_t kBad[] = {
        hash::wide(L"dbghelp.dll"),
        hash::wide(L"dbgcore.dll"),
        hash::wide(L"x64dbg.dll"),
        hash::wide(L"ida.dll"),
        hash::wide(L"ida64.dll"),
        hash::wide(L"hook.dll"),
        hash::wide(L"frida.dll"),
        hash::wide(L"detours.dll"),
    };
    for (uint32_t h : kBad) {
        if (api::module(h) != nullptr) return true;
    }
    return false;
}

// 5. 父进程粗筛
//
// 逻辑：取自身的 InheritedFromUniqueProcessId，再看该 PID 的镜像名。
// 命中已知调试器/分析器 → 拒绝启动。
// 这是一个"低误杀"的黑名单：只拦确定的分析工具，其余一律放行，
// 因为正常用户也可能从各种宿主启动（explorer、cmd、启动器）。
inline DWORD parent_pid() noexcept {
    using Fn = LONG(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    static Fn q = api::get<Fn>(api::mod::ntdll, hash::ascii("NtQueryInformationProcess"));
    if (!q) return 0;

    struct {
        PVOID Reserved1;
        PVOID PebBaseAddress;
        PVOID Reserved2[2];
        ULONG_PTR UniqueProcessId;
        PVOID Reserved3;
    } pbi{};

    ULONG ret = 0;
    if (q(GetCurrentProcess(), 0 /*ProcessBasicInformation*/, &pbi, sizeof(pbi), &ret) < 0) {
        return 0;
    }
    return static_cast<DWORD>(reinterpret_cast<uintptr_t>(pbi.Reserved3));
}

// 已知分析器/调试器的镜像名（小写，FNV-1a 常量，不落明文）
inline bool is_analyzer_image(const std::wstring& lowerName) noexcept {
    static const uint32_t kBad[] = {
        hash::wide(L"x64dbg.exe"),
        hash::wide(L"x32dbg.exe"),
        hash::wide(L"ollydbg.exe"),
        hash::wide(L"windbg.exe"),
        hash::wide(L"windbgx.exe"),
        hash::wide(L"ida.exe"),
        hash::wide(L"ida64.exe"),
        hash::wide(L"idaq.exe"),
        hash::wide(L"idaq64.exe"),
        hash::wide(L"ghidra.exe"),
        hash::wide(L"devenv.exe"),      // VS 附加调试
        hash::wide(L"dnspy.exe"),
        hash::wide(L"cheatengine-x86_64.exe"),
        hash::wide(L"cheatengine-x86_64-sse4-avx2.exe"),
        hash::wide(L"processhacker.exe"),
        hash::wide(L"systeminformer.exe"),
        hash::wide(L"procmon.exe"),
        hash::wide(L"procmon64.exe"),
        hash::wide(L"procexp.exe"),
        hash::wide(L"procexp64.exe"),
        hash::wide(L"frida.exe"),
        hash::wide(L"frida-server.exe"),
        hash::wide(L"ollyice.exe"),
        hash::wide(L"immunity debugger.exe"),
    };

    uint32_t h = hash::kOffset;
    for (wchar_t c : lowerName) {
        if (c >= L'A' && c <= L'Z') c = static_cast<wchar_t>(c - L'A' + L'a');
        const uint16_t v = static_cast<uint16_t>(c);
        h ^= static_cast<uint8_t>(v & 0xFF); h *= hash::kPrime;
        h ^= static_cast<uint8_t>(v >> 8);   h *= hash::kPrime;
    }
    for (uint32_t b : kBad) {
        if (b == h) return true;
    }
    return false;
}

inline bool suspicious_parent() noexcept {
    // 延迟探测：只在第一次调用时扫一次，避免每次启动都做全进程枚举
    static const bool bad = []() -> bool {
        const DWORD ppid = parent_pid();
        if (ppid == 0) return false;

        // 用 Toolhelp 快照拿父进程镜像名（一次性，句柄作用域内关闭）
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == INVALID_HANDLE_VALUE) return false;

        bool hit = false;
        PROCESSENTRY32W pe{};
        pe.dwSize = sizeof(pe);
        if (Process32FirstW(snap, &pe)) {
            do {
                if (pe.th32ProcessID != ppid) continue;
                const size_t n = wcslen(pe.szExeFile);
                if (n > 0 && n < 128) {
                    hit = is_analyzer_image(std::wstring(pe.szExeFile, n));
                }
                break;
            } while (Process32NextW(snap, &pe));
        }
        CloseHandle(snap);
        return hit;
    }();
    return bad;
}

inline bool any() noexcept {
    return peb_flag() || debug_object() || hw_breakpoint() || hostile_module() ||
           suspicious_parent();
}

}  // namespace adbg
